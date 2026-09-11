"""Phase 4.4 — Android APK backend analysis.

Decompiles an APK (shelling out to ``apktool`` or ``jadx`` — not added as a
Python dependency) and mines the result for the app's backend attack surface:
API endpoints (URL strings), hardcoded keys/secrets, certificate-pinning config,
and deeplink handlers from ``AndroidManifest.xml``. Discovered endpoints feed the
normal scan pipeline via :meth:`MobileAnalysis.to_endpoints`.

The decompile step shells out and is guarded; the extraction logic
(:meth:`analyze_extracted`) works on an already-extracted directory, so it is
fully unit-testable with fixture files and no external tools.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_SECRET_PATTERNS = [
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("firebase_url", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}")),
    ("generic_api_key", re.compile(r"(?i)(?:api[_-]?key|apikey|secret|token)"
                                   r"[\"'\s:=]+([A-Za-z0-9._\-]{16,})")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
]
_TEXT_EXTS = {".smali", ".java", ".kt", ".xml", ".json", ".js", ".txt", ".properties", ".cfg"}


@dataclass
class MobileAnalysis:
    source: str
    package: str = ""
    endpoints: List[str] = field(default_factory=list)
    secrets: List[Dict[str, str]] = field(default_factory=list)
    deeplinks: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    cert_pinning: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "package": self.package,
                "endpoints": self.endpoints, "secrets": self.secrets,
                "deeplinks": self.deeplinks, "permissions": self.permissions,
                "cert_pinning": self.cert_pinning}

    def to_endpoints(self) -> List[Dict[str, str]]:
        """Endpoint dicts for the scan pipeline (dedup by URL)."""
        seen, out = set(), []
        for u in self.endpoints:
            if u not in seen:
                seen.add(u)
                out.append({"url": u, "method": "GET", "source": "mobile_apk"})
        return out


def extract_urls(text: str) -> List[str]:
    return sorted(set(_URL_RE.findall(text or "")))


def extract_secrets(text: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for name, pat in _SECRET_PATTERNS:
        for m in pat.finditer(text or ""):
            val = m.group(0)
            out.append({"type": name, "match": val[:80]})
    return out


def parse_android_manifest(xml_text: str) -> Dict[str, Any]:
    """Best-effort parse of AndroidManifest.xml for permissions + deeplinks."""
    result: Dict[str, Any] = {"package": "", "permissions": [], "deeplinks": []}
    m = re.search(r'package="([^"]+)"', xml_text or "")
    if m:
        result["package"] = m.group(1)
    result["permissions"] = sorted(set(
        re.findall(r'uses-permission[^>]*android:name="([^"]+)"', xml_text or "")))
    # Deeplinks: <data android:scheme=".." android:host="..">
    for data in re.finditer(r"<data\b([^>]*)/?>", xml_text or ""):
        attrs = data.group(1)
        scheme = re.search(r'android:scheme="([^"]+)"', attrs)
        host = re.search(r'android:host="([^"]+)"', attrs)
        if scheme:
            link = f"{scheme.group(1)}://{host.group(1) if host else ''}"
            result["deeplinks"].append(link)
    result["deeplinks"] = sorted(set(result["deeplinks"]))
    return result


def detect_cert_pinning(text: str) -> bool:
    t = (text or "").lower()
    return any(k in t for k in ("certificatepinner", "<pin-set", "network_security_config",
                                "x509trustmanager", "sslpinning", "trustkit"))


class MobileAnalyzer:

    def analyze_extracted(self, directory: str, source: str = "") -> MobileAnalysis:
        """Analyze an already-decompiled APK directory (testable, no tools)."""
        root = Path(directory)
        analysis = MobileAnalysis(source=source or str(root))
        endpoints, secrets, cert_pin = set(), [], False

        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in _TEXT_EXTS:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            endpoints.update(extract_urls(text))
            secrets.extend(extract_secrets(text))
            if detect_cert_pinning(text):
                cert_pin = True
            if path.name == "AndroidManifest.xml":
                man = parse_android_manifest(text)
                analysis.package = man["package"] or analysis.package
                analysis.permissions = man["permissions"]
                analysis.deeplinks = man["deeplinks"]

        analysis.endpoints = sorted(endpoints)
        analysis.secrets = _dedup_secrets(secrets)
        analysis.cert_pinning = cert_pin
        return analysis

    def decompile(self, apk_path: str, out_dir: str) -> bool:
        """Shell out to apktool (preferred) or jadx. Returns False if neither is
        installed or decompilation fails."""
        apktool = shutil.which("apktool")
        jadx = shutil.which("jadx")
        try:
            if apktool:
                subprocess.run([apktool, "d", "-f", "-o", out_dir, apk_path],
                               check=True, capture_output=True, timeout=600)
                return True
            if jadx:
                subprocess.run([jadx, "-d", out_dir, apk_path],
                               check=True, capture_output=True, timeout=600)
                return True
            logger.warning("mobile_analyzer: neither apktool nor jadx on PATH")
        except Exception as e:
            logger.warning("mobile_analyzer: decompile failed (%s)", e)
        return False

    def analyze(self, apk_path: str) -> MobileAnalysis:
        out_dir = tempfile.mkdtemp(prefix="apk_")
        if not self.decompile(apk_path, out_dir):
            return MobileAnalysis(source=apk_path)
        return self.analyze_extracted(out_dir, source=apk_path)


def inject_endpoints_into_context(ctx: Any, urls: List[str],
                                  source: str = "mobile_apk") -> int:
    """Merge mobile-derived backend endpoints into a scan's shared context so
    they are scanned like any other discovered endpoint. Scope enforcement still
    applies at request time — out-of-scope hosts are blocked, not auto-authorized.
    Returns the number of endpoints added."""
    eps = [{"url": u, "method": "GET", "params": "", "source": source}
           for u in (urls or []) if u]
    if not eps:
        return 0
    if hasattr(ctx, "add_endpoints"):
        try:
            ctx.add_endpoints(eps, source=source)
            return len(eps)
        except Exception as e:
            logger.debug("inject_endpoints: add_endpoints failed (%s); falling back", e)
    cur = getattr(ctx, "endpoints", None)
    if isinstance(cur, list):
        cur.extend(eps)
        return len(eps)
    return 0


def _dedup_secrets(secrets: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen, out = set(), []
    for s in secrets:
        key = (s["type"], s["match"])
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out
