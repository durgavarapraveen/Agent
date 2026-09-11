"""Phase 4.4 — iOS IPA backend analysis.

The IPA counterpart of ``mobile_analyzer``. Extracts the backend attack surface
from an unzipped .ipa: API endpoints and secrets from the app binary/resources,
plus URL-scheme deeplinks and App Transport Security exceptions from
``Info.plist``.

Uses stdlib ``plistlib`` (parses both binary and XML plists natively — no need
to shell out to ``plutil``). The extraction operates on an already-unzipped IPA
directory, so it unit-tests with fixtures and no external tools.
"""
from __future__ import annotations

import logging
import plistlib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from core.discovery.mobile_analyzer import (
    _TEXT_EXTS,
    _dedup_secrets,
    extract_secrets,
    extract_urls,
)

logger = logging.getLogger(__name__)


@dataclass
class IPAAnalysis:
    source: str
    bundle_id: str = ""
    endpoints: List[str] = field(default_factory=list)
    secrets: List[Dict[str, str]] = field(default_factory=list)
    deeplinks: List[str] = field(default_factory=list)
    ats_exceptions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "bundle_id": self.bundle_id,
                "endpoints": self.endpoints, "secrets": self.secrets,
                "deeplinks": self.deeplinks, "ats_exceptions": self.ats_exceptions}

    def to_endpoints(self) -> List[Dict[str, str]]:
        seen, out = set(), []
        for u in self.endpoints:
            if u not in seen:
                seen.add(u)
                out.append({"url": u, "method": "GET", "source": "mobile_ipa"})
        return out


def parse_info_plist(data: bytes) -> Dict[str, Any]:
    """Parse Info.plist (binary or XML) → bundle id, URL schemes, ATS exceptions."""
    out: Dict[str, Any] = {"bundle_id": "", "deeplinks": [], "ats_exceptions": []}
    try:
        plist = plistlib.loads(data)
    except Exception as e:
        logger.debug("ipa_analyzer: plist parse failed (%s)", e)
        return out
    if not isinstance(plist, dict):
        return out
    out["bundle_id"] = plist.get("CFBundleIdentifier", "")

    for url_type in plist.get("CFBundleURLTypes", []) or []:
        for scheme in (url_type.get("CFBundleURLSchemes", []) if isinstance(url_type, dict) else []):
            out["deeplinks"].append(f"{scheme}://")

    ats = plist.get("NSAppTransportSecurity", {}) or {}
    if ats.get("NSAllowsArbitraryLoads"):
        out["ats_exceptions"].append("NSAllowsArbitraryLoads=true")
    for domain in (ats.get("NSExceptionDomains", {}) or {}):
        out["ats_exceptions"].append(domain)

    out["deeplinks"] = sorted(set(out["deeplinks"]))
    out["ats_exceptions"] = sorted(set(out["ats_exceptions"]))
    return out


class IPAAnalyzer:

    def analyze_extracted(self, directory: str, source: str = "") -> IPAAnalysis:
        root = Path(directory)
        analysis = IPAAnalysis(source=source or str(root))
        endpoints, secrets = set(), []

        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.name == "Info.plist":
                try:
                    info = parse_info_plist(path.read_bytes())
                    analysis.bundle_id = info["bundle_id"] or analysis.bundle_id
                    analysis.deeplinks = sorted(set(analysis.deeplinks + info["deeplinks"]))
                    analysis.ats_exceptions = sorted(set(analysis.ats_exceptions + info["ats_exceptions"]))
                except Exception as e:
                    logger.debug("ipa_analyzer: Info.plist read failed (%s)", e)
                continue
            if path.suffix.lower() in _TEXT_EXTS or path.suffix == "":
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                endpoints.update(extract_urls(text))
                secrets.extend(extract_secrets(text))

        analysis.endpoints = sorted(endpoints)
        analysis.secrets = _dedup_secrets(secrets)
        return analysis

    def analyze(self, ipa_path: str) -> IPAAnalysis:
        import tempfile
        out_dir = tempfile.mkdtemp(prefix="ipa_")
        try:
            with zipfile.ZipFile(ipa_path) as z:
                z.extractall(out_dir)
        except Exception as e:
            logger.warning("ipa_analyzer: unzip failed (%s)", e)
            return IPAAnalysis(source=ipa_path)
        return self.analyze_extracted(out_dir, source=ipa_path)
