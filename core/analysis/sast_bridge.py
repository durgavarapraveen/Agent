"""Phase 4.5 — source-aware grey-box mode (SAST ↔ DAST correlation).

When the customer shares source, run Semgrep's security rules over it, map the
results to the internal finding format, and correlate with the DAST findings:

  * same vuln class + overlapping location in both  → CONFIRMED;
  * SAST only → "potential, needs runtime validation";
  * DAST only → "confirmed at runtime".

Semgrep is an optional dependency (graceful fallback if not installed); cloning
and running it are shelled out and guarded. The output parser and the
correlation are pure and unit-testable with a sample Semgrep JSON — no Semgrep,
no repo, no network required.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def correlate_and_persist(scan_id: str, sast_findings: List[Dict[str, Any]],
                          dast_findings: List[Dict[str, Any]],
                          out_dir: str = "data/sast_correlation") -> Dict[str, Any]:
    """Correlate SAST↔DAST for a scan and persist the result to
    ``{out_dir}/{scan_id}.json`` so the report/UI can read it back. Returns the
    correlation dict (confirmed / sast_only / dast_only + counts)."""
    result = correlate_sast_dast(sast_findings or [], dast_findings or [])
    summary = {
        "scan_id": scan_id,
        "confirmed": result["confirmed"],
        "sast_only": result["sast_only"],
        "dast_only": result["dast_only"],
        "counts": {"confirmed": len(result["confirmed"]),
                   "sast_only": len(result["sast_only"]),
                   "dast_only": len(result["dast_only"])},
    }
    try:
        p = Path(out_dir) / f"{scan_id}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    except Exception as e:
        logger.warning("sast_bridge: could not persist correlation (%s)", e)
    return summary


def load_correlation(scan_id: str, out_dir: str = "data/sast_correlation") -> Optional[Dict[str, Any]]:
    p = Path(out_dir) / f"{scan_id}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

# Map Semgrep check_id / CWE → internal vuln class. Broad coverage so every
# statically-detectable class Semgrep's security packs report is labeled (not
# collapsed to "generic").
_CWE_CLASS = {
    # Injection family
    "89": "sqli", "564": "sqli", "943": "nosql_injection",
    "79": "xss", "80": "xss", "83": "xss",
    "78": "command_injection", "77": "command_injection",
    "94": "code_injection", "95": "code_injection", "1336": "ssti", "917": "ssti",
    "90": "ldap_injection", "643": "xpath_injection", "91": "xml_injection",
    "74": "injection", "93": "crlf_injection", "113": "http_response_splitting",
    # Path / file / traversal
    "22": "path_traversal", "23": "path_traversal", "36": "path_traversal",
    "98": "lfi", "73": "file_inclusion", "434": "unrestricted_file_upload",
    # SSRF / XXE / deserialization
    "918": "ssrf", "611": "xxe", "776": "xxe",
    "502": "insecure_deserialization",
    # AuthN / AuthZ / session
    "287": "auth_bypass", "306": "auth_bypass", "862": "missing_authz",
    "863": "broken_authz", "639": "idor", "566": "idor",
    "384": "session_fixation", "613": "session_expiry", "620": "weak_auth",
    "798": "hardcoded_secret", "259": "hardcoded_secret", "321": "hardcoded_key",
    # Crypto
    "327": "weak_crypto", "328": "weak_hash", "326": "weak_crypto",
    "330": "weak_random", "338": "weak_random", "760": "weak_crypto",
    "347": "jwt_signature", "319": "cleartext_transport", "295": "cert_validation",
    # Web misconfig / client-side
    "601": "open_redirect", "352": "csrf", "942": "cors_misconfig",
    "614": "insecure_cookie", "1004": "insecure_cookie", "1275": "insecure_cookie",
    "693": "missing_security_header", "1021": "clickjacking",
    "1321": "prototype_pollution", "915": "mass_assignment",
    # Info leak / dos / misc
    "532": "sensitive_logging", "209": "info_disclosure", "200": "info_disclosure",
    "1333": "redos", "400": "dos", "776_dos": "dos",
    "116": "improper_encoding", "20": "improper_input_validation",
    "434_upload": "unrestricted_file_upload", "raw": "generic",
}
_KEYWORD_CLASS = [
    ("sql", "sqli"), ("nosql", "nosql_injection"),
    ("xss", "xss"), ("cross-site-scripting", "xss"),
    ("command-injection", "command_injection"), ("os-command", "command_injection"),
    ("code-injection", "code_injection"), ("eval", "code_injection"),
    ("ssti", "ssti"), ("template-injection", "ssti"),
    ("ldap", "ldap_injection"), ("xpath", "xpath_injection"),
    ("path-traversal", "path_traversal"), ("traversal", "path_traversal"),
    ("file-upload", "unrestricted_file_upload"), ("upload", "unrestricted_file_upload"),
    ("ssrf", "ssrf"), ("xxe", "xxe"), ("xml-external", "xxe"),
    ("deserial", "insecure_deserialization"), ("pickle", "insecure_deserialization"),
    ("open-redirect", "open_redirect"), ("redirect", "open_redirect"),
    ("csrf", "csrf"), ("cors", "cors_misconfig"), ("idor", "idor"),
    ("mass-assignment", "mass_assignment"), ("prototype-pollution", "prototype_pollution"),
    ("hardcoded", "hardcoded_secret"), ("secret", "hardcoded_secret"),
    ("token", "hardcoded_secret"), ("password", "hardcoded_secret"),
    ("jwt", "jwt_signature"), ("weak-hash", "weak_hash"), ("md5", "weak_hash"),
    ("sha1", "weak_hash"), ("crypto", "weak_crypto"), ("cipher", "weak_crypto"),
    ("insecure-random", "weak_random"), ("random", "weak_random"),
    ("tls", "cleartext_transport"), ("ssl", "cert_validation"),
    ("cookie", "insecure_cookie"), ("clickjack", "clickjacking"),
    ("redos", "redos"), ("regex", "redos"), ("log", "sensitive_logging"),
    ("rce", "rce"), ("remote-code", "rce"),
]
_SEV_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
_STOPWORDS = {"api", "v1", "v2", "app", "src", "www", "index", "main", "com", "net"}


def classify_rule(check_id: str, cwe: Optional[List[str]] = None) -> str:
    for c in cwe or []:
        m = re.search(r"CWE-(\d+)", str(c))
        if m and m.group(1) in _CWE_CLASS:
            return _CWE_CLASS[m.group(1)]
    cid = (check_id or "").lower()
    for kw, cls in _KEYWORD_CLASS:
        if kw in cid:
            return cls
    return "generic"


# Security rulesets covering EVERY statically-detectable class (not just SQLi):
#   p/security-audit  — broad security incl. taint (SQLi/XSS/cmdi/SSRF/…)
#   p/owasp-top-ten   — the OWASP Top 10 categories
#   p/cwe-top-25      — the CWE Top 25 most dangerous weaknesses
#   p/secrets         — hardcoded credentials / keys / tokens
#   p/default         — curated high-confidence security rules across languages
# Many are TAINT (dataflow) rules — they report a class only when untrusted input
# actually reaches a dangerous sink. Override the whole set with SEMGREP_RULESETS.
_DEFAULT_RULESETS = "p/security-audit p/owasp-top-ten p/cwe-top-25 p/secrets p/default"


def _ruleset_args(config: str = "") -> List[str]:
    """Build semgrep --config args. Override with SEMGREP_RULESETS
    (space/comma-separated pack names or paths). An explicit `config` wins."""
    if config:
        return ["--config", config]
    from core.common.settings import settings
    raw = settings.list("SEMGREP_RULESETS", _DEFAULT_RULESETS.split())
    args: List[str] = []
    for r in raw:
        if r:
            args += ["--config", r]
    return args or ["--config", "auto"]


def parse_semgrep_output(raw: Any) -> List[Dict[str, Any]]:
    """Map Semgrep JSON (dict or JSON string) to internal SAST finding dicts."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            return []
    findings: List[Dict[str, Any]] = []
    for r in (raw or {}).get("results", []) or []:
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        check_id = r.get("check_id", "")
        vuln_class = classify_rule(check_id, meta.get("cwe"))
        taint = _extract_taint(r.get("path", ""), extra.get("dataflow_trace"))
        findings.append({
            "id": f"sast::{check_id}::{r.get('path','')}::{(r.get('start',{}) or {}).get('line',0)}",
            "source": "sast",
            "check_id": check_id,
            "vuln_class": vuln_class,
            "type": vuln_class,
            "file": r.get("path", ""),
            "line": (r.get("start", {}) or {}).get("line", 0),
            "severity": _SEV_MAP.get(str(extra.get("severity", "")).upper(), "medium"),
            "title": (extra.get("message", "") or check_id)[:200],
            "cwe": meta.get("cwe") or [],
            "owasp": meta.get("owasp") or [],
            # Dataflow evidence: the untrusted-input → dangerous-sink path Semgrep
            # traced. Present only for taint rules (SQLi/XSS/cmdi/SSRF/etc.); this
            # is the "yes, exploitable in THIS code" proof.
            "taint": taint,
            # Taint findings carry a proven source→sink path → higher confidence.
            "confidence": "taint" if taint else "potential",
        })
    return findings


def _loc(entry: Any) -> Dict[str, Any]:
    """Pull {line, content} from a semgrep dataflow trace node (shape varies)."""
    loc = entry
    if isinstance(entry, dict) and "location" in entry:
        loc = entry.get("location") or {}
    if not isinstance(loc, dict):
        return {}
    line = (loc.get("start", {}) or {}).get("line", loc.get("line", 0))
    content = entry.get("content") if isinstance(entry, dict) else ""
    return {"line": line, "content": (content or "")[:200]}


def _extract_taint(path: str, trace: Any) -> Optional[Dict[str, Any]]:
    """Compact source→sink summary from Semgrep's dataflow_trace, or None."""
    if not isinstance(trace, dict):
        return None
    src = trace.get("taint_source")
    sink = trace.get("taint_sink")
    if not (src or sink):
        return None
    # Both are usually a nested list whose first useful element is a location.
    def _first(node):
        while isinstance(node, list) and node:
            node = node[0]
        return _loc(node) if node else {}
    out = {"file": path, "source": _first(src), "sink": _first(sink)}
    inter = trace.get("intermediate_vars") or []
    if isinstance(inter, list) and inter:
        out["intermediate"] = [_loc(v) for v in inter[:5] if v]
    return out


def _tokens(text: str) -> set:
    toks = set(re.split(r"[/._\-]+", (text or "").lower()))
    return {t for t in toks if t and t not in _STOPWORDS and not t.isdigit() and len(t) > 2}


def _vuln_class(f: Dict[str, Any]) -> str:
    return (f.get("vuln_class") or f.get("type") or "").lower()


def correlate_sast_dast(sast: List[Dict[str, Any]],
                        dast: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Correlate by vuln class + overlapping location tokens (SAST file path vs
    DAST url path)."""
    confirmed: List[Dict[str, Any]] = []
    matched_sast, matched_dast = set(), set()

    for i, s in enumerate(sast):
        s_cls = _vuln_class(s)
        s_toks = _tokens(s.get("file", ""))
        for j, d in enumerate(dast):
            if j in matched_dast:
                continue
            if _vuln_class(d) != s_cls or not s_cls or s_cls == "generic":
                continue
            d_toks = _tokens(d.get("url", "") or d.get("endpoint", "") or d.get("location", ""))
            if s_toks & d_toks:
                confirmed.append({
                    "vuln_class": s_cls, "confidence": "confirmed",
                    "severity": d.get("severity", s.get("severity", "medium")),
                    "sast": s, "dast": d,
                    "rationale": "same vuln class + location correlated in source and runtime",
                })
                matched_sast.add(i)
                matched_dast.add(j)
                break

    sast_only = [{**s, "confidence": "potential", "note": "SAST only — needs runtime validation"}
                 for i, s in enumerate(sast) if i not in matched_sast]
    dast_only = [{**d, "confidence": "confirmed_runtime", "note": "DAST only — confirmed at runtime"}
                 for j, d in enumerate(dast) if j not in matched_dast]
    return {"confirmed": confirmed, "sast_only": sast_only, "dast_only": dast_only}


class SastBridge:

    def semgrep_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def clone_repo(self, repo_url: str, dest: Optional[str] = None) -> Optional[str]:
        dest = dest or tempfile.mkdtemp(prefix="sast_repo_")
        try:
            subprocess.run(["git", "clone", "--depth", "1", repo_url, dest],
                           check=True, capture_output=True, timeout=600)
            return dest
        except Exception as e:
            logger.warning("sast_bridge: git clone failed (%s)", e)
            return None

    # semgrep is Linux/macOS-native. On a Windows API host it can't run locally,
    # so fall back to the Kali Linux container (where semgrep is installed) via
    # docker cp + docker exec — the same "tool lives in the container" pattern
    # used elsewhere. In AWS/Linux prod, the local path is used directly.
    @staticmethod
    def _kali_container() -> str:
        return os.getenv("KALI_CONTAINER_NAME", "kali-pentesting")

    def _container_semgrep_available(self) -> bool:
        try:
            r = subprocess.run(
                ["docker", "exec", self._kali_container(), "sh", "-c", "command -v semgrep"],
                capture_output=True, timeout=15)
            return r.returncode == 0
        except Exception:
            return False

    def run_semgrep(self, path: str, config: str = "") -> List[Dict[str, Any]]:
        cfg_args = _ruleset_args(config)
        if self.semgrep_available():
            try:
                r = subprocess.run(["semgrep", *cfg_args, "--json", path],
                                   capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800)
                out = parse_semgrep_output(r.stdout)
                # Registry packs need network; if they yielded nothing AND the run
                # errored, fall back to the bundled `auto` ruleset once.
                if not out and r.returncode not in (0, 1) and "auto" not in cfg_args:
                    logger.info("sast_bridge: ruleset run failed — falling back to --config auto")
                    r2 = subprocess.run(["semgrep", "--config", "auto", "--json", path],
                                        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800)
                    return parse_semgrep_output(r2.stdout)
                return out
            except Exception as e:
                logger.warning("sast_bridge: local semgrep run failed (%s)", e)
                return []
        if self._container_semgrep_available():
            return self._run_semgrep_in_container(path, config)
        logger.warning("sast_bridge: semgrep not available locally or in the %s container "
                       "— grey-box SAST skipped (pip install semgrep to enable)",
                       self._kali_container())
        return []

    def _run_semgrep_in_container(self, path: str, config: str = "auto") -> List[Dict[str, Any]]:
        import io
        import tarfile
        import uuid
        container = self._kali_container()
        name = f"sast_{uuid.uuid4().hex[:12]}"
        dest = f"/tmp/{name}"
        try:
            # Stream the code in as a tar over stdin (`docker cp -`) instead of a
            # host path. A Windows source path like C:\... breaks `docker cp`
            # because it splits args on ':' (drive letter looks like container:path).
            # The tar contains a top-level dir `name`; extracting into /tmp (an
            # existing dir) yields /tmp/name.
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                tar.add(path, arcname=name)
            # `docker exec -i … tar` reads the tar from stdin and extracts into
            # /tmp — avoids `docker cp`'s drive-letter/stream quirks entirely.
            cp = subprocess.run(
                ["docker", "exec", "-i", container, "tar", "xzf", "-", "-C", "/tmp"],
                input=buf.getvalue(), capture_output=True, timeout=300)
            if cp.returncode != 0:
                logger.warning("sast_bridge: tar-stream into container failed (%s)",
                               (cp.stderr or b"")[:200])
                return []
            r = subprocess.run(
                ["docker", "exec", container, "semgrep", *_ruleset_args(config), "--json", dest],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800)
            return parse_semgrep_output(r.stdout)
        except Exception as e:
            logger.warning("sast_bridge: container semgrep run failed (%s)", e)
            return []
        finally:
            try:
                subprocess.run(["docker", "exec", container, "rm", "-rf", dest],
                               capture_output=True, timeout=60)
            except Exception:
                pass

    def analyze(self, source_path: str = "", source_repo: str = "") -> List[Dict[str, Any]]:
        path = source_path
        cloned_dir = ""   # remove our own clone afterwards; findings persist in DB
        if source_repo and not path:
            path = self.clone_repo(source_repo) or ""
            cloned_dir = path
        try:
            if not path or not os.path.isdir(path):
                return []
            return self.run_semgrep(path)
        finally:
            if cloned_dir and os.path.isdir(cloned_dir):
                try:
                    shutil.rmtree(cloned_dir, ignore_errors=True)
                    logger.info("sast_bridge: removed cloned repo %s", cloned_dir)
                except Exception as e:
                    logger.warning("sast_bridge: clone cleanup failed (non-fatal): %s", e)
