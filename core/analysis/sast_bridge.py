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
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Map Semgrep check_id / CWE → internal vuln class.
_CWE_CLASS = {
    "89": "sqli", "79": "xss", "78": "command_injection", "77": "command_injection",
    "22": "path_traversal", "98": "lfi", "918": "ssrf", "611": "xxe",
    "94": "rce", "502": "insecure_deserialization", "306": "auth_bypass",
    "639": "idor", "601": "open_redirect", "352": "csrf",
}
_KEYWORD_CLASS = [
    ("sql", "sqli"), ("xss", "xss"), ("cross-site-scripting", "xss"),
    ("command-injection", "command_injection"), ("os-command", "command_injection"),
    ("path-traversal", "path_traversal"), ("traversal", "path_traversal"),
    ("ssrf", "ssrf"), ("xxe", "xxe"), ("deserial", "insecure_deserialization"),
    ("open-redirect", "open_redirect"), ("redirect", "open_redirect"),
    ("csrf", "csrf"), ("idor", "idor"), ("rce", "rce"),
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
            "confidence": "potential",   # needs runtime validation until correlated
        })
    return findings


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

    def run_semgrep(self, path: str, config: str = "auto") -> List[Dict[str, Any]]:
        if not self.semgrep_available():
            logger.warning("sast_bridge: semgrep not installed — grey-box SAST skipped "
                           "(pip install semgrep to enable)")
            return []
        try:
            r = subprocess.run(["semgrep", "--config", config, "--json", path],
                               capture_output=True, text=True, timeout=1800)
            return parse_semgrep_output(r.stdout)
        except Exception as e:
            logger.warning("sast_bridge: semgrep run failed (%s)", e)
            return []

    def analyze(self, source_path: str = "", source_repo: str = "") -> List[Dict[str, Any]]:
        path = source_path
        if source_repo and not path:
            path = self.clone_repo(source_repo) or ""
        if not path or not os.path.isdir(path):
            return []
        return self.run_semgrep(path)
