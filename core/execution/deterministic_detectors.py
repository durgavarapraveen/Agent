"""Phase 8.3 — deterministic-first detectors.

Many findings need no LLM: CORS misconfig, missing security headers, info
disclosure in error pages, and error-based SQLi are all detectable by
regex/signature. Running these first eliminates 30-50% of executor LLM calls;
the LLM is reserved for ambiguous results and business-logic judgment.

Pure functions over (headers, body, status) → finding dicts. Fully testable.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

REQUIRED_SECURITY_HEADERS = {
    "x-frame-options": "Clickjacking protection",
    "content-security-policy": "XSS/injection mitigation",
    "strict-transport-security": "HSTS (TLS downgrade protection)",
    "x-content-type-options": "MIME-sniffing protection",
}

_STACK_TRACE_SIGNS = [
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"at [\w.$]+\(.*\.java:\d+\)"),
    re.compile(r"in <module>|File \".*\", line \d+"),
    re.compile(r"System\.\w+Exception"),
    re.compile(r"org\.springframework|com\.mysql|psycopg2\."),
]
_VERSION_DISCLOSURE = re.compile(r"(?i)(?:server|x-powered-by):?\s*[\w/]+/\d+\.\d+")
_SQL_ERROR_SIGNS = [
    re.compile(r"(?i)sql syntax.*MySQL"),
    re.compile(r"(?i)ORA-\d{5}"),
    re.compile(r"(?i)PostgreSQL.*ERROR"),
    re.compile(r"(?i)Unclosed quotation mark after the character string"),
    re.compile(r"(?i)SQLite3::"),
    re.compile(r"(?i)syntax error at or near"),
]


def _lower_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def detect_cors(headers: Optional[Dict[str, str]], origin_sent: str = "https://evil.example.com"
                ) -> Optional[Dict[str, Any]]:
    h = _lower_headers(headers)
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        return {"test": "cors", "severity": "high", "deterministic": True,
                "detail": "ACAO=* with credentials=true", "acao": acao}
    if acao in ("*", "null", origin_sent):
        sev = "medium" if acac != "true" else "high"
        return {"test": "cors", "severity": sev, "deterministic": True,
                "detail": f"permissive ACAO={acao}", "acao": acao}
    return None


def detect_missing_security_headers(headers: Optional[Dict[str, str]]) -> Optional[Dict[str, Any]]:
    h = _lower_headers(headers)
    missing = [name for name in REQUIRED_SECURITY_HEADERS if name not in h]
    if not missing:
        return None
    return {"test": "missing_security_headers", "deterministic": True,
            "severity": "medium" if len(missing) >= 2 else "low",
            "missing": missing}


def detect_info_disclosure(body: str) -> Optional[Dict[str, Any]]:
    body = body or ""
    for pat in _STACK_TRACE_SIGNS:
        if pat.search(body):
            return {"test": "info_disclosure", "deterministic": True, "severity": "medium",
                    "detail": "stack trace exposed in response"}
    if _VERSION_DISCLOSURE.search(body):
        return {"test": "info_disclosure", "deterministic": True, "severity": "low",
                "detail": "software version disclosed"}
    return None


def detect_error_based_sqli(body: str) -> Optional[Dict[str, Any]]:
    body = body or ""
    for pat in _SQL_ERROR_SIGNS:
        if pat.search(body):
            return {"test": "sqli", "deterministic": True, "severity": "high",
                    "detail": "SQL error signature in response (error-based SQLi)",
                    "needs_llm_classification": False}
    return None


def run_all(headers: Optional[Dict[str, str]] = None, body: str = "",
            status: int = 0) -> List[Dict[str, Any]]:
    """Run every deterministic detector; return the findings that fired."""
    findings = []
    for detector in (lambda: detect_cors(headers),
                     lambda: detect_missing_security_headers(headers),
                     lambda: detect_info_disclosure(body),
                     lambda: detect_error_based_sqli(body)):
        f = detector()
        if f:
            findings.append(f)
    return findings


def needs_llm(body: str, deterministic_findings: List[Dict[str, Any]]) -> bool:
    """A response needs LLM analysis only when deterministic detection is
    inconclusive (nothing fired but the response is non-trivial)."""
    if deterministic_findings:
        return False
    return bool(body and len(body) > 32)
