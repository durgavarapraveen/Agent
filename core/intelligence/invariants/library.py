from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Optional

from core.intelligence.differential.comparison import ResponseSnapshot

CheckFn = Callable[[ResponseSnapshot], Optional[str]]


@dataclass(frozen=True)
class SecurityInvariant:
    name: str
    category: str
    severity: str
    description: str
    check: CheckFn


def _snip(text: str, match: re.Match, width: int = 60) -> str:
    start = max(0, match.start() - width // 2)
    return text[start:start + width].replace("\n", " ")


_STACK_TRACE = re.compile(
    r"(Traceback \(most recent call last\)|"
    r"at [\w.$]+\([\w.$]+\.java:\d+\)|"
    r"\.rb:\d+:in\s|"
    r"System\.\w+Exception|"
    r"Fatal error:|Uncaught \w+Error|"
    r"org\.springframework|"
    r"werkzeug\.debug|Whoops\\Exception)", re.I)

_SQL_ERROR = re.compile(
    r"(SQLSTATE\[|ORA-\d{5}|you have an error in your sql syntax|"
    r"mysql_fetch|pg_query|psql:|PG::\w+Error|SQLite3::|"
    r"Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|"
    r"Unclosed quotation mark after the character string)", re.I)

_PATH_DISCLOSURE = re.compile(
    r"([A-Za-z]:\\(?:Users|inetpub|wwwroot|Windows|xampp|Program Files)\\[\w\\.\- ]+|"
    r"/(?:var/www|home/[\w.-]+|usr/local|opt|srv/www)/[\w/.\-]+)")

_SERVER_VERSION = re.compile(r"\b(?:Apache|nginx|Microsoft-IIS|PHP|Werkzeug|Express|"
                             r"OpenSSL|Jetty|Tomcat)/\d+(?:\.\d+)+", re.I)


def _no_stack_trace(snap: ResponseSnapshot) -> Optional[str]:
    m = _STACK_TRACE.search(snap.body or "")
    if m:
        return f"stack trace / framework internals leaked: '...{_snip(snap.body, m)}...'"
    return None


def _no_sql_error(snap: ResponseSnapshot) -> Optional[str]:
    m = _SQL_ERROR.search(snap.body or "")
    if m:
        return f"database error string leaked: '...{_snip(snap.body, m)}...'"
    return None


def _no_path_disclosure(snap: ResponseSnapshot) -> Optional[str]:
    m = _PATH_DISCLOSURE.search(snap.body or "")
    if m:
        return f"absolute server path disclosed: '{m.group(0)[:80]}'"
    return None


def _no_server_version(snap: ResponseSnapshot) -> Optional[str]:
    for k, v in snap.headers.items():
        if k.lower() in ("server", "x-powered-by") and _SERVER_VERSION.search(v or ""):
            return f"{k} header discloses component version: '{v[:80]}'"
    return None


def _html_success_has_content_type_options(snap: ResponseSnapshot) -> Optional[str]:
    if 200 <= snap.status < 300 and "html" in snap.content_type:
        stable = snap.stable_headers()
        if "x-content-type-options" not in stable:
            return "HTML 2xx response missing X-Content-Type-Options: nosniff"
    return None


def _html_success_has_frame_protection(snap: ResponseSnapshot) -> Optional[str]:
    if 200 <= snap.status < 300 and "html" in snap.content_type:
        stable = snap.stable_headers()
        xfo = stable.get("x-frame-options", "")
        csp = stable.get("content-security-policy", "")
        if not xfo.strip() and "frame-ancestors" not in csp.lower():
            return ("HTML 2xx response has no clickjacking defence "
                    "(neither X-Frame-Options nor CSP frame-ancestors)")
    return None


def _https_response_has_hsts(snap: ResponseSnapshot) -> Optional[str]:
    if snap.label.startswith("https://") and 200 <= snap.status < 400:
        if "strict-transport-security" not in snap.stable_headers():
            return "HTTPS response missing Strict-Transport-Security (HSTS) header"
    return None


BUILTIN_INVARIANTS: List[SecurityInvariant] = [
    SecurityInvariant("no_stack_trace", "info_leak", "medium",
                      "Responses must not leak stack traces or framework internals.",
                      _no_stack_trace),
    SecurityInvariant("no_sql_error", "info_leak", "high",
                      "Responses must not leak database engine errors.",
                      _no_sql_error),
    SecurityInvariant("no_path_disclosure", "info_leak", "low",
                      "Responses must not disclose absolute server filesystem paths.",
                      _no_path_disclosure),
    SecurityInvariant("no_server_version", "fingerprint", "low",
                      "Server/X-Powered-By headers should not disclose component versions.",
                      _no_server_version),
    SecurityInvariant("html_nosniff", "hardening", "low",
                      "HTML responses should send X-Content-Type-Options: nosniff.",
                      _html_success_has_content_type_options),
    SecurityInvariant("html_frame_protection", "hardening", "low",
                      "HTML responses should declare a clickjacking framing policy "
                      "(X-Frame-Options or CSP frame-ancestors).",
                      _html_success_has_frame_protection),
    SecurityInvariant("https_hsts", "hardening", "low",
                      "HTTPS responses should send Strict-Transport-Security.",
                      _https_response_has_hsts),
]
