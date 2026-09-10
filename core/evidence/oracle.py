from __future__ import annotations

import abc
import re
from typing import Any, Dict, List, Tuple

from core.evidence.evidence import Evidence

SQL_ERROR_PATTERNS = [
    r"SQL syntax",
    r"SQL syntax.*?MySQL",
    r"Warning.*?\Wmysqli?_",
    r"PostgreSQL.*?ERROR",
    r"ORA-\d{5}",
    r"Unclosed quotation mark",
    r"SQLITE_ERROR",
    r"SQLSTATE\[",
    r"java\.sql\.SQLException",
]

_SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)


class Oracle(abc.ABC):
    @abc.abstractmethod
    def apply(self, response: Dict[str, Any], evidence: Evidence) -> Tuple[bool, str]:
        ...


class DifferentialResponseOracle(Oracle):
    def __init__(self, baseline: Dict[str, Any]) -> None:
        self.baseline = baseline

    def apply(self, response: Dict[str, Any], evidence: Evidence) -> Tuple[bool, str]:
        baseline_body = str(self.baseline.get("body", ""))
        response_body = str(response.get("body", ""))
        baseline_status = self.baseline.get("status_code", 0)
        response_status = response.get("status_code", 0)

        different = (baseline_body != response_body) or (baseline_status != response_status)
        return different, "differential_response"


class ErrorSignatureOracle(Oracle):
    def __init__(self, patterns: List[str] | None = None) -> None:
        if patterns:
            self._re = re.compile("|".join(patterns), re.IGNORECASE)
        else:
            self._re = _SQL_ERROR_RE

    def apply(self, response: Dict[str, Any], evidence: Evidence) -> Tuple[bool, str]:
        body = str(response.get("body", ""))
        matched = bool(self._re.search(body))
        return matched, "error_signature"


class TimingDifferenceOracle(Oracle):
    def __init__(self, threshold_ms: float = 5000.0) -> None:
        self.threshold_ms = threshold_ms

    def apply(self, response: Dict[str, Any], evidence: Evidence) -> Tuple[bool, str]:
        elapsed = response.get("elapsed_ms", 0.0)
        return elapsed >= self.threshold_ms, "timing_difference"


class ReflectionOracle(Oracle):
    def __init__(self, payload: str = "") -> None:
        self.payload = payload

    def apply(self, response: Dict[str, Any], evidence: Evidence) -> Tuple[bool, str]:
        body = str(response.get("body", ""))
        payload = self.payload or response.get("payload", "")
        if not payload:
            return False, "reflection"
        return payload in body, "reflection"


class DOMExecutionOracle(Oracle):
    def apply(self, response: Dict[str, Any], evidence: Evidence) -> Tuple[bool, str]:
        body = str(response.get("body", ""))
        indicators = ["<script>", "onerror=", "onload=", "javascript:", "eval("]
        found = any(ind.lower() in body.lower() for ind in indicators)
        return found, "dom_execution"


class StateChangeOracle(Oracle):

    def __init__(self, before_state: Dict[str, Any] | None = None) -> None:
        self.before_state = before_state or {}

    def set_before(self, state: Dict[str, Any]) -> None:
        self.before_state = state

    def apply(self, response: Dict[str, Any], evidence: Evidence) -> Tuple[bool, str]:
        after_body = str(response.get("body", ""))
        after_status = response.get("status_code", 0)
        before_body = str(self.before_state.get("body", ""))
        before_status = self.before_state.get("status_code", 0)

        if not self.before_state:
            return False, "state_change_no_baseline"

        changes: List[str] = []

        if before_status != after_status:
            changes.append(f"status:{before_status}->{after_status}")

        if before_body and after_body and before_body != after_body:
            before_len = len(before_body)
            after_len = len(after_body)
            if before_len > 0:
                diff_ratio = abs(after_len - before_len) / before_len
                if diff_ratio > 0.1:
                    changes.append(f"body_size_delta:{diff_ratio:.1%}")

            before_keys = set(re.findall(r'"(\w+)":', before_body))
            after_keys = set(re.findall(r'"(\w+)":', after_body))
            new_keys = after_keys - before_keys
            if new_keys:
                changes.append(f"new_fields:{','.join(list(new_keys)[:5])}")

        if changes:
            evidence.add_metadata("state_changes", changes)
            return True, f"state_change:{';'.join(changes)}"
        return False, "state_change_no_diff"


class HeaderOracle(Oracle):

    def __init__(self, expected_headers: Dict[str, str] | None = None) -> None:
        self.expected = expected_headers or {}

    def apply(self, response: Dict[str, Any], evidence: Evidence) -> Tuple[bool, str]:
        headers = response.get("headers", {})
        if not isinstance(headers, dict):
            return False, "header_no_data"

        findings: List[str] = []

        if self.expected:
            for name, expected_val in self.expected.items():
                actual = headers.get(name, headers.get(name.lower(), ""))
                if expected_val == "*" and actual:
                    findings.append(f"{name}:present")
                elif expected_val and expected_val.lower() in str(actual).lower():
                    findings.append(f"{name}:matched")
        else:
            security_headers = {
                "Access-Control-Allow-Origin": None,
                "Access-Control-Allow-Credentials": "true",
                "X-Frame-Options": None,
                "Content-Security-Policy": None,
                "Set-Cookie": None,
            }
            for hdr, sensitive_val in security_headers.items():
                val = headers.get(hdr, headers.get(hdr.lower(), ""))
                if val:
                    if sensitive_val and sensitive_val.lower() in str(val).lower():
                        findings.append(f"{hdr}:{val[:50]}")
                    elif sensitive_val is None:
                        findings.append(f"{hdr}:present")

        if findings:
            return True, f"header:{';'.join(findings)}"
        return False, "header_no_match"


class StatusCodeOracle(Oracle):

    def __init__(self, expected_codes: List[int] | None = None,
                 unexpected_success: bool = False) -> None:
        self.expected_codes = expected_codes or []
        self.unexpected_success = unexpected_success

    def apply(self, response: Dict[str, Any], evidence: Evidence) -> Tuple[bool, str]:
        status = response.get("status_code", 0)

        if self.expected_codes:
            matched = status in self.expected_codes
            return matched, f"status_code:{status}"

        if self.unexpected_success:
            return 200 <= status < 300, f"unexpected_success:{status}"

        return False, f"status_code:{status}"


class OutOfBandOracle(Oracle):

    def __init__(self, callback_id: str = "") -> None:
        self.callback_id = callback_id
        self._interactions: List[Dict[str, Any]] = []

    def record_interaction(self, interaction: Dict[str, Any]) -> None:
        self._interactions.append(interaction)

    def apply(self, response: Dict[str, Any], evidence: Evidence) -> Tuple[bool, str]:
        oob_data = response.get("oob_interactions", [])
        if oob_data:
            self._interactions.extend(oob_data)

        if self._interactions:
            types = [i.get("type", "unknown") for i in self._interactions]
            evidence.add_metadata("oob_interactions", self._interactions[:5])
            return True, f"oob:{','.join(types)}"

        if self.callback_id:
            body = str(response.get("body", ""))
            if self.callback_id in body:
                return True, f"oob_callback_reflected:{self.callback_id}"

        return False, "oob_no_interaction"


# ── Unified Oracle Engine ──────────────────────────────────────────────
# Merged from core/verification/oracle_engine.py — single oracle registry
# covering all vuln classes from hypothesis_ledger._CLASS_PATTERNS.

from dataclasses import dataclass, field as _field
from typing import Optional as _Opt

@dataclass
class OracleResult:
    is_vulnerable: bool
    confidence: float
    evidence_nodes: list = _field(default_factory=list)
    reasoning: str = ""
    requires_manual_confirmation: bool = False


class OracleEngine:
    """Unified oracle engine — one per vuln class, extensible via register().

    Unknown/insufficient-oracle cases remain inconclusive (never silently confirmed).
    """

    def __init__(self, config: dict = None):
        self._config = config or {}
        self._oracles = {}
        self._register_defaults()

    def register(self, vuln_class: str, oracle_fn) -> None:
        self._oracles[vuln_class.upper()] = oracle_fn

    def evaluate(self, vulnerability_class: str, evidence: Dict[str, Any]) -> OracleResult:
        fn = self._oracles.get(vulnerability_class.upper())
        if not fn:
            return OracleResult(False, 0.0, [], f"No oracle for {vulnerability_class}. Inconclusive.")
        try:
            return fn(evidence, self._config)
        except Exception as e:
            return OracleResult(False, 0.0, [], f"Oracle error: {e}")

    def supported_classes(self) -> list:
        return sorted(self._oracles.keys())

    def _register_defaults(self):
        for cls, fn in _DEFAULT_ORACLES.items():
            self._oracles[cls] = fn


def _oracle_sqli(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    body = str(ev.get("response_body", "")).lower()
    if _SQL_ERROR_RE.search(body):
        return OracleResult(True, 0.95, [ev.get("evidence_id")], "Database error string in response.")
    threshold = cfg.get("sqli_time_threshold_ms", 5000)
    if ev.get("response_time_ms", 0) > threshold:
        return OracleResult(True, 0.85, [ev.get("evidence_id")], f"Time delay >{threshold}ms correlates with payload.")
    return OracleResult(False, 0.0, [], "No definitive SQLi indicators.")


def _oracle_nosqli(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    body = str(ev.get("response_body", ""))
    indicators = [r"MongoError", r"BSONError", r"\$ne", r"\$gt", r"operator.*invalid"]
    if any(re.search(p, body, re.IGNORECASE) for p in indicators):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "NoSQL error indicator in response.")
    return OracleResult(False, 0.0, [], "No NoSQLi indicators.")


def _oracle_xss(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    for event in ev.get("dom_events", []):
        if event.get("type") == "alert":
            return OracleResult(True, 1.0, [event.get("evidence_id")], "Payload execution confirmed via DOM alert.")
    body = str(ev.get("response_body", ""))
    payload = ev.get("payload", "")
    if payload and payload in body:
        return OracleResult(True, 0.7, [ev.get("evidence_id")], "Payload reflected unescaped in response body.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "Payload execution not observed.")


def _oracle_idor(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("status_code") == 200 and ev.get("data_belongs_to_other_user"):
        return OracleResult(True, 0.9, [ev.get("evidence_id")], "Cross-user data accessed.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No unauthorized cross-user data access.")


def _oracle_auth_bypass(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("status_code") == 200 and ev.get("requires_auth") and ev.get("session_role") == "anonymous":
        return OracleResult(True, 0.99, [ev.get("evidence_id")], "Authenticated endpoint accessed anonymously.")
    return OracleResult(False, 0.0, [], "Auth enforcement appears functional.")


def _oracle_ssrf(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    body = str(ev.get("response_body", ""))
    indicators = [r"169\.254\.169\.254", r"metadata", r"127\.0\.0\.1", r"localhost", r"internal"]
    if any(re.search(p, body, re.IGNORECASE) for p in indicators):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "Internal/metadata content in response.")
    for interaction in ev.get("oob_interactions", []):
        if interaction.get("type") in ("dns", "http"):
            return OracleResult(True, 0.9, [interaction.get("evidence_id")], "OOB interaction observed.")
    return OracleResult(False, 0.0, [], "No SSRF indicators.")


def _oracle_xxe(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    body = str(ev.get("response_body", ""))
    if re.search(r"root:.*?:0:0:", body) or "ENTITY" in body:
        return OracleResult(True, 0.9, [ev.get("evidence_id")], "XXE file content or entity marker in response.")
    return OracleResult(False, 0.0, [], "No XXE indicators.")


def _oracle_ssti(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    body = str(ev.get("response_body", ""))
    canary = ev.get("expected_result", "")
    if canary and canary in body:
        return OracleResult(True, 0.95, [ev.get("evidence_id")], f"Template expression evaluated: {canary} in response.")
    return OracleResult(False, 0.0, [], "No SSTI indicators.")


def _oracle_rce(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    body = str(ev.get("response_body", ""))
    canary = ev.get("expected_result", "")
    if canary and canary in body:
        return OracleResult(True, 0.95, [ev.get("evidence_id")], "Command output observed in response.")
    for interaction in ev.get("oob_interactions", []):
        return OracleResult(True, 0.9, [interaction.get("evidence_id")], "OOB interaction confirms code execution.")
    return OracleResult(False, 0.0, [], "No RCE indicators.")


def _oracle_lfi(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    body = str(ev.get("response_body", ""))
    if re.search(r"root:.*?:0:0:", body) or re.search(r"\[boot loader\]", body, re.IGNORECASE):
        return OracleResult(True, 0.9, [ev.get("evidence_id")], "File content observed in response.")
    return OracleResult(False, 0.0, [], "No LFI indicators.")


def _oracle_open_redirect(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    location = ev.get("redirect_location", "")
    expected_domain = ev.get("expected_redirect_domain", "")
    if location and expected_domain and expected_domain in location:
        return OracleResult(True, 0.9, [ev.get("evidence_id")], f"Redirect to external domain: {location}")
    return OracleResult(False, 0.0, [], "No open redirect indicators.")


def _oracle_mass_assignment(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("privilege_changed") or ev.get("role_escalated"):
        return OracleResult(True, 0.9, [ev.get("evidence_id")], "Mass assignment changed privilege/role.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No mass assignment indicators.")


def _oracle_access_control(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("status_code") == 200 and ev.get("expected_status") in (401, 403):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "Expected denial but got success.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "Access control appears functional.")


def _oracle_csrf(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("state_changed_without_token"):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "State-changing request succeeded without CSRF token.")
    return OracleResult(False, 0.0, [], "No CSRF indicators.")


_DEFAULT_ORACLES: Dict[str, Any] = {
    "SQLI": _oracle_sqli,
    "NOSQLI": _oracle_nosqli,
    "XSS": _oracle_xss,
    "IDOR": _oracle_idor,
    "AUTH_BYPASS": _oracle_auth_bypass,
    "SSRF": _oracle_ssrf,
    "XXE": _oracle_xxe,
    "SSTI": _oracle_ssti,
    "RCE": _oracle_rce,
    "LFI": _oracle_lfi,
    "OPEN_REDIRECT": _oracle_open_redirect,
    "MASS_ASSIGNMENT": _oracle_mass_assignment,
    "ACCESS_CONTROL": _oracle_access_control,
    "CSRF": _oracle_csrf,
}


_engine_instance: _Opt[OracleEngine] = None
_engine_lock = __import__("threading").RLock()


def get_oracle_engine(config: dict = None) -> OracleEngine:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = OracleEngine(config)
        return _engine_instance
