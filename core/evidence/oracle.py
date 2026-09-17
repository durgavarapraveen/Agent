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


def _oracle_cors_misconfig(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    origin = ev.get("request_origin", "")
    acao = ev.get("acao", ev.get("access_control_allow_origin", ""))
    acac = ev.get("acac", ev.get("access_control_allow_credentials", False))
    acac = str(acac).lower() in ("true", "1")
    if acao == "*" and acac:
        return OracleResult(True, 0.9, [ev.get("evidence_id")], "Wildcard ACAO with credentials allowed.")
    if origin and acao and (acao == origin or acao == "null") and acac:
        return OracleResult(True, 0.9, [ev.get("evidence_id")], f"Reflected origin '{acao}' with credentials.")
    return OracleResult(False, 0.0, [], "No exploitable CORS misconfiguration.")


def _oracle_jwt(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("status_code") == 200 and (ev.get("jwt_alg_none_accepted") or ev.get("jwt_signature_stripped_accepted")):
        return OracleResult(True, 0.95, [ev.get("evidence_id")], "Forged JWT (alg=none / stripped signature) accepted.")
    if ev.get("jwt_weak_secret_cracked"):
        return OracleResult(True, 0.9, [ev.get("evidence_id")], "JWT signed with crackable weak secret.")
    return OracleResult(False, 0.0, [], "No JWT weakness indicators.")


def _oracle_graphql(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    body = str(ev.get("response_body", ""))
    if ev.get("introspection_enabled") or "__schema" in body or "__type" in body:
        return OracleResult(True, 0.8, [ev.get("evidence_id")], "GraphQL introspection exposed.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No GraphQL abuse indicators.")


def _oracle_api_abuse(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("no_rate_limit") and ev.get("status_code") == 200:
        return OracleResult(True, 0.7, [ev.get("evidence_id")], "No rate limiting on repeated requests.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No API abuse indicators.")


def _oracle_business_logic(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("workflow_step_skipped") or ev.get("state_changed_unexpectedly"):
        return OracleResult(True, 0.8, [ev.get("evidence_id")], "Workflow step skipped / invalid state transition accepted.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No business-logic bypass indicators.")


def _oracle_race_condition(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("duplicate_success_count", 0) > 1 or ev.get("double_spend"):
        return OracleResult(True, 0.85, [ev.get("evidence_id")],
                            f"Concurrent requests yielded {ev.get('duplicate_success_count', 2)} successes (race).")
    return OracleResult(False, 0.0, [], "No race-condition indicators.")


_SECRET_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]+|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|"
    r"(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"][^'\"]{8,})", re.IGNORECASE)


def _oracle_secret_exposure(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    body = str(ev.get("response_body", ""))
    if _SECRET_RE.search(body):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "Credential/secret pattern exposed in response.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No exposed secrets.")


_INFO_LEAK_RE = re.compile(
    r"(Traceback \(most recent call last\)|Warning: .* on line \d+|Exception in thread|"
    r"at [\w.$]+\([\w.]+\.java:\d+\)|/(?:home|var|usr|etc)/[\w./-]+|"
    r"(?:nginx|apache|php|express|django)/[\d.]+)", re.IGNORECASE)


def _oracle_info_disclosure(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    body = str(ev.get("response_body", ""))
    if _INFO_LEAK_RE.search(body):
        return OracleResult(True, 0.75, [ev.get("evidence_id")], "Stack trace / internal path / version disclosed.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No information disclosure.")


def _oracle_misconfiguration(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    body = str(ev.get("response_body", ""))
    if ev.get("debug_enabled") or ev.get("directory_listing") or re.search(r"Index of /", body):
        return OracleResult(True, 0.8, [ev.get("evidence_id")], "Debug mode / directory listing exposed.")
    return OracleResult(False, 0.0, [], "No misconfiguration indicators.")


def _oracle_weak_crypto(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("weak_cipher") or ev.get("tls_version") in ("SSLv2", "SSLv3", "TLSv1.0"):
        return OracleResult(True, 0.8, [ev.get("evidence_id")], f"Weak crypto: {ev.get('tls_version') or ev.get('weak_cipher')}.")
    if re.search(r"\b(MD5|SHA1|DES|RC4)\b", str(ev.get("response_body", ""))):
        return OracleResult(True, 0.6, [ev.get("evidence_id")], "Weak algorithm referenced in response.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No weak-crypto indicators.")


def _oracle_session(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("session_id_unchanged_after_login") or ev.get("session_fixation"):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "Session ID not rotated after auth (fixation).")
    return OracleResult(False, 0.0, [], "No session-hijacking indicators.")


def _oracle_identity_spoofing(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("status_code") == 200 and ev.get("spoofed_identity_accepted"):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "Spoofed identity header accepted (e.g. X-Forwarded-For / X-User).")
    return OracleResult(False, 0.0, [], "No identity-spoofing indicators.")


def _oracle_dom_manipulation(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    for event in ev.get("dom_events", []):
        if event.get("type") in ("alert", "sink_write", "dom_xss"):
            return OracleResult(True, 0.9, [event.get("evidence_id")], "Client-side sink executed attacker input.")
    return OracleResult(False, 0.0, [], "No DOM manipulation observed.")


def _oracle_dependency_vuln(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("cve_matched") and ev.get("component_version"):
        cves = ev.get("cve_matched")
        return OracleResult(True, 0.8, [ev.get("evidence_id")],
                            f"{ev.get('component')} {ev.get('component_version')} matches {cves}.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No known-vulnerable dependency matched.")


def _oracle_websocket(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("cross_origin_ws_accepted") or ev.get("ws_missing_origin_check"):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "Cross-origin WebSocket handshake accepted (CSWSH).")
    return OracleResult(False, 0.0, [], "No WebSocket-hijacking indicators.")


def _oracle_file_upload(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    body = str(ev.get("response_body", ""))
    canary = ev.get("expected_result", "")
    if ev.get("uploaded_file_executed") or (canary and canary in body):
        return OracleResult(True, 0.9, [ev.get("evidence_id")], "Uploaded file executed / accessible (unrestricted upload).")
    return OracleResult(False, 0.0, [], "No file-upload exploitation indicators.")


def _oracle_credential_bruteforce(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("no_lockout") and ev.get("auth_attempts", 0) >= cfg.get("bruteforce_attempt_threshold", 10):
        return OracleResult(True, 0.7, [ev.get("evidence_id")], "No account lockout / throttling on repeated auth attempts.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "Auth throttling appears present.")


def _oracle_clickjacking(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    xfo = str(ev.get("x_frame_options", "")).upper()
    csp = str(ev.get("csp", "")).lower()
    if not xfo and "frame-ancestors" not in csp:
        return OracleResult(True, 0.7, [ev.get("evidence_id")], "No X-Frame-Options and no CSP frame-ancestors — framable.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "Framing protection present.")


def _oracle_cache_poisoning(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    body = str(ev.get("response_body", ""))
    marker = ev.get("injected_marker", "")
    if ev.get("cache_hit") and marker and marker in body:
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "Injected input served from cache (poisoning).")
    return OracleResult(False, 0.0, [], "No cache-poisoning indicators.")


def _oracle_host_header_injection(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    injected = ev.get("injected_host", "")
    body = str(ev.get("response_body", ""))
    location = str(ev.get("redirect_location", ""))
    if injected and (injected in body or injected in location):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], f"Injected Host '{injected}' reflected in response/redirect.")
    return OracleResult(False, 0.0, [], "No host-header-injection indicators.")


def _oracle_http_smuggling(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    threshold = cfg.get("smuggling_time_threshold_ms", 5000)
    if ev.get("smuggling_time_diff_ms", 0) > threshold or ev.get("smuggling_socket_desync"):
        return OracleResult(True, 0.8, [ev.get("evidence_id")], "Timing differential / socket desync indicates request smuggling.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No request-smuggling indicators.")


def _oracle_email_injection(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    if ev.get("crlf_header_injected") or ev.get("extra_recipient_accepted"):
        return OracleResult(True, 0.8, [ev.get("evidence_id")], "CRLF header injection accepted in email field.")
    return OracleResult(False, 0.0, [], "No email/CRLF injection indicators.")


def _oracle_prototype_pollution(ev: Dict[str, Any], cfg: dict) -> OracleResult:
    body = str(ev.get("response_body", ""))
    if ev.get("proto_polluted") or "__proto__" in body or ev.get("polluted_property_reflected"):
        return OracleResult(True, 0.8, [ev.get("evidence_id")], "__proto__ property reflected / pollution observed.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No prototype-pollution indicators.")


# ── §7 per-category oracles (PATT categories previously lacking detection) ──
# Each stays honest: confirmed only on a real signal, else inconclusive.

_LDAP_ERR_RE = re.compile(r"(LDAP: error code|javax\.naming\.|com\.sun\.jndi|"
                          r"Invalid DN syntax|LDAPException|Bad search filter)", re.I)
_XPATH_ERR_RE = re.compile(r"(XPathException|MS\.Internal\.Xml|Expression must evaluate to a node-set|"
                           r"xmlXPathEval|SimpleXMLElement::xpath|Invalid expression)", re.I)
_XSLT_ERR_RE = re.compile(r"(xsl:|XSLTProcessor|Sablotron|libxslt|xmlXPathCompOpEval|Saxonc?)", re.I)


def _canary_hit(ev) -> bool:
    canary = ev.get("expected_result", "")
    return bool(canary) and canary in str(ev.get("response_body", ""))


def _oracle_ldap(ev, cfg):
    if _LDAP_ERR_RE.search(str(ev.get("response_body", ""))):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "LDAP error signature in response.")
    return OracleResult(False, 0.0, [], "No LDAP injection indicators.")


def _oracle_xpath(ev, cfg):
    if _XPATH_ERR_RE.search(str(ev.get("response_body", ""))):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "XPath error signature in response.")
    return OracleResult(False, 0.0, [], "No XPath injection indicators.")


def _oracle_xslt(ev, cfg):
    if _canary_hit(ev):
        return OracleResult(True, 0.9, [ev.get("evidence_id")], "XSLT expression evaluated (canary in response).")
    if _XSLT_ERR_RE.search(str(ev.get("response_body", ""))):
        return OracleResult(True, 0.7, [ev.get("evidence_id")], "XSLT processor error/version disclosed.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No XSLT injection indicators.")


def _oracle_ssi(ev, cfg):
    if _canary_hit(ev):
        return OracleResult(True, 0.9, [ev.get("evidence_id")], "SSI directive evaluated (canary in response).")
    return OracleResult(False, 0.0, [], "No SSI injection indicators.")


def _oracle_css_injection(ev, cfg):
    body = str(ev.get("response_body", "")); payload = ev.get("payload") or ""
    if payload and payload in body and ("<style" in body.lower() or "style=" in body.lower()):
        return OracleResult(True, 0.6, [ev.get("evidence_id")], "Payload reflected in CSS context.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No CSS injection indicators.")


def _oracle_csv_injection(ev, cfg):
    payload = ev.get("payload") or ""
    if payload[:1] in ("=", "+", "-", "@") and payload in str(ev.get("response_body", "")):
        return OracleResult(True, 0.6, [ev.get("evidence_id")], "Formula payload stored/reflected (CSV/formula injection).",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No CSV injection indicators.")


def _oracle_latex(ev, cfg):
    if _canary_hit(ev):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "LaTeX command output observed (canary).")
    return OracleResult(False, 0.0, [], "No LaTeX injection indicators.")


def _oracle_crlf(ev, cfg):
    headers = ev.get("headers", {}) or {}
    injected = ev.get("injected_header") or "x-crlf-test"
    if any(injected.lower() in str(k).lower() or injected.lower() in str(v).lower()
           for k, v in headers.items()):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "Injected CRLF header reflected in response headers.")
    payload = ev.get("payload", "")
    if "\r\n" in payload and "set-cookie" in {str(k).lower() for k in headers}:
        return OracleResult(True, 0.6, [ev.get("evidence_id")], "CRLF payload produced extra header.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No CRLF injection indicators.")


def _oracle_hpp(ev, cfg):
    if ev.get("both_values_reflected") or ev.get("hpp_behavior_changed"):
        return OracleResult(True, 0.6, [ev.get("evidence_id")], "Duplicate parameter altered behavior (HPP).",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No HTTP parameter pollution indicators.")


def _oracle_type_juggling(ev, cfg):
    if ev.get("status_code") == 200 and (ev.get("loose_compare_accepted") or ev.get("auth_bypassed_via_type")):
        return OracleResult(True, 0.8, [ev.get("evidence_id")], "Loose type comparison accepted forged value.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No type-juggling indicators.")


_ORM_LEAK_RE = re.compile(r'"(password|passwd|hash|salt|ssn|credit_card|secret|api_key|token)"\s*:',
                          re.I)


def _oracle_orm_leak(ev, cfg):
    if _ORM_LEAK_RE.search(str(ev.get("response_body", ""))):
        return OracleResult(True, 0.75, [ev.get("evidence_id")], "Sensitive ORM field exposed in response (over-fetch).",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No ORM leak indicators.")


def _oracle_cspt(ev, cfg):
    body = str(ev.get("response_body", "")); payload = ev.get("payload") or ""
    if payload and payload in body and ("fetch(" in body or "XMLHttpRequest" in body or "src=" in body.lower()):
        return OracleResult(True, 0.6, [ev.get("evidence_id")], "Traversal reflected into a client-side URL sink.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No client-side path traversal indicators.")


def _oracle_redos(ev, cfg):
    threshold = cfg.get("redos_time_threshold_ms", 5000)
    if ev.get("response_time_ms", 0) > threshold:
        return OracleResult(True, 0.8, [ev.get("evidence_id")], f"Response time >{threshold}ms on crafted regex input (ReDoS).")
    return OracleResult(False, 0.0, [], "No ReDoS indicators.")


def _oracle_prompt_injection(ev, cfg):
    if _canary_hit(ev):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "Injected instruction obeyed by LLM (canary echoed).")
    return OracleResult(False, 0.0, [], "No prompt-injection indicators.")


def _oracle_dom_clobbering(ev, cfg):
    body = str(ev.get("response_body", "")); payload = ev.get("payload") or ""
    if payload and payload in body and re.search(r'\b(id|name)\s*=', body):
        return OracleResult(True, 0.6, [ev.get("evidence_id")], "Attacker id/name attribute reflected (DOM clobbering surface).",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No DOM clobbering indicators.")


def _oracle_xs_leak(ev, cfg):
    if ev.get("cross_origin_observable") or ev.get("status_oracle_diff"):
        return OracleResult(True, 0.6, [ev.get("evidence_id")], "Cross-site observable difference (status/size/timing).",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No XS-Leak indicators.")


def _oracle_saml(ev, cfg):
    if ev.get("status_code") == 200 and (ev.get("saml_signature_stripped_accepted") or ev.get("saml_assertion_forged_accepted")):
        return OracleResult(True, 0.9, [ev.get("evidence_id")], "Forged/unsigned SAML assertion accepted.")
    return OracleResult(False, 0.0, [], "No SAML injection indicators.")


def _oracle_zip_slip(ev, cfg):
    if ev.get("path_traversal_file_written") or _canary_hit(ev):
        return OracleResult(True, 0.85, [ev.get("evidence_id")], "Archive entry escaped extraction dir (Zip Slip).")
    return OracleResult(False, 0.0, [], "No Zip Slip indicators.")


def _oracle_reverse_proxy(ev, cfg):
    body = str(ev.get("response_body", ""))
    if ev.get("internal_path_reachable") or re.search(r"(X-Accel|/server-status|/nginx_status|upstream)", body, re.I):
        return OracleResult(True, 0.7, [ev.get("evidence_id")], "Reverse-proxy misrouting / internal endpoint reachable.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No reverse-proxy misconfiguration indicators.")


def _oracle_mgmt_interface(ev, cfg):
    body = str(ev.get("response_body", ""))
    if ev.get("status_code") == 200 and re.search(r"(phpMyAdmin|Jenkins|Actuator|/manager/html|Kibana|Grafana|Adminer|console)", body, re.I):
        return OracleResult(True, 0.75, [ev.get("evidence_id")], "Exposed management/admin interface.")
    return OracleResult(False, 0.0, [], "No exposed management interface.")


def _oracle_insecure_random(ev, cfg):
    if ev.get("token_predictable") or ev.get("low_entropy_token"):
        return OracleResult(True, 0.7, [ev.get("evidence_id")], "Predictable/low-entropy token observed.",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No insecure-randomness indicators.")


def _oracle_tabnabbing(ev, cfg):
    body = str(ev.get("response_body", ""))
    if re.search(r'target\s*=\s*["\']_blank["\']', body, re.I) and "noopener" not in body.lower():
        return OracleResult(True, 0.6, [ev.get("evidence_id")], "target=_blank link without rel=noopener (tabnabbing).",
                            requires_manual_confirmation=True)
    return OracleResult(False, 0.0, [], "No tabnabbing indicators.")


def _oracle_dns_rebinding(ev, cfg):
    for interaction in ev.get("oob_interactions", []):
        if interaction.get("type") in ("dns", "http"):
            return OracleResult(True, 0.8, [interaction.get("evidence_id")], "OOB interaction confirms DNS rebinding/SSRF.")
    return _oracle_ssrf(ev, cfg)


_DEFAULT_ORACLES: Dict[str, Any] = {
    # ── original 14 ──
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
    # ── expansion: keys match hypothesis ATTACK_TYPE_MAP values ──
    "CORS_MISCONFIGURATION": _oracle_cors_misconfig,
    "JWT_MANIPULATION": _oracle_jwt,
    "GRAPHQL_INTROSPECTION": _oracle_graphql,
    "API_ABUSE": _oracle_api_abuse,
    "BUSINESS_LOGIC_BYPASS": _oracle_business_logic,
    "RACE_CONDITION": _oracle_race_condition,
    "SECRET_EXPOSURE": _oracle_secret_exposure,
    "INFORMATION_DISCLOSURE": _oracle_info_disclosure,
    "MISCONFIGURATION": _oracle_misconfiguration,
    "WEAK_CRYPTO": _oracle_weak_crypto,
    "SESSION_HIJACKING": _oracle_session,
    "IDENTITY_SPOOFING": _oracle_identity_spoofing,
    "DOM_MANIPULATION": _oracle_dom_manipulation,
    "DEPENDENCY_VULNERABILITY": _oracle_dependency_vuln,
    "WEBSOCKET_HIJACKING": _oracle_websocket,
    "FILE_UPLOAD": _oracle_file_upload,
    "CREDENTIAL_BRUTE_FORCE": _oracle_credential_bruteforce,
    # ── roadmap-named aliases (same fns, alternate keys callers may use) ──
    "CORS": _oracle_cors_misconfig,
    "JWT_WEAKNESS": _oracle_jwt,
    "JWT": _oracle_jwt,
    "GRAPHQL_ABUSE": _oracle_graphql,
    "GRAPHQL": _oracle_graphql,
    "BUSINESS_LOGIC": _oracle_business_logic,
    "SECRET_EXPOSURE_LEAK": _oracle_secret_exposure,
    "SESSION": _oracle_session,
    "WEBSOCKET_HIJACK": _oracle_websocket,
    "DEPENDENCY_VULN": _oracle_dependency_vuln,
    "CLICKJACKING": _oracle_clickjacking,
    "CACHE_POISONING": _oracle_cache_poisoning,
    "HOST_HEADER_INJECTION": _oracle_host_header_injection,
    "HTTP_SMUGGLING": _oracle_http_smuggling,
    "EMAIL_INJECTION": _oracle_email_injection,
    "PROTOTYPE_POLLUTION": _oracle_prototype_pollution,
    # ── §7 full-category coverage ──
    "LDAP_INJECTION": _oracle_ldap,
    "XPATH_INJECTION": _oracle_xpath,
    "XSLT_INJECTION": _oracle_xslt,
    "SSI_INJECTION": _oracle_ssi,
    "CSS_INJECTION": _oracle_css_injection,
    "CSV_INJECTION": _oracle_csv_injection,
    "LATEX_INJECTION": _oracle_latex,
    "CRLF_INJECTION": _oracle_crlf,
    "HTTP_PARAMETER_POLLUTION": _oracle_hpp,
    "TYPE_JUGGLING": _oracle_type_juggling,
    "ORM_LEAK": _oracle_orm_leak,
    "CLIENT_SIDE_PATH_TRAVERSAL": _oracle_cspt,
    "REDOS": _oracle_redos,
    "PROMPT_INJECTION": _oracle_prompt_injection,
    "DOM_CLOBBERING": _oracle_dom_clobbering,
    "XS_LEAK": _oracle_xs_leak,
    "SAML_INJECTION": _oracle_saml,
    "ZIP_SLIP": _oracle_zip_slip,
    "REVERSE_PROXY_MISCONFIG": _oracle_reverse_proxy,
    "INSECURE_MANAGEMENT_INTERFACE": _oracle_mgmt_interface,
    "INSECURE_RANDOMNESS": _oracle_insecure_random,
    "TABNABBING": _oracle_tabnabbing,
    "DNS_REBINDING": _oracle_dns_rebinding,
    # aliases → existing oracles
    "ACCOUNT_TAKEOVER": _oracle_auth_bypass,
    "DEPENDENCY_CONFUSION": _oracle_dependency_vuln,
    "VIRTUAL_HOSTS": _oracle_host_header_injection,
    "GOOGLE_WEB_TOOLKIT": _oracle_misconfiguration,
    "JAVA_RMI": _oracle_rce,
    "COMMAND_INJECTION": _oracle_rce,
    "DIRECTORY_TRAVERSAL": _oracle_lfi,
    "FILE_INCLUSION": _oracle_lfi,
    "DENIAL_OF_SERVICE": _oracle_redos,
    "REGULAR_EXPRESSION": _oracle_redos,
    "CVE_EXPLOITS": _oracle_dependency_vuln,
    "API_KEY_LEAKS": _oracle_secret_exposure,
    "INSECURE_SOURCE_CODE_MANAGEMENT": _oracle_info_disclosure,
    "HIDDEN_PARAMETERS": _oracle_api_abuse,
    "OAUTH_MISCONFIGURATION": _oracle_open_redirect,
    "WEB_CACHE_DECEPTION": _oracle_cache_poisoning,
    "REQUEST_SMUGGLING": _oracle_http_smuggling,
    "EXTERNAL_VARIABLE_MODIFICATION": _oracle_mass_assignment,
    "BUSINESS_LOGIC_ERRORS": _oracle_business_logic,
    "BRUTE_FORCE": _oracle_credential_bruteforce,
    "WEB_SOCKETS": _oracle_websocket,
    "UPLOAD_INSECURE_FILES": _oracle_file_upload,
    "SSI": _oracle_ssi,
}


_engine_instance: _Opt[OracleEngine] = None
_engine_lock = __import__("threading").RLock()


def get_oracle_engine(config: dict = None) -> OracleEngine:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = OracleEngine(config)
        return _engine_instance
