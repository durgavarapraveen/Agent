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
    """Before/after resource comparison oracle (Phase 27).

    Captures a resource's state before an action, then compares after.
    Used for: IDOR (can user A see user B's data after manipulation?),
    privilege escalation (did role change?), data modification attacks.
    """

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
    """Check response headers for security-relevant signals."""

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
    """Check if response status code matches expected success/failure."""

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
    """Detect out-of-band interactions (DNS, HTTP callbacks)."""

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
