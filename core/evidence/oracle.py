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
