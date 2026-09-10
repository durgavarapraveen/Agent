from __future__ import annotations

import hashlib
import json
import logging
import time
import threading
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class TestOutcome(str, Enum):
    CONFIRMED = "confirmed"
    NO_ISSUE_FOUND = "no_issue_found"
    RULED_OUT = "ruled_out"
    NOT_APPLICABLE = "not_applicable"
    NEEDS_FOLLOW_UP = "needs_follow_up"


class FailureReason(str, Enum):
    RATE_LIMITED = "rate_limited"
    WAF_BLOCKED = "waf_blocked"
    AUTH_FAILED = "auth_failed"
    ENDPOINT_NOT_FOUND = "endpoint_not_found"
    TIMEOUT = "timeout"
    INVALID_INPUT = "invalid_input"
    TRANSIENT_ERROR = "transient_error"
    UNKNOWN = "unknown"
    NONE = "none"


@dataclass
class TestAttempt:
    test_id: str
    category: str
    endpoint: str
    parameter: str
    payload: str
    http_request_summary: str = ""
    http_status: int = 0
    response_length: int = 0
    response_time_ms: float = 0.0
    outcome: TestOutcome = TestOutcome.NO_ISSUE_FOUND
    failure_reason: FailureReason = FailureReason.NONE
    evidence: str = ""
    attempt_number: int = 1
    timestamp: float = field(default_factory=time.time)
    tool_name: str = ""
    agent_id: str = ""

    @property
    def surface_key(self) -> str:
        return f"{self.endpoint}|{self.parameter}"

    @property
    def risk_key(self) -> str:
        return f"{self.category}|{self.endpoint}|{self.parameter}"


class CoverageTracker:

    def __init__(self, output_dir: Optional[str] = None):
        self._attempts: List[TestAttempt] = []
        self._lock = threading.RLock()
        self._seen_keys: Dict[str, str] = {}
        self._output_dir = Path(output_dir) if output_dir else None

    def record(self, attempt: TestAttempt) -> str:
        with self._lock:
            if not attempt.test_id:
                raw = f"{attempt.category}|{attempt.endpoint}|{attempt.parameter}|{attempt.payload}|{attempt.attempt_number}"
                attempt.test_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
            self._attempts.append(attempt)

            key = f"{attempt.endpoint}|{attempt.parameter}|{attempt.category}"
            if key not in self._seen_keys:
                self._seen_keys[key] = attempt.test_id

        return attempt.test_id

    def get_attempts(self, **filters) -> List[TestAttempt]:
        with self._lock:
            results = list(self._attempts)
        for k, v in filters.items():
            results = [a for a in results if getattr(a, k, None) == v]
        return results

    def get_by_failure_reason(self, reason: FailureReason) -> List[TestAttempt]:
        return self.get_attempts(failure_reason=reason)

    def get_retryable(self) -> List[TestAttempt]:
        retryable = {FailureReason.RATE_LIMITED, FailureReason.TIMEOUT,
                     FailureReason.TRANSIENT_ERROR, FailureReason.WAF_BLOCKED}
        with self._lock:
            return [a for a in self._attempts if a.failure_reason in retryable]

    def get_never_attempted(self, planned_tests: List[Dict[str, str]]) -> List[Dict[str, str]]:
        attempted_keys = set()
        with self._lock:
            for a in self._attempts:
                attempted_keys.add(f"{a.category}|{a.endpoint}")
        return [t for t in planned_tests
                if f"{t.get('category', '')}|{t.get('endpoint', '')}" not in attempted_keys]

    def outcome_counts(self) -> Dict[str, int]:
        counts = {o.value: 0 for o in TestOutcome}
        counts["failed"] = 0
        with self._lock:
            for a in self._attempts:
                counts[a.outcome.value] = counts.get(a.outcome.value, 0) + 1
                if a.failure_reason not in (FailureReason.NONE,):
                    counts["failed"] += 1
        return counts

    def failure_breakdown(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        with self._lock:
            for a in self._attempts:
                if a.failure_reason != FailureReason.NONE:
                    counts[a.failure_reason.value] = counts.get(a.failure_reason.value, 0) + 1
        return counts

    def real_coverage(self, total_planned: int) -> Dict[str, Any]:
        with self._lock:
            confirmed = sum(1 for a in self._attempts if a.outcome == TestOutcome.CONFIRMED)
            no_issue = sum(1 for a in self._attempts if a.outcome == TestOutcome.NO_ISSUE_FOUND)
            ruled_out = sum(1 for a in self._attempts if a.outcome == TestOutcome.RULED_OUT)
            not_applicable = sum(1 for a in self._attempts if a.outcome == TestOutcome.NOT_APPLICABLE)
            needs_follow = sum(1 for a in self._attempts if a.outcome == TestOutcome.NEEDS_FOLLOW_UP)
            failed = sum(1 for a in self._attempts if a.failure_reason not in (FailureReason.NONE,))

        applicable = total_planned - not_applicable
        resolved = confirmed + no_issue + ruled_out
        real_pct = (resolved / applicable * 100) if applicable > 0 else 0.0

        return {
            "total_planned": total_planned,
            "not_applicable": not_applicable,
            "applicable": applicable,
            "confirmed_findings": confirmed,
            "no_issue_found": no_issue,
            "ruled_out": ruled_out,
            "needs_follow_up": needs_follow,
            "failed": failed,
            "failure_breakdown": self.failure_breakdown(),
            "real_coverage_pct": round(real_pct, 1),
            "honest_summary": (
                f"{confirmed} confirmed, {no_issue + ruled_out} clear, "
                f"{failed} failed, {needs_follow} need follow-up, "
                f"{not_applicable} not applicable"
            ),
        }

    def generate_report(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._attempts)
            by_category: Dict[str, Dict[str, int]] = {}
            by_endpoint: Dict[str, int] = {}
            for a in self._attempts:
                cat = by_category.setdefault(a.category, {"total": 0, "confirmed": 0, "failed": 0})
                cat["total"] += 1
                if a.outcome == TestOutcome.CONFIRMED:
                    cat["confirmed"] += 1
                if a.failure_reason != FailureReason.NONE:
                    cat["failed"] += 1
                by_endpoint[a.endpoint] = by_endpoint.get(a.endpoint, 0) + 1

        return {
            "total_attempts": total,
            "outcome_counts": self.outcome_counts(),
            "failure_breakdown": self.failure_breakdown(),
            "by_category": by_category,
            "endpoints_tested": len(by_endpoint),
            "coverage": self.real_coverage(total),
        }

    def persist(self, path: Optional[str] = None) -> None:
        out = Path(path) if path else (self._output_dir / "coverage_tracker.json" if self._output_dir else None)
        if not out:
            return
        out.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            data = {
                "generated_at": time.time(),
                "total_attempts": len(self._attempts),
                "report": self.generate_report(),
                "attempts": [asdict(a) for a in self._attempts[-500:]],
            }
        tmp = out.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        tmp.replace(out)
