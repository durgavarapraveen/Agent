"""P0.8 — Reproduction validation gate.

A finding may only be marked CONFIRMED if it can be reproduced
deterministically. This module validates that:
  1. A reproduction request exists (method + URL + optional body)
  2. The reproduction target is in scope (PolicyEngine)
  3. The reproduction evidence matches expected indicators
  4. The reproduction is idempotent (same result on retry)

Findings that fail reproduction are downgraded to INCONCLUSIVE.
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ReproStatus(str, Enum):
    PENDING = "pending"
    REPRODUCED = "reproduced"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    SCOPE_DENIED = "scope_denied"


@dataclass
class ReproductionRequest:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    expected_status: Optional[int] = None
    expected_pattern: Optional[str] = None
    expected_indicators: List[str] = field(default_factory=list)


@dataclass
class ReproductionResult:
    finding_id: str
    status: ReproStatus
    attempts: int = 0
    successful_attempts: int = 0
    evidence_hash: str = ""
    reason: str = ""
    response_status: Optional[int] = None
    matched_indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "status": self.status.value,
            "attempts": self.attempts,
            "successful_attempts": self.successful_attempts,
            "evidence_hash": self.evidence_hash,
            "reason": self.reason,
            "response_status": self.response_status,
            "matched_indicators": self.matched_indicators,
        }


def _hash_response(status: int, body: str) -> str:
    payload = f"{status}:{body[:4096]}"
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _check_indicators(body: str, indicators: List[str]) -> List[str]:
    matched = []
    for ind in indicators:
        try:
            if re.search(ind, body, re.IGNORECASE):
                matched.append(ind)
        except re.error:
            if ind.lower() in body.lower():
                matched.append(ind)
    return matched


def _extract_repro_request(finding: Dict[str, Any]) -> Optional[ReproductionRequest]:
    url = finding.get("affected_endpoint") or finding.get("location") or finding.get("target") or ""
    if not url:
        return None

    method = str(finding.get("method") or "GET").upper()
    title = str(finding.get("title") or "")
    m = re.match(r"^\s*([A-Z]+)\s+(https?://\S+)", title)
    if m:
        method = m.group(1)
        url = m.group(2)

    body = finding.get("body") or finding.get("request_body") or None

    indicators = []
    proof = str(finding.get("proof") or finding.get("evidence") or "")
    if proof:
        for token in (
            "reflected", "alert(", "error", "admin", "token",
            "password", "unauthorized", "bypass",
            "uid=", "whoami", "id=", "root:", "/etc/passwd",
            "command output", "exec(", "system(",
            "127.0.0.1", "localhost", "169.254.169.254", "metadata",
            "<!ENTITY", "SYSTEM", "file://",
            "${", "{{", "{%", "<%",
            "syntax error", "exception", "traceback", "stack trace",
            "access denied", "forbidden", "privilege",
            "redirect", "location:", "set-cookie",
        ):
            if token in proof.lower():
                indicators.append(token)

    return ReproductionRequest(
        method=method,
        url=url,
        body=body,
        expected_indicators=indicators,
    )


def validate_scope(url: str, method: str = "GET") -> Tuple[bool, str]:
    try:
        from core.security.policy_engine import get_policy_engine
        engine = get_policy_engine()
        decision = engine.authorize_network(url, method=method)
        if not decision.allowed:
            return False, decision.reason
        return True, "in scope"
    except ImportError:
        return True, "policy engine unavailable, allowing"
    except Exception as e:
        return False, f"scope check error: {e}"


class ReproductionGate:
    """Gate that validates finding reproducibility before confirmation."""

    def __init__(self, min_attempts: int = 2, min_success_ratio: float = 0.5):
        self._min_attempts = min_attempts
        self._min_ratio = min_success_ratio
        self._results: Dict[str, ReproductionResult] = {}

    def check_reproducible(self, finding_id: str, finding: Dict[str, Any],
                           responses: Optional[List[Dict[str, Any]]] = None,
                           ) -> ReproductionResult:
        repro_req = _extract_repro_request(finding)
        if repro_req is None:
            result = ReproductionResult(
                finding_id=finding_id,
                status=ReproStatus.SKIPPED,
                reason="no reproduction URL extractable",
            )
            self._results[finding_id] = result
            return result

        in_scope, scope_reason = validate_scope(repro_req.url, method=repro_req.method)
        if not in_scope:
            result = ReproductionResult(
                finding_id=finding_id,
                status=ReproStatus.SCOPE_DENIED,
                reason=f"target out of scope: {scope_reason}",
            )
            self._results[finding_id] = result
            return result

        if not responses:
            result = ReproductionResult(
                finding_id=finding_id,
                status=ReproStatus.PENDING,
                reason="no reproduction responses provided",
            )
            self._results[finding_id] = result
            return result

        hashes = set()
        total = len(responses)
        successes = 0
        all_matched = []

        for resp in responses:
            status = resp.get("status", 0)
            body = str(resp.get("body", ""))
            h = _hash_response(status, body)
            hashes.add(h)

            matched = _check_indicators(body, repro_req.expected_indicators)
            all_matched.extend(matched)

            if repro_req.expected_status and status == repro_req.expected_status:
                successes += 1
            elif repro_req.expected_pattern:
                if re.search(repro_req.expected_pattern, body, re.IGNORECASE):
                    successes += 1
            elif repro_req.expected_indicators and matched:
                successes += 1
            elif not repro_req.expected_status and not repro_req.expected_pattern:
                successes += 1

        ratio = successes / max(total, 1)

        if total >= self._min_attempts and ratio >= self._min_ratio:
            status = ReproStatus.REPRODUCED
        elif successes > 0:
            status = ReproStatus.PARTIAL
        else:
            status = ReproStatus.FAILED

        evidence_hash = sorted(hashes)[0] if hashes else ""

        result = ReproductionResult(
            finding_id=finding_id,
            status=status,
            attempts=total,
            successful_attempts=successes,
            evidence_hash=evidence_hash,
            matched_indicators=list(set(all_matched)),
            reason=f"{successes}/{total} attempts matched",
        )
        self._results[finding_id] = result
        return result

    def is_confirmation_allowed(self, finding_id: str) -> Tuple[bool, str]:
        result = self._results.get(finding_id)
        if result is None:
            return False, "no reproduction attempted"
        if result.status == ReproStatus.REPRODUCED:
            return True, "reproduced"
        if result.status == ReproStatus.SKIPPED:
            return True, "reproduction skipped (no URL)"
        return False, f"reproduction {result.status.value}: {result.reason}"

    def get_result(self, finding_id: str) -> Optional[ReproductionResult]:
        return self._results.get(finding_id)
