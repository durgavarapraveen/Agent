from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class DecisionAction(str, Enum):
    RUN_TEST = "RUN_TEST"
    RUN_EXPLOIT = "RUN_EXPLOIT"
    DISCOVER = "DISCOVER"
    VALIDATE = "VALIDATE"
    RETEST = "RETEST"
    SKIP = "SKIP"
    COMPLETE = "COMPLETE"
    WAIT = "WAIT"


@dataclass
class StructuredDecision:
    next_action: DecisionAction
    reason: str = ""
    target: str = ""
    endpoint: str = ""
    test_id: str = ""
    payload_id: str = ""
    identity: str = ""
    prerequisites: List[str] = field(default_factory=list)
    expected_evidence: List[str] = field(default_factory=list)
    risk: str = "low"
    priority: int = 5
    cost: str = "low"


@dataclass
class DecisionValidationResult:
    valid: bool = True
    rejected_reason: str = ""
    stage: str = ""


class StructuredStateBuilder:

    @staticmethod
    def build(
        attack_surface=None,
        target_health=None,
        findings=None,
        coverage_summary=None,
        identities=None,
        learning_summary=None,
        convergence_status=None,
        budget_status=None,
    ) -> Dict[str, Any]:
        state: Dict[str, Any] = {}

        # AttackSurfaceState summary
        if attack_surface:
            if hasattr(attack_surface, 'summary'):
                state["attack_surface"] = attack_surface.summary()
            else:
                state["attack_surface"] = {"status": "available"}
        else:
            state["attack_surface"] = {"status": "not_initialized"}

        # Target health
        if target_health:
            if hasattr(target_health, 'to_dict'):
                state["target_health"] = target_health.to_dict()
            else:
                state["target_health"] = {
                    "state": getattr(target_health, 'state', 'UNKNOWN'),
                    "concurrency": getattr(target_health, 'concurrency', 0),
                }
        else:
            state["target_health"] = {"state": "UNKNOWN"}

        # Findings summary
        if findings:
            by_state: Dict[str, int] = {}
            for f in findings:
                s = f.get("state", "UNKNOWN") if isinstance(f, dict) else "UNKNOWN"
                by_state[s] = by_state.get(s, 0) + 1
            state["findings"] = {
                "total": len(findings),
                "by_state": by_state,
            }
        else:
            state["findings"] = {"total": 0, "by_state": {}}

        # Coverage
        state["coverage"] = coverage_summary or {}

        # Identities
        if identities:
            if isinstance(identities, dict):
                state["identities"] = {
                    "count": len(identities),
                    "roles": list(identities.keys())[:10],
                }
            elif isinstance(identities, list):
                state["identities"] = {"count": len(identities), "roles": identities[:10]}
            else:
                state["identities"] = {"count": 0}
        else:
            state["identities"] = {"count": 0}

        # Learning
        state["learning_history"] = learning_summary or {}

        # Convergence
        if convergence_status:
            if isinstance(convergence_status, dict):
                state["convergence"] = convergence_status
            elif hasattr(convergence_status, '__dict__'):
                state["convergence"] = {
                    "is_converged": getattr(convergence_status, 'is_converged', False),
                    "reason": getattr(convergence_status, 'reason', ''),
                    "coverage_pct": getattr(convergence_status, 'coverage_pct', 0),
                }
        else:
            state["convergence"] = {"is_converged": False}

        # Budget
        state["budget"] = budget_status or {}

        return state




# ── Granular Budget Manager (Phase 36) ──

@dataclass
class GranularBudget:
    request_budget: int = 10000
    request_used: int = 0
    time_budget_seconds: int = 3600
    time_used_seconds: int = 0
    concurrency_budget: int = 10
    per_tool_budget: Dict[str, int] = field(default_factory=lambda: {})
    per_tool_used: Dict[str, int] = field(default_factory=lambda: {})
    per_target_budget: Dict[str, int] = field(default_factory=lambda: {})
    per_target_used: Dict[str, int] = field(default_factory=lambda: {})
    risk_budget: int = 100
    risk_used: int = 0
    evidence_budget: int = 500
    evidence_used: int = 0

    def record_request(self, tool: str = "", target: str = "", risk_cost: int = 1) -> None:
        self.request_used += 1
        self.risk_used += risk_cost
        if tool:
            self.per_tool_used[tool] = self.per_tool_used.get(tool, 0) + 1
        if target:
            self.per_target_used[target] = self.per_target_used.get(target, 0) + 1

    def record_evidence(self, count: int = 1) -> None:
        self.evidence_used += count

    def is_request_exhausted(self) -> bool:
        return self.request_used >= self.request_budget

    def is_risk_exhausted(self) -> bool:
        return self.risk_used >= self.risk_budget

    def is_tool_exhausted(self, tool: str) -> bool:
        limit = self.per_tool_budget.get(tool, 0)
        if limit <= 0:
            return False
        return self.per_tool_used.get(tool, 0) >= limit

    def is_target_exhausted(self, target: str) -> bool:
        limit = self.per_target_budget.get(target, 0)
        if limit <= 0:
            return False
        return self.per_target_used.get(target, 0) >= limit

    def is_any_exhausted(self) -> bool:
        return self.is_request_exhausted() or self.is_risk_exhausted()

    def remaining_summary(self) -> Dict[str, Any]:
        return {
            "requests": {"used": self.request_used, "budget": self.request_budget,
                         "remaining": max(0, self.request_budget - self.request_used)},
            "risk": {"used": self.risk_used, "budget": self.risk_budget,
                     "remaining": max(0, self.risk_budget - self.risk_used)},
            "evidence": {"used": self.evidence_used, "budget": self.evidence_budget},
            "per_tool_exhausted": [t for t in self.per_tool_used if self.is_tool_exhausted(t)],
            "per_target_exhausted": [t for t in self.per_target_used if self.is_target_exhausted(t)],
        }

    def untested_report(self, remaining_tests: List[str]) -> Dict[str, Any]:
        return {
            "budget_exhausted": self.is_any_exhausted(),
            "remaining_tests_count": len(remaining_tests),
            "remaining_tests_sample": remaining_tests[:20],
            "budget_summary": self.remaining_summary(),
        }
