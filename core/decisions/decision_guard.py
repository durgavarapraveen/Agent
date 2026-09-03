import logging
from typing import Tuple, Optional, Any, Set, List
from core.coverage.coverage_engine import CoverageEngine
from core.learning.experience_learner import ExperienceLearner
from core.tools.capability_mapper import CapabilityMapper

logger = logging.getLogger(__name__)

FAILURE_THRESHOLD = 2
DEFAULT_TIME_BUDGET_SECONDS = 3600


class DecisionGuardV2:
    def __init__(
        self,
        coverage_engine: CoverageEngine,
        experience_learner: ExperienceLearner,
        capability_mapper: Optional[CapabilityMapper] = None,
        available_tools: Optional[Set[str]] = None,
        time_budget_seconds: float = DEFAULT_TIME_BUDGET_SECONDS,
    ):
        self.coverage_engine = coverage_engine
        self.learner = experience_learner
        self.capability_mapper = capability_mapper or CapabilityMapper()
        self.available_tools = available_tools or set()
        self.time_budget_seconds = time_budget_seconds
        self.time_spent_seconds: float = 0.0
        self._queued: Set[str] = set()
        self._blocked: Set[str] = set()
        # Optional closed-loop reward policy (set by CentralBrain). When present,
        # alternative-strategy selection is ordered by measured reward yield.
        self.reward_policy: Optional[Any] = None

    def validate(self, experiment: Any) -> Tuple[bool, str, Optional[str]]:
        test_id = _attr(experiment, "test_id", "")
        strategy = _attr(experiment, "test_strategy", _attr(experiment, "strategy_id", "default"))
        endpoint_id = _attr(experiment, "target_endpoint_id", _attr(experiment, "endpoint_id", ""))
        estimated_seconds = _attr(experiment, "estimated_seconds", 60)

        sig = f"{test_id}|{endpoint_id}|{strategy}"

        # 1. Already terminal
        if self.coverage_engine.is_test_terminal(test_id):
            return False, f"Test '{test_id}' already in terminal state", None

        # 2. Skip loop — previously blocked or failed identical experiment
        if sig in self._blocked:
            alt = self._find_alternative(test_id, strategy)
            return False, f"Experiment '{sig}' previously blocked/failed", alt

        # 3. Repeated failure pattern
        fail_count = self.learner.get_failure_count(strategy, test_id)
        if fail_count >= FAILURE_THRESHOLD:
            alt = self._find_alternative(test_id, strategy)
            self._blocked.add(sig)
            return False, f"Strategy '{strategy}' failed {fail_count}x for '{test_id}'", alt

        # 4. Capability exists — test_id must be in catalog
        test_def = self.coverage_engine.catalog.get_test(test_id)
        if test_def is None:
            return False, f"No test definition for '{test_id}'", None

        # 5. Tool available
        tool_name = self._resolve_tool(strategy, test_id)
        if tool_name and self.available_tools and tool_name not in self.available_tools:
            alt = self._find_alternative(test_id, strategy)
            return False, f"Tool '{tool_name}' not available", alt

        # 6. Duplicate queued
        if sig in self._queued:
            return False, f"Duplicate experiment already queued: '{sig}'", None

        # 7. Time budget
        if self.time_spent_seconds + estimated_seconds > self.time_budget_seconds:
            return False, f"Time budget exceeded ({self.time_spent_seconds:.0f}s spent, {estimated_seconds}s needed, {self.time_budget_seconds:.0f}s total)", None

        self._queued.add(sig)
        self.time_spent_seconds += estimated_seconds
        logger.info(f"DECISION_GUARD_V2 decision=ACCEPT sig={sig}")
        return True, "accepted", None

    def mark_failed(self, experiment: Any):
        test_id = _attr(experiment, "test_id", "")
        strategy = _attr(experiment, "test_strategy", _attr(experiment, "strategy_id", "default"))
        endpoint_id = _attr(experiment, "target_endpoint_id", _attr(experiment, "endpoint_id", ""))
        sig = f"{test_id}|{endpoint_id}|{strategy}"
        self._blocked.add(sig)
        self._queued.discard(sig)

    def _find_alternative(self, test_id: str, failed_strategy: str) -> Optional[str]:
        test_def = self.coverage_engine.catalog.get_test(test_id)

        # Gather viable candidates (not the failed one, under the failure threshold).
        candidates: List[str] = []
        if test_def:
            for strat in test_def.execution_strategies:
                if strat != failed_strategy and self.learner.get_failure_count(strat, test_id) < FAILURE_THRESHOLD:
                    candidates.append(strat)

        tools = self.capability_mapper.get_tools_for_capability(test_id)
        if not tools:
            category = test_def.category if test_def else ""
            tools = self.capability_mapper.get_tools_for_capability(category)
        for tool in tools:
            if tool != failed_strategy and tool not in candidates \
                    and self.learner.get_failure_count(tool, test_id) < FAILURE_THRESHOLD:
                candidates.append(tool)

        if not candidates:
            return None

        # Reward-policy ordering: pick the highest measured-yield alternative.
        if self.reward_policy is not None:
            try:
                best = self.reward_policy.preferred(test_id, candidates)
                if best:
                    return best
            except Exception:
                pass
        return candidates[0]

    def _resolve_tool(self, strategy: str, test_id: str) -> Optional[str]:
        if strategy and strategy not in ("default", ""):
            return strategy
        return None


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)
