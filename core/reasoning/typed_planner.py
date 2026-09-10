import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from core.coverage.hypothesis_ledger import HypothesisLedger

logger = logging.getLogger(__name__)

@dataclass
class TypedAction:
    tool_name: str
    arguments: Dict[str, Any]
    expected_outcome: str

@dataclass
class TypedPlan:
    hypothesis: str
    prerequisites: List[str]
    actions: List[TypedAction]
    fallback_plan: Optional["TypedPlan"] = None

BLOCKED_TOOLS = frozenset({"shell", "bash", "cmd", "powershell", "sh", "exec", "eval"})

class TypedActionPlanner:
    def __init__(self, ledger: HypothesisLedger, policy_engine=None,
                 allowed_tools: Optional[frozenset] = None):
        self.ledger = ledger
        self.policy_engine = policy_engine
        self.allowed_tools = allowed_tools

    def validate_plan(self, plan: TypedPlan) -> bool:
        for action in plan.actions:
            if action.tool_name in BLOCKED_TOOLS:
                logger.error(f"Arbitrary execution blocked: {action.tool_name}")
                return False
            if self.allowed_tools and action.tool_name not in self.allowed_tools:
                logger.error(f"Tool not in allowlist: {action.tool_name}")
                return False
        if self.policy_engine:
            try:
                from core.decisions.policy_engine import enforce
                for action in plan.actions:
                    verdict = enforce("tool_health", {"tool": action.tool_name})
                    if not verdict.allow:
                        logger.error(f"Policy denied tool {action.tool_name}: {verdict.reason}")
                        return False
            except Exception as e:
                logger.error(f"Policy check failed (fail-closed): {e}")
                return False
        return True

    def submit_plan(self, plan: TypedPlan, url: str = "") -> bool:
        if not self.validate_plan(plan):
            return False
        self.ledger.record_hypothesis(
            url=url,
            hypothesis=plan.hypothesis,
            prerequisites=plan.prerequisites,
            expected_observation=plan.actions[-1].expected_outcome if plan.actions else "",
        )
        return True
