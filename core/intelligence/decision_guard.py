import logging
from typing import Optional, Dict

from core.common.llm_schemas import LLMDecision
from core.memory.failure_store import FailureStore
from core.memory.strategy_store import StrategyStore

logger = logging.getLogger(__name__)


class DecisionGuard:
    """
    Safety and validation layer sitting between DeepSeek's outputs and the Scheduler.
    """

    def __init__(self, failure_store: FailureStore, strategy_store: StrategyStore, scope_config: Dict):
        self.failure_store = failure_store
        self.strategy_store = strategy_store
        self.scope_config = scope_config
        self.forbidden_actions = [
            "authorize", "bypass", "exec", "shell", "store_credential",
            "confirm_vulnerability", "finish_coverage"
        ]

    def _is_in_scope(self, target: str) -> bool:
        """Check if the target is within the authorized scope."""
        allowed_domains = self.scope_config.get("allowed_domains", [])
        return any(domain in target for domain in allowed_domains)

    def validate_decision(self, decision: LLMDecision, target_fingerprint: str) -> Optional[LLMDecision]:
        """
        Validates the decision. Returns the decision if safe, otherwise None.
        """
        action_lower = decision.action.lower()
        
        # 1. Unsafe Requests & Forbidden actions
        for forbidden in self.forbidden_actions:
            if forbidden in action_lower:
                logger.warning(f"DECISION_GUARD REJECTED: Forbidden action detected '{forbidden}' in '{decision.action}'")
                return None
                
        for hyp in decision.hypotheses:
            rationale_lower = hyp.rationale.lower()
            if "bash -c" in rationale_lower or "sh -c" in rationale_lower or "cmd.exe" in rationale_lower:
                logger.warning("DECISION_GUARD REJECTED: Potential shell command execution in rationale.")
                return None

            # 2. Out-of-scope targets
            if hyp.endpoint_id and not self._is_in_scope(hyp.endpoint_id):
                 logger.warning(f"DECISION_GUARD REJECTED: Target {hyp.endpoint_id} is out of scope.")
                 return None

            # 3. Duplicate experiments / Previously failed strategies
            if self.failure_store.has_failed_before(hyp.test_id, target_fingerprint):
                # Only reject if a better alternative might exist, for now we just reject it to force alternative
                logger.warning(f"DECISION_GUARD REJECTED: Strategy {hyp.test_id} has failed before for this fingerprint.")
                return None

        # 4. Direct vulnerability confirmation
        if "confirm" in action_lower and "vulnerability" in action_lower:
             logger.warning("DECISION_GUARD REJECTED: LLM attempted to directly confirm vulnerability.")
             return None

        # 5. Experiments without prerequisites - checking if it needs an identity but none is provided
        for hyp in decision.hypotheses:
             if "auth" in hyp.test_id.lower() and not hyp.identity_ids:
                  logger.warning("DECISION_GUARD REJECTED: Experiment requires prerequisites (identity) but none provided.")
                  return None

        logger.info(f"DECISION_GUARD accepted: {decision.action}")
        return decision
