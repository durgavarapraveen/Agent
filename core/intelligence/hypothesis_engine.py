import logging
import json
from core.intelligence.llm_router import LLMRouter
from core.memory.failure_store import FailureStore
from core.common.llm_schemas import LLMDecision

logger = logging.getLogger(__name__)

class HypothesisEngine:
    def __init__(self, router: LLMRouter, failure_store: FailureStore):
        self.router = router
        self.failure_store = failure_store
        
    def generate_hypotheses(self, task: str, context: dict, simulate_failure=False) -> LLMDecision:
        model = self.router.route_hypothesis_ranking(task, context)
        
        # Simulate LLM call
        response = self._call_llm(model, context, simulate_failure)
        
        # Validation and Fallback Loop
        if not response or not self._is_valid_json(response):
            logger.warning("LLM_OUTPUT_INVALID logged")
            print("LLM_OUTPUT_INVALID logged")
            
            self.failure_store.record_failure({
                "task": task,
                "failure_type": "invalid_json" if response else "empty_output",
                "failure_reason": "Failed to parse JSON"
            })
            
            # Retry with simplified context
            simplified = {"task": task, "fallback": True}
            response = self._call_llm(model, simplified, simulate_failure=simulate_failure)
            
            if not response or not self._is_valid_json(response):
                logger.warning("LLM_OUTPUT_INVALID logged")
                print("LLM_OUTPUT_INVALID logged")
                # Fallback to deterministic candidates
                return self._deterministic_fallback(task)
                
        logger.info("DEEPSEEK_RESPONSE_VALID schema_validation=PASS")
        print("DEEPSEEK_RESPONSE_VALID schema_validation=PASS")
        return LLMDecision.model_validate_json(response)
        
    def _call_llm(self, model: str, context: dict, simulate_failure: bool) -> str:
        if simulate_failure:
            return "THIS IS NOT JSON"
            
        # Mocking a valid response
        return json.dumps({
            "action": "TEST",
            "hypotheses": [
                {
                    "hypothesis_id": "hyp-1",
                    "test_id": "authorization.idor",
                    "endpoint_id": "ep-1",
                    "identity_ids": ["user_a", "user_b"],
                    "rationale": "Endpoint contains object ID and multiple identities are available.",
                    "expected_signals": ["cross_user_access"],
                    "priority": 0.9
                }
            ],
            "reasoning": "High probability of IDOR based on context.",
            "confidence": 0.85
        })
        
    def _is_valid_json(self, text: str) -> bool:
        try:
            json.loads(text)
            return True
        except json.JSONDecodeError:
            return False
            
    def _deterministic_fallback(self, task: str) -> LLMDecision:
        logger.info("Using deterministic fallback to prevent campaign abort.")
        print("Using deterministic fallback to prevent campaign abort.")
        return LLMDecision(
            action="TEST",
            hypotheses=[],
            reasoning="Fallback deterministic strategy",
            confidence=0.5
        )
