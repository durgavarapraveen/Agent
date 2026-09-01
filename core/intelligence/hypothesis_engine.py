import json
import logging
from typing import List

from core.common.llm_schemas import LLMDecision
from core.intelligence.llm_router import DeepSeekRouter
from core.intelligence.llm_context_builder import LLMContextBuilder

logger = logging.getLogger(__name__)


class HypothesisEngine:
    """Uses DeepSeek to generate and rank hypotheses."""

    def __init__(self, router: DeepSeekRouter, context_builder: LLMContextBuilder):
        self.router = router
        self.context_builder = context_builder

    async def generate_hypotheses(self, observations: str) -> LLMDecision:
        """
        Generates hypotheses based on current context and observations.
        """
        context = self.context_builder.build_context()
        
        prompt = f"""
        Based on the following context and observations, generate a set of hypotheses for pentesting.
        Context:
        {json.dumps(context)}
        
        Observations:
        {observations}
        """

        decision = await self.router.route_request(
            purpose="simple_hypothesis_generation",
            prompt=prompt,
            schema=LLMDecision,
            max_retries=3
        )
        
        if decision:
            logger.info(f"Generated {len(decision.hypotheses)} hypotheses.")
            return decision
            
        # Return empty decision on total failure
        return LLMDecision(action="continue", hypotheses=[], confidence=0.0)
