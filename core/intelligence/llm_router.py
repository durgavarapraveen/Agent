import json
import logging
import time
from typing import Dict, Any, Type, Optional

from pydantic import BaseModel, ValidationError
from agents.llm_client import LLMClient, TaskTier

logger = logging.getLogger(__name__)


class DeepSeekRouter:
    """
    Manages communication with DeepSeek API, enforces model policies,
    and implements smart fallbacks on invalid schemas.
    """

    def __init__(self):
        self.client = LLMClient.get()
        self.flash_model = "deepseek-v4-flash"
        self.thinking_model = "deepseek-v4-thinking"
        
        # Metrics
        self.metrics = {
            "llm_calls": 0,
            "valid_outputs": 0,
            "invalid_outputs": 0,
            "retries": 0,
            "deterministic_fallbacks": 0,
            "tokens": 0,
            "latency": 0.0,
            "estimated_cost": 0.0
        }

    def _determine_tier(self, purpose: str) -> TaskTier:
        """Applies DeepSeek model policy."""
        flash_purposes = [
            "classification", "normalization", "routine_prioritization",
            "summarization", "simple_hypothesis_generation"
        ]
        thinking_purposes = [
            "complex_authorization_reasoning", "business_logic_reasoning",
            "multi_step_attack_path_analysis", "ambiguous_evidence", "strategy_comparison"
        ]
        if purpose in thinking_purposes:
            return TaskTier.LARGE
        return TaskTier.SMALL

    async def route_request(self, purpose: str, prompt: str, schema: Type[BaseModel], max_retries: int = 3) -> Optional[BaseModel]:
        """
        Routes the request to DeepSeek, enforcing schema and bounded retries.
        """
        logger.info(f"DEEPSEEK_REQUEST purpose={purpose}")
        self.metrics["llm_calls"] += 1
        tier = self._determine_tier(purpose)
        
        start_time = time.time()
        
        for attempt in range(max_retries):
            try:
                # Call underlying generate_json which handles basic JSON conversion
                # Note: raw_json might actually be a dictionary already due to generate_json semantics
                raw_json = await self.client.generate_json(
                    prompt=prompt,
                    tier=tier,
                    system="You are a strict JSON-only API. Respond entirely in valid JSON."
                )
                
                # Strict schema validation
                validated_model = schema(**raw_json)
                
                latency = time.time() - start_time
                self.metrics["latency"] += latency
                self.metrics["valid_outputs"] += 1
                
                logger.info(f"DEEPSEEK_RESPONSE_VALID purpose={purpose} latency={latency:.2f}s")
                return validated_model
                
            except (ValidationError, ValueError, TypeError) as e:
                self.metrics["invalid_outputs"] += 1
                logger.warning(f"DEEPSEEK_RESPONSE_INVALID attempt={attempt + 1} reason='{str(e)}'")
                if attempt < max_retries - 1:
                    self.metrics["retries"] += 1
                else:
                    return self._deterministic_fallback(purpose, schema)
        
        return None

    def _deterministic_fallback(self, purpose: str, schema: Type[BaseModel]) -> Optional[BaseModel]:
        """Generates a deterministic candidate when LLM fails entirely."""
        self.metrics["deterministic_fallbacks"] += 1
        logger.info(f"Generating deterministic fallback for purpose={purpose}")
        # Placeholder for deterministic logic
        return None

    def get_metrics(self) -> Dict[str, Any]:
        return self.metrics
