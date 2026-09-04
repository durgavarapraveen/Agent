import requests
import logging
import json
from typing import Dict, Any, List
from core.llm.schemas import RankedCandidatesResult, GeneratedPayloadsResult, LLMResponse
from core.llm.context_builder import ContextBuilder

logger = logging.getLogger(__name__)

class LLMRouter:
    def __init__(self, api_key: str, model: str = "deepseek-reasoner"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.deepseek.com/v1/chat/completions"

    def _fallback_heuristic(self, task_type: str, candidates: List[Any]) -> Dict[str, Any]:
        """Provides a safe, degraded local heuristic if the LLM fails."""
        logger.warning(f"Using local fallback heuristic for {task_type}")
        
        if task_type == "hypothesis_ranking":
            # Assign descending scores
            ranked = []
            for i, c in enumerate(candidates):
                score = max(0.0, 1.0 - (i * 0.1))
                ranked.append({"id": c.get("id", str(i)) if isinstance(c, dict) else str(c), "score": score, "justification": "Fallback heuristic"})
            return {"candidates": ranked}
            
        elif task_type == "payload_generation":
            return {"payloads": [{"value": "' OR 1=1--", "expected_behavior": "SQLi Bypass", "justification": "Fallback"}]}
            
        return {}

    def route_task(self, task_type: str, context: Dict[str, Any], candidates: List[Any]) -> LLMResponse:
        """
        Routes the task to DeepSeek API. Extracts thinking trace and structured JSON.
        """
        instruction_map = {
            "hypothesis_ranking": "Rank the following hypotheses by likelihood of success (0.0 to 1.0). Return a JSON object matching {'candidates': [{'id': '...', 'score': 0.9, 'justification': '...'}]}",
            "payload_generation": "Generate targeted injection payloads. Return JSON object matching {'payloads': [{'value': '...', 'expected_behavior': '...', 'justification': '...'}]}"
        }
        
        instruction = instruction_map.get(task_type, "Provide structured JSON output for the following context.")
        prompt = ContextBuilder.format_as_prompt(context, candidates, instruction)
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a deterministic security orchestrator. You output ONLY valid JSON without markdown wrapping."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2
        }

        try:
            logger.info(f"Routing {task_type} to {self.model}...")
            response = requests.post(self.base_url, headers=headers, json=payload, timeout=45.0)
            response.raise_for_status()
            
            data = response.json()
            message = data["choices"][0]["message"]
            
            # DeepSeek specific thinking block extraction
            reasoning = message.get("reasoning_content", "")
            content = message.get("content", "{}").strip()
            
            # Strip markdown if present
            if content.startswith("```json"):
                content = content.replace("```json", "").replace("```", "").strip()
                
            parsed_json = json.loads(content)
            
            return LLMResponse(
                reasoning_trace=reasoning,
                structured_data=parsed_json,
                raw_response=content
            )
            
        except Exception as e:
            logger.error(f"LLM Routing failed for {task_type}: {e}")
            fallback_data = self._fallback_heuristic(task_type, candidates)
            return LLMResponse(
                reasoning_trace="LLM Failed. Fallback executed.",
                structured_data=fallback_data,
                raw_response=json.dumps(fallback_data)
            )

    def parse_llm_response(self, response: LLMResponse, schema: Any) -> Any:
        """Validates the returned data against the strict Pydantic schemas."""
        try:
            return schema(**response.structured_data)
        except Exception as e:
            logger.error(f"Failed to parse LLM structured data into schema: {e}")
            raise ValueError(f"Schema validation failed: {e}")
