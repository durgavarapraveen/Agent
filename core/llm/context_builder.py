from typing import Dict, Any, List
import json
from core.domain.endpoint import Endpoint

class ContextBuilder:
    @staticmethod
    def build_for_hypothesis_ranking(endpoint: Endpoint, coverage_gaps: List[str], history: List[str]) -> Dict[str, Any]:
        return {
            "endpoint": {
                "id": endpoint.endpoint_id,
                "url": endpoint.url,
                "methods": list(endpoint.method_set)
            },
            "coverage_gaps": coverage_gaps,
            "history": history
        }

    @staticmethod
    def build_for_payload_generation(endpoint: Endpoint, parameter: str, attack_type: str) -> Dict[str, Any]:
        return {
            "endpoint": {
                "id": endpoint.endpoint_id,
                "url": endpoint.url,
                "methods": list(endpoint.method_set)
            },
            "parameter_targeted": parameter,
            "attack_type": attack_type
        }

    @staticmethod
    def format_as_prompt(context: Dict[str, Any], candidates: List[Any], task_instruction: str) -> str:
        prompt = f"Task: {task_instruction}\n\nContext:\n{json.dumps(context, indent=2)}\n\nCandidates to evaluate:\n"
        for idx, c in enumerate(candidates):
            prompt += f"[{idx}] {c}\n"
            
        prompt += "\nPlease output strict JSON wrapping your response. Do not use markdown backticks in your final output, just raw JSON."
        return prompt
