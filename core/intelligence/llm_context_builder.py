from core.memory.shared_context_v2 import SharedContextV2
from typing import Dict, Any

class LLMContextBuilder:
    def __init__(self, shared_context: SharedContextV2):
        self.shared_context = shared_context
        
    def build_for_hypothesis_ranking(self, endpoint_id: str, coverage_gaps: list) -> Dict[str, Any]:
        """
        Builds tightly scoped context limited to ~4000 tokens.
        """
        params = {
            "endpoint_id": endpoint_id
        }
        
        # Build base context without memory/tool specifics just for baseline ranking
        context = self.shared_context.build_llm_context("hypothesis_ranking", params)
        context["coverage_gaps"] = coverage_gaps
        
        # Trim list sizes to avoid blowing up context
        context = self._trim_to_tokens(context, 4000)
        
        return context

    def _trim_to_tokens(self, context: dict, max_tokens: int) -> dict:
        """
        Heuristic trim for large lists in context.
        Assuming 1 token ~ 4 chars of JSON string.
        """
        import json
        while len(json.dumps(context)) // 4 > max_tokens:
            trimmed_something = False
            if "coverage_gaps" in context and len(context["coverage_gaps"]) > 10:
                context["coverage_gaps"] = context["coverage_gaps"][:10]
                trimmed_something = True
            elif "relevant_memory" in context and len(context["relevant_memory"]) > 5:
                context["relevant_memory"] = context["relevant_memory"][:5]
                trimmed_something = True
            elif "relevant_experiences" in context and len(context["relevant_experiences"]) > 5:
                context["relevant_experiences"] = context["relevant_experiences"][:5]
                trimmed_something = True
            
            if not trimmed_something:
                break
                
        return context
