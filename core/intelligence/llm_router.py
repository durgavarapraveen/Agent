import logging

logger = logging.getLogger(__name__)

class LLMRouter:
    def __init__(self):
        pass
        
    def route_classification(self, task: str, context: dict) -> str:
        """Use DeepSeek Flash for quick classification tasks"""
        self._log_routing("classification", "flash", context)
        return "deepseek-flash"
        
    def route_hypothesis_ranking(self, task: str, context: dict) -> str:
        """Use DeepSeek Thinking for complex hypothesis ranking"""
        self._log_routing("hypothesis_ranking", "thinking", context)
        return "deepseek-thinking"
        
    def route_deep_reasoning(self, task: str, context: dict) -> str:
        """Use a stronger model for intense reasoning paths"""
        self._log_routing("deep_reasoning", "stronger", context)
        return "deepseek-stronger"
        
    def route_summarization(self, task: str, context: dict) -> str:
        """Use DeepSeek Flash for summarization"""
        self._log_routing("summarization", "flash", context)
        return "deepseek-flash"
        
    def _log_routing(self, purpose: str, model: str, context: dict):
        import json
        context_size = len(json.dumps(context)) // 4
        logger.info(f"DEEPSEEK_REQUEST purpose={purpose} model_routing={model} context_size={context_size}_tokens")
        print(f"DEEPSEEK_REQUEST purpose={purpose} model_routing={model} context_size={context_size}_tokens")
