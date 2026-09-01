import logging
from typing import Dict, Any, List
from core.memory.shared_context_v2 import SharedContextV2

logger = logging.getLogger(__name__)


class LLMContextBuilder:
    """Acts as the pipeline between Coverage/Knowledge and DeepSeek, assembling context."""

    def __init__(self, shared_context: SharedContextV2):
        self.shared_context = shared_context
        self.sensitive_keys = ["password", "token", "secret", "cookie", "auth"]

    def _redact_secrets(self, data: Any) -> Any:
        """Recursively redact passwords, tokens, cookies, secrets."""
        if isinstance(data, dict):
            redacted = {}
            for k, v in data.items():
                if any(sec in k.lower() for sec in self.sensitive_keys):
                    redacted[k] = "[REDACTED]"
                else:
                    redacted[k] = self._redact_secrets(v)
            return redacted
        elif isinstance(data, list):
            return [self._redact_secrets(item) for item in data]
        return data

    def build_context(self, decision_type: str = "general") -> Dict:
        """
        Builds the comprehensive context object to be sent to DeepSeek.
        Slices context based on decision_type so DeepSeek receives only relevant data.
        """
        full_context = self.shared_context.build_llm_context()
        
        # Redact secrets
        safe_context = self._redact_secrets(full_context)
        
        # Slicing context based on decision type
        sliced_context = {}
        sliced_context["target_profile"] = safe_context["target_profile"]
        sliced_context["execution_mode"] = safe_context["execution_mode"]
        
        if decision_type == "hypothesis_generation":
            sliced_context["observations"] = safe_context["observations"]
            sliced_context["attack_surface"] = safe_context["attack_surface"]
            sliced_context["capabilities"] = safe_context["capabilities"]
        elif decision_type == "strategy_selection":
            sliced_context["experiences"] = safe_context["experiences"]
            sliced_context["successful_strategies"] = safe_context["successful_strategies"]
            sliced_context["failed_strategies"] = safe_context["failed_strategies"]
            sliced_context["pending_tests"] = safe_context["pending_tests"]
        else:
            # Fallback includes more data but is redacted
            sliced_context = safe_context

        logger.info("LLM_CONTEXT_BUILT endpoints=%d identities=%d coverage_gaps=%s",
                    len(self.shared_context.endpoints),
                    len(self.shared_context.identities),
                    len(self.shared_context.coverage_gaps))
                    
        return sliced_context
