from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import json
import logging

logger = logging.getLogger(__name__)

class LLMProvider(ABC):
    """Abstract base class for LLM providers."""
    
    @abstractmethod
    async def generate(self, prompt: str, system_prompt: str = "", 
                      max_tokens: int = 2000, temperature: float = 0.7) -> str:
        """Generate text response."""
        pass
    
    @abstractmethod
    async def generate_json(self, prompt: str, system_prompt: str = "",
                           schema: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate structured JSON response."""
        pass
    
    def parse_json_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse JSON from LLM response."""
        try:
            # Try to extract JSON from response
            if "{" in response and "}" in response:
                start = response.find("{")
                end = response.rfind("}") + 1
                json_str = response[start:end]
                return json.loads(json_str)
        except Exception as e:
            logger.warning(f"Failed to parse JSON from response: {e}")
        
        return None
