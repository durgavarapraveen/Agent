import aiohttp
import json
import logging
from typing import Dict, Any, Optional

from llm.base import LLMProvider

logger = logging.getLogger(__name__)

class OllamaProvider(LLMProvider):
    """Ollama local LLM provider."""
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "neural-chat"):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.generate_url = f"{self.base_url}/api/generate"
        self.embedding_url = f"{self.base_url}/api/embeddings"
    
    async def _check_connection(self) -> bool:
        """Check if Ollama is available."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/api/tags", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    return resp.status == 200
        except:
            return False
    
    async def generate(self, prompt: str, system_prompt: str = "",
                      max_tokens: int = 2000, temperature: float = 0.7) -> str:
        """Generate text using Ollama."""
        try:
            full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
            
            payload = {
                "model": self.model,
                "prompt": full_prompt,
                "stream": False,
                "temperature": temperature,
                "num_predict": max_tokens
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.generate_url, json=payload,
                                       timeout=aiohttp.ClientTimeout(total=120)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("response", "")
                    else:
                        logger.error(f"Ollama error: {resp.status}")
                        return ""
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            return ""
    
    async def generate_json(self, prompt: str, system_prompt: str = "",
                           schema: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate JSON response from Ollama."""
        json_prompt = f"{prompt}\n\nRespond ONLY with valid JSON, no other text."
        
        response = await self.generate(
            json_prompt,
            system_prompt=system_prompt,
            temperature=0.1  # Lower temperature for structured output
        )
        
        parsed = self.parse_json_response(response)
        return parsed or {"error": "Failed to parse JSON"}
    
    async def get_embeddings(self, text: str) -> Optional[list]:
        """Get embeddings for text."""
        try:
            payload = {
                "model": self.model,
                "prompt": text
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.embedding_url, json=payload,
                                       timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("embedding")
        except Exception as e:
            logger.error(f"Embedding generation failed: {e}")
        
        return None

class MockLLMProvider(LLMProvider):
    """Mock LLM provider for testing."""
    
    def __init__(self):
        self.call_count = 0
    
    async def generate(self, prompt: str, system_prompt: str = "",
                      max_tokens: int = 2000, temperature: float = 0.7) -> str:
        self.call_count += 1
        
        if "agent" in prompt.lower() and "create" in prompt.lower():
            return "The reconnaissance phase requires creating a recon agent."
        elif "decision" in prompt.lower():
            return '{"decision_type": "CREATE_TASK", "reason": "Discovered new capability"}'
        else:
            return "Mock response to prompt"
    
    async def generate_json(self, prompt: str, system_prompt: str = "",
                           schema: Dict[str, Any] = None) -> Dict[str, Any]:
        self.call_count += 1
        
        return {
            "decision_type": "CREATE_TASK",
            "reason": "Mock decision",
            "tasks": []
        }
