"""
LLM Client - Pluggable interface for local/remote LLMs
Supports Ollama by default. Easy to swap providers.

Task tiers:
  SMALL: quick classification, extraction, summarization (fast model)
  LARGE: reasoning, analysis, report generation (bigger model)
"""

import json
import logging
import os
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Dict, List

import httpx

logger = logging.getLogger(__name__)


class TaskTier(Enum):
    SMALL = "small"   # fast, cheap - extraction/classification
    LARGE = "large"   # slower, better - reasoning/analysis


class LLMProvider(ABC):
    """Base interface. Implement this to add new providers."""

    @abstractmethod
    async def generate(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                        system: Optional[str] = None, max_tokens: int = 1024,
                        temperature: float = 0.3) -> str:
        """Generate text completion. Returns raw string."""
        pass

    @abstractmethod
    async def generate_json(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                             system: Optional[str] = None, max_tokens: int = 2048) -> Dict:
        """Generate JSON response. Returns dict."""
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if provider is reachable."""
        pass


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider"""

    def __init__(self,
                 base_url: str = "http://localhost:11434",
                 small_model: str = "qwen3:8b",
                 large_model: str = "qwen3:8b"):
        self.base_url = base_url.rstrip("/")
        self.small_model = small_model
        self.large_model = large_model
        self.timeout = 120

    def _model_for(self, tier: TaskTier) -> str:
        return self.small_model if tier == TaskTier.SMALL else self.large_model

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self.base_url}/api/tags")
                return r.status_code == 200
        except Exception as e:
            logger.debug(f"Ollama not available: {e}")
            return False

    async def list_models(self) -> List[str]:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self.base_url}/api/tags")
                if r.status_code == 200:
                    return [m["name"] for m in r.json().get("models", [])]
        except:
            pass
        return []

    async def generate(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                        system: Optional[str] = None, max_tokens: int = 1024,
                        temperature: float = 0.3) -> str:
        model = self._model_for(tier)
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens}
        }
        if system:
            payload["system"] = system

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(f"{self.base_url}/api/generate", json=payload)
                if r.status_code == 200:
                    return r.json().get("response", "").strip()
                logger.error(f"Ollama error {r.status_code}: {r.text[:200]}")
        except Exception as e:
            logger.error(f"Ollama generate failed: {e}")
        return ""

    async def generate_json(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                             system: Optional[str] = None, max_tokens: int = 2048) -> Dict:
        model = self._model_for(tier)
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1, "num_predict": max_tokens}
        }
        if system:
            payload["system"] = system

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(f"{self.base_url}/api/generate", json=payload)
                if r.status_code == 200:
                    text = r.json().get("response", "").strip()
                    try:
                        return json.loads(text)
                    except json.JSONDecodeError:
                        # Try to extract JSON from response
                        import re
                        m = re.search(r'\{[\s\S]*\}', text)
                        if m:
                            try:
                                return json.loads(m.group(0))
                            except:
                                pass
                        logger.warning(f"Ollama returned non-JSON: {text[:200]}")
        except Exception as e:
            logger.error(f"Ollama generate_json failed: {e}")
        return {}


class NullProvider(LLMProvider):
    """No-op provider when no LLM is available"""

    async def generate(self, *args, **kwargs) -> str:
        return ""

    async def generate_json(self, *args, **kwargs) -> Dict:
        return {}

    async def is_available(self) -> bool:
        return False


# Registry - add new providers here
_PROVIDERS = {
    "ollama": OllamaProvider,
    "null": NullProvider,
}


class LLMClient:
    """Singleton client - use LLMClient.get() to access."""

    _instance: Optional[LLMProvider] = None
    _initialized: bool = False

    @classmethod
    def get(cls) -> LLMProvider:
        if cls._instance is None:
            cls._instance = cls._create_from_env()
        return cls._instance

    @classmethod
    def set_provider(cls, provider: LLMProvider):
        """Manually set provider (for testing/swapping)"""
        cls._instance = provider

    @classmethod
    def _create_from_env(cls) -> LLMProvider:
        """
        Read config from environment variables:
          LLM_PROVIDER=ollama (default)
          LLM_BASE_URL=http://localhost:11434
          LLM_SMALL_MODEL=llama3.2:3b
          LLM_LARGE_MODEL=llama3.1:8b

        To swap providers later, just change LLM_PROVIDER env var
        or call LLMClient.set_provider(YourProvider(...))
        """
        provider_name = os.getenv("LLM_PROVIDER", "ollama").lower()

        if provider_name == "ollama":
            return OllamaProvider(
                base_url=os.getenv("LLM_BASE_URL", "http://localhost:11434"),
                small_model=os.getenv("LLM_SMALL_MODEL", "qwen3:8b"),
                large_model=os.getenv("LLM_LARGE_MODEL", "qwen3:8b"),
            )
        elif provider_name in _PROVIDERS:
            return _PROVIDERS[provider_name]()
        else:
            logger.warning(f"Unknown provider {provider_name}, using null")
            return NullProvider()


# Convenience functions
async def llm_extract(text: str, instruction: str, tier: TaskTier = TaskTier.SMALL) -> Dict:
    """Small task: extract structured data from text"""
    client = LLMClient.get()
    prompt = f"{instruction}\n\nInput:\n{text[:6000]}\n\nRespond with valid JSON only."
    return await client.generate_json(prompt, tier=tier)


async def llm_analyze(text: str, question: str, tier: TaskTier = TaskTier.LARGE) -> str:
    """Larger task: reason about content"""
    client = LLMClient.get()
    return await client.generate(f"{question}\n\nContext:\n{text[:8000]}", tier=tier, max_tokens=2048)