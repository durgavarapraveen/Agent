"""
LLM Client - Reads config from .env file
Supports Gemini + Ollama + extensible for other providers
"""

import json
import logging
import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Dict

import httpx

from core.config import get_config

try:
    from groq import Groq as GroqClient
    HAS_GROQ = True
except ImportError:
    HAS_GROQ = False

logger = logging.getLogger(__name__)


class TaskTier(Enum):
    SMALL = "small"
    LARGE = "large"


class LLMProvider(ABC):
    """Base provider interface"""

    @abstractmethod
    async def generate(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                        system: Optional[str] = None, max_tokens: int = 1024,
                        temperature: float = 0.3) -> str:
        pass

    @abstractmethod
    async def generate_json(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                             system: Optional[str] = None, max_tokens: int = 2048) -> Dict:
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        pass


# ═══════════════════════════════════════════════════════════════
# GEMINI PROVIDER
# ═══════════════════════════════════════════════════════════════

class GeminiProvider(LLMProvider):
    """Google Gemini API provider"""

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash-exp"):
        self.api_key = api_key
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY not set in .env")
        self.model = model
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"
        self.timeout = 120

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                url = f"{self.base_url}/{self.model}:generateContent?key={self.api_key}"
                r = await client.post(url, json={"contents": [{"parts": [{"text": "test"}]}]})
                return r.status_code in (200, 400)
        except Exception as e:
            logger.debug(f"Gemini unavailable: {e}")
            return False

    async def generate(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                        system: Optional[str] = None, max_tokens: int = 1024,
                        temperature: float = 0.3) -> str:
        contents = []
        if system:
            contents.append({"parts": [{"text": system}]})
        contents.append({"role": "user", "parts": [{"text": prompt}]})

        payload = {
            "contents": contents,
            "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature}
        }

        url = f"{self.base_url}/{self.model}:generateContent?key={self.api_key}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(url, json=payload)
                if r.status_code == 200:
                    data = r.json()
                    if "candidates" in data and data["candidates"]:
                        parts = data["candidates"][0].get("content", {}).get("parts", [])
                        if parts:
                            return parts[0].get("text", "").strip()
                logger.error(f"Gemini {r.status_code}: {r.text[:200]}")
        except Exception as e:
            logger.error(f"Gemini generate: {e}")
        return ""

    async def generate_json(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                             system: Optional[str] = None, max_tokens: int = 2048) -> Dict:
        json_prompt = f"{prompt}\n\nRespond ONLY with valid JSON."
        text = await self.generate(json_prompt, tier, system, max_tokens, temperature=0.1)
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            m = re.search(r'\{[\s\S]*\}', text)
            if m:
                try:
                    return json.loads(m.group(0))
                except:
                    pass
        return {}


# ═══════════════════════════════════════════════════════════════
# GROQ PROVIDER
# ═══════════════════════════════════════════════════════════════

class GroqProvider(LLMProvider):
    """Groq API provider - FREE, fast models"""

    def __init__(self):
        if not HAS_GROQ:
            raise ImportError("groq package not installed. Install with: pip install groq")
        
        api_key = get_config().get("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY not set in .env")
        
        self.model = get_config().get("GROQ_MODEL", "mixtral-8x7b-32768")
        self.client = GroqClient(api_key=api_key)

    async def generate(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                       system: Optional[str] = None, max_tokens: int = 1024,
                       temperature: float = 0.3) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system or "You are a helpful assistant."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Groq generate error: {e}")
            return ""

    async def generate_json(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                            system: Optional[str] = None, max_tokens: int = 2048) -> Dict:
        json_prompt = f"{prompt}\n\nRespond ONLY with valid JSON. No markdown backticks."
        json_system = (system or "") + "\n\nRespond ONLY with valid JSON."
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": json_system},
                    {"role": "user", "content": json_prompt}
                ],
                max_tokens=max_tokens,
                temperature=0.1,
            )
            text = response.choices[0].message.content
            
            # Remove markdown code blocks
            text = re.sub(r'```json\n?|\n?```', '', text)
            text = text.strip()
            
            if not text:
                return {}
            
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                m = re.search(r'\{[\s\S]*\}', text)
                if m:
                    try:
                        return json.loads(m.group(0))
                    except:
                        pass
            return {}
        except Exception as e:
            logger.error(f"Groq generate_json error: {e}")
            return {}

    async def is_available(self) -> bool:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=10,
            )
            return response.choices[0].message.content != ""
        except:
            return False


# ═══════════════════════════════════════════════════════════════
# OLLAMA PROVIDER
# ═══════════════════════════════════════════════════════════════

class OllamaProvider(LLMProvider):
    """Ollama local LLM provider"""

    def __init__(self, base_url: str = "http://localhost:11434",
                 small_model: str = "qwen3:8b", large_model: str = "qwen3:8b"):
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
        except:
            return False

    async def generate(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                        system: Optional[str] = None, max_tokens: int = 1024,
                        temperature: float = 0.3) -> str:
        model = self._model_for(tier)
        payload = {
            "model": model, "prompt": prompt, "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens}
        }
        if system:
            payload["system"] = system
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(f"{self.base_url}/api/generate", json=payload)
                if r.status_code == 200:
                    return r.json().get("response", "").strip()
                logger.error(f"Ollama {r.status_code}: {r.text[:200]}")
        except Exception as e:
            logger.error(f"Ollama generate: {e}")
        return ""

    async def generate_json(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                             system: Optional[str] = None, max_tokens: int = 2048) -> Dict:
        model = self._model_for(tier)
        payload = {
            "model": model, "prompt": prompt, "stream": False, "format": "json",
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
                        m = re.search(r'\{[\s\S]*\}', text)
                        if m:
                            try:
                                return json.loads(m.group(0))
                            except:
                                pass
        except Exception as e:
            logger.error(f"Ollama generate_json: {e}")
        return {}


class NullProvider(LLMProvider):
    """Fallback provider when nothing works"""
    async def generate(self, *args, **kwargs) -> str:
        return ""
    async def generate_json(self, *args, **kwargs) -> Dict:
        return {}
    async def is_available(self) -> bool:
        return False


# ═══════════════════════════════════════════════════════════════
# CLIENT
# ═══════════════════════════════════════════════════════════════

class LLMClient:
    """Main client - loads provider from .env"""

    _instance: Optional[LLMProvider] = None

    @classmethod
    def get(cls) -> LLMProvider:
        if cls._instance is None:
            cls._instance = cls._create_from_config()
        return cls._instance

    @classmethod
    def set_provider(cls, provider: LLMProvider):
        cls._instance = provider

    @classmethod
    def _create_from_config(cls) -> LLMProvider:
        """
        Read from .env:
          LLM_PROVIDER=gemini|ollama|other

        For Gemini:
          GOOGLE_API_KEY=...
          GEMINI_MODEL=gemini-2.0-flash-exp

        For Ollama:
          OLLAMA_BASE_URL=http://localhost:11434
          OLLAMA_SMALL_MODEL=qwen3:8b
          OLLAMA_LARGE_MODEL=qwen3:8b
        """
        config = get_config()
        provider_name = config.get("LLM_PROVIDER", "ollama").lower()

        logger.info(f"LLM_PROVIDER from .env: {provider_name}")

        if provider_name == "groq":
            try:
                model = config.get("GROQ_MODEL", "mixtral-8x7b-32768")
                logger.info(f"Using Groq provider (model: {model})")
                return GroqProvider()
            except (ValueError, ImportError) as e:
                logger.error(f"Groq init failed: {e}")
                logger.info("Falling back to NullProvider")
                return NullProvider()

        elif provider_name == "gemini":
            try:
                api_key = config.get("GOOGLE_API_KEY")
                model = config.get("GEMINI_MODEL", "gemini-2.0-flash-exp")
                logger.info(f"Using Gemini provider (model: {model})")
                return GeminiProvider(api_key, model)
            except ValueError as e:
                logger.error(f"Gemini init failed: {e}")
                logger.info("Falling back to NullProvider")
                return NullProvider()

        elif provider_name == "ollama":
            base_url = config.get("OLLAMA_BASE_URL", "http://localhost:11434")
            small_model = config.get("OLLAMA_SMALL_MODEL", "qwen3:8b")
            large_model = config.get("OLLAMA_LARGE_MODEL", "qwen3:8b")
            logger.info(f"Using Ollama provider ({small_model})")
            return OllamaProvider(base_url, small_model, large_model)
        
        elif provider_name == "bridge":
            try:
                from agents.llm_client_bridge import ClaudeBridgeProvider
                bridge_url = config.get("BRIDGE_URL", "http://localhost:8000")
                bridge_model = config.get("BRIDGE_MODEL", "sonnet")
                logger.info(f"Using Claude Bridge provider: {bridge_url} ({bridge_model})")
                return ClaudeBridgeProvider(bridge_url, bridge_model)
            except (ImportError, ValueError) as e:
                logger.error(f"Bridge init failed: {e}")
                logger.info("Falling back to NullProvider")
                return NullProvider()

        else:
            logger.warning(f"Unknown provider: {provider_name}")
            logger.info("Falling back to NullProvider")
            return NullProvider()


# Convenience functions
async def llm_extract(text: str, instruction: str, tier: TaskTier = TaskTier.SMALL) -> Dict:
    client = LLMClient.get()
    prompt = f"{instruction}\n\nInput:\n{text[:6000]}\n\nJSON only."
    return await client.generate_json(prompt, tier=tier)


async def llm_analyze(text: str, question: str, tier: TaskTier = TaskTier.LARGE) -> str:
    client = LLMClient.get()
    return await client.generate(f"{question}\n\n{text[:8000]}", tier=tier, max_tokens=2048)