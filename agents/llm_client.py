"""
LLM Client - Reads config from .env file
Supports Gemini + Ollama + extensible for other providers
"""

import json
import logging
import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Dict, Any

import httpx

from core.config import get_config
from core.schemas import NormalizedLLMResponse

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
    async def generate_response(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                                system: Optional[str] = None, max_tokens: int = 1024,
                                temperature: float = 0.3, response_format: Optional[str] = None) -> NormalizedLLMResponse:
        pass

    async def generate(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                        system: Optional[str] = None, max_tokens: int = 1024,
                        temperature: float = 0.3) -> str:
        res = await self.generate_response(prompt, tier, system, max_tokens, temperature)
        return res.content

    async def generate_json(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                             system: Optional[str] = None, max_tokens: int = 2048) -> Dict:
        res = await self.generate_response(prompt, tier, system, max_tokens, temperature=0.1, response_format="json")
        return res.structured_output or {}

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

    async def generate_response(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                                system: Optional[str] = None, max_tokens: int = 1024,
                                temperature: float = 0.3, response_format: Optional[str] = None) -> NormalizedLLMResponse:
        contents = []
        if system:
            contents.append({"parts": [{"text": system}]})
        contents.append({"role": "user", "parts": [{"text": prompt}]})

        payload = {
            "contents": contents,
            "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature}
        }
        if response_format == "json":
            payload["generationConfig"]["responseMimeType"] = "application/json"

        url = f"{self.base_url}/{self.model}:generateContent?key={self.api_key}"
        content = ""
        structured = None
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(url, json=payload)
                if r.status_code == 200:
                    data = r.json()
                    if "candidates" in data and data["candidates"]:
                        candidate = data["candidates"][0]
                        parts = candidate.get("content", {}).get("parts", [])
                        if parts:
                            content = parts[0].get("text", "").strip()
                            finish_reason = candidate.get("finishReason")
                            if response_format == "json" or content.startswith("{") or content.startswith("["):
                                try:
                                    structured = json.loads(content)
                                except Exception:
                                    # Fallback regex
                                    m = re.search(r'\{[\s\S]*\}', content)
                                    if m:
                                        try:
                                            structured = json.loads(m.group(0))
                                        except:
                                            pass
                            return NormalizedLLMResponse(
                                content=content,
                                structured_output=structured,
                                finish_reason=finish_reason,
                                provider="gemini",
                                model=self.model,
                            )
                logger.error(f"Gemini {r.status_code}: {r.text[:200]}")
        except Exception as e:
            logger.error(f"Gemini generate_response: {e}")
            
        return NormalizedLLMResponse(content="", provider="gemini", model=self.model)


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

    async def generate_response(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                                system: Optional[str] = None, max_tokens: int = 1024,
                                temperature: float = 0.3, response_format: Optional[str] = None) -> NormalizedLLMResponse:
        try:
            kwargs = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system or "You are a helpful assistant."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
            if response_format == "json":
                kwargs["response_format"] = {"type": "json_object"}
                
            response = self.client.chat.completions.create(**kwargs)
            content = response.choices[0].message.content or ""
            # Clean markdown code blocks
            clean_content = re.sub(r'```json\n?|\n?```', '', content).strip()
            
            structured = None
            if response_format == "json" or clean_content.startswith("{") or clean_content.startswith("["):
                try:
                    structured = json.loads(clean_content)
                except Exception:
                    m = re.search(r'\{[\s\S]*\}', clean_content)
                    if m:
                        try:
                            structured = json.loads(m.group(0))
                        except:
                            pass
                            
            return NormalizedLLMResponse(
                content=clean_content,
                structured_output=structured,
                finish_reason=response.choices[0].finish_reason,
                provider="groq",
                model=self.model,
                usage={"completion_tokens": response.usage.completion_tokens, "prompt_tokens": response.usage.prompt_tokens} if hasattr(response, "usage") and response.usage else None
            )
        except Exception as e:
            logger.error(f"Groq generate_response error: {e}")
            return NormalizedLLMResponse(content="", provider="groq", model=self.model)

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
# DEEPSEEK PROVIDER
# ═══════════════════════════════════════════════════════════════

class DeepSeekProvider(LLMProvider):
    """DeepSeek API provider - OpenAI-compatible chat completions."""

    def __init__(self, api_key: str, small_model: str = "deepseek-v4-flash",
                 large_model: str = "deepseek-v4-flash",
                 base_url: str = "https://api.deepseek.com"):
        self.api_key = api_key
        if not self.api_key:
            raise ValueError("DEEPSEEK_API_KEY not set in .env")
        self.small_model = small_model
        self.large_model = large_model
        self.base_url = base_url.rstrip("/")
        self.timeout = 120

    def _model_for(self, tier: TaskTier) -> str:
        return self.small_model if tier == TaskTier.SMALL else self.large_model

    def _headers(self) -> Dict:
        return {"Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"}

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    f"{self.base_url}/chat/completions", headers=self._headers(),
                    json={"model": self.small_model,
                          "messages": [{"role": "user", "content": "test"}],
                          "max_tokens": 1})
                return r.status_code == 200
        except Exception as e:
            logger.debug(f"DeepSeek unavailable: {e}")
            return False

    async def generate_response(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                                system: Optional[str] = None, max_tokens: int = 1024,
                                temperature: float = 0.3, response_format: Optional[str] = None) -> NormalizedLLMResponse:
        messages = []
        messages.append({"role": "system", "content": system or "You are a helpful assistant."})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self._model_for(tier), 
            "messages": messages,
            "max_tokens": max_tokens, 
            "temperature": temperature,
            "stream": False
        }
        if response_format == "json":
            payload["response_format"] = {"type": "json_object"}
            
        model_name = self._model_for(tier)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(f"{self.base_url}/chat/completions",
                                      headers=self._headers(), json=payload)
                if r.status_code == 200:
                    data = r.json()
                    choice = data["choices"][0]
                    message = choice.get("message", {})
                    
                    content = message.get("content") or ""
                    reasoning_content = message.get("reasoning_content") or ""
                    
                    # Core fix: DeepSeek Empty Content Bug
                    if not content and reasoning_content:
                        content = reasoning_content
                        
                    clean_content = re.sub(r'```json\n?|\n?```', '', content).strip()
                    
                    structured = None
                    if response_format == "json" or clean_content.startswith("{") or clean_content.startswith("["):
                        try:
                            structured = json.loads(clean_content)
                        except Exception:
                            m = re.search(r'\{[\s\S]*\}', clean_content)
                            if m:
                                try:
                                    structured = json.loads(m.group(0))
                                except:
                                    pass
                                    
                    return NormalizedLLMResponse(
                        content=clean_content,
                        structured_output=structured,
                        finish_reason=choice.get("finish_reason"),
                        provider="deepseek",
                        model=model_name,
                        usage=data.get("usage")
                    )
                else:
                    logger.error(f"DeepSeek error {r.status_code}: {r.text[:500]}")
        except Exception as e:
            logger.error(f"DeepSeek generate_response exception: {e}")
            
        return NormalizedLLMResponse(content="", provider="deepseek", model=model_name)


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

    async def generate_response(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                                system: Optional[str] = None, max_tokens: int = 1024,
                                temperature: float = 0.3, response_format: Optional[str] = None) -> NormalizedLLMResponse:
        model = self._model_for(tier)
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system or "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens}
        }
        if response_format == "json":
            payload["format"] = "json"
            
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(f"{self.base_url}/api/chat", json=payload)
                if r.status_code == 200:
                    data = r.json()
                    message = data.get("message", {})
                    content = message.get("content", "").strip()
                    
                    clean_content = re.sub(r'```json\n?|\n?```', '', content).strip()
                    
                    structured = None
                    if response_format == "json" or clean_content.startswith("{") or clean_content.startswith("["):
                        try:
                            structured = json.loads(clean_content)
                        except Exception:
                            m = re.search(r'\{[\s\S]*\}', clean_content)
                            if m:
                                try:
                                    structured = json.loads(m.group(0))
                                except:
                                    pass
                                    
                    return NormalizedLLMResponse(
                        content=clean_content,
                        structured_output=structured,
                        provider="ollama",
                        model=model,
                    )
                else:
                    logger.error(f"Ollama error {r.status_code}: {r.text[:200]}")
        except Exception as e:
            logger.error(f"Ollama generate_response exception: {e}")
            
        return NormalizedLLMResponse(content="", provider="ollama", model=model)


class NullProvider(LLMProvider):
    """Fallback provider when nothing works"""
    async def generate_response(self, *args, **kwargs) -> NormalizedLLMResponse:
        return NormalizedLLMResponse(content="", provider="null", model="null")
        
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

        elif provider_name == "deepseek":
            try:
                api_key = config.get("DEEPSEEK_API_KEY")
                small = config.get("DEEPSEEK_SMALL_MODEL", "deepseek-chat")
                large = config.get("DEEPSEEK_LARGE_MODEL", "deepseek-chat")
                base = config.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
                logger.info(f"Using DeepSeek provider ({small}/{large})")
                return DeepSeekProvider(api_key, small, large, base)
            except ValueError as e:
                logger.error(f"DeepSeek init failed: {e}")
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