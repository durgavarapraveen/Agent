"""
LLM Client - Reads config from .env file
Supports Gemini + Ollama + extensible for other providers
"""

import asyncio
import json
import logging
import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Dict, Any, List, Tuple

import httpx

from core.common.schemas import NormalizedLLMResponse



logger = logging.getLogger(__name__)


def validate_json_payload(data: Any, mandatory_fields: Optional[List[str]] = None) -> bool:
    """
    Strict validation check for LLM JSON responses.
    Treats None, non-dict objects, empty dicts ({}), or dicts missing mandatory fields as invalid.
    """
    if not data or not isinstance(data, dict) or len(data) == 0:
        return False
    if mandatory_fields:
        for field in mandatory_fields:
            if field not in data or data[field] is None:
                return False
    return True


from core.common.schemas import TaskTier  # canonical enum

from agents.llm_harness_adapter import get_llm, initialize_llm
HarnessTaskTier = TaskTier  # backward compat alias

class LLMProvider(ABC):
    """Base provider interface (Deprecated - routing to Universal Harness)"""

    async def generate_response(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                                system: Optional[str] = None, max_tokens: int = 1024,
                                temperature: float = 0.3, response_format: Optional[str] = None) -> NormalizedLLMResponse:
        
        harness = get_llm()
        if not harness:
            # Emergency fallback if not initialized
            await initialize_llm()
            harness = get_llm()

        harness_tier = HarnessTaskTier.SMALL if tier == TaskTier.SMALL else HarnessTaskTier.LARGE
        
        # If the format is JSON, force JSON generation
        if response_format == "json":
            json_out = await harness.generate_json(prompt, system, max_tokens, tier=harness_tier)
            if isinstance(json_out, list):
                json_out = {"agents": json_out}
            elif not isinstance(json_out, dict):
                json_out = {}
            return NormalizedLLMResponse(
                content=json.dumps(json_out),
                structured_output=json_out,
                provider=harness.active_provider.provider_type.value if harness.active_provider else "unknown",
                model=harness.active_provider.get_model_for_tier(harness_tier) if harness.active_provider else "unknown"
            )
            
        text_out = await harness.generate_text(prompt, system, max_tokens, tier=harness_tier)
        return NormalizedLLMResponse(
            content=text_out,
            structured_output=None,
            provider=harness.active_provider.provider_type.value if harness.active_provider else "unknown",
            model=harness.active_provider.get_model_for_tier(harness_tier) if harness.active_provider else "unknown"
        )



    async def generate(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                        system: Optional[str] = None, max_tokens: int = 1024,
                        temperature: float = 0.3) -> str:
        res = await self.generate_response(prompt, tier, system, max_tokens, temperature)
        return res.content

    async def generate_json(self, prompt: str, tier: TaskTier = TaskTier.SMALL,
                             system: Optional[str] = None, max_tokens: int = 2048,
                             mandatory_fields: Optional[List[str]] = None) -> Dict:
        res = await self.generate_response(prompt, tier, system, max_tokens, temperature=0.1, response_format="json")
        raw_content = res.content
        structured = res.structured_output

        if structured is None and raw_content:
            try:
                clean_content = re.sub(r'```json\n?|\n?```', '', raw_content).strip()
                structured = json.loads(clean_content)
            except Exception:
                m = re.search(r'\{[\s\S]*\}', raw_content)
                if m:
                    try:
                        structured = json.loads(m.group(0))
                    except Exception:
                        pass

        if not validate_json_payload(structured, mandatory_fields):
            logger.warning(
                f"[LLMClient] Invalid/empty JSON response received from provider '{res.provider}'. "
                f"Raw response: '{raw_content}'"
            )
            return {}

        return structured

    async def generate_json_with_retry(
        self,
        prompt: str,
        tier: TaskTier = TaskTier.SMALL,
        system: Optional[str] = None,
        max_tokens: int = 2048,
        mandatory_fields: Optional[List[str]] = None,
        max_retries: int = 3,
        initial_backoff: float = 0.5
    ) -> Tuple[Dict, str]:
        """
        Generates JSON response with strict validation, exponential backoff retries,
        and diagnostic logging of raw responses on empty/invalid outputs.
        Returns tuple of (structured_dict, raw_content).
        """
        raw_content = ""
        for attempt in range(max_retries):
            res = await self.generate_response(prompt, tier, system, max_tokens, temperature=0.1, response_format="json")
            raw_content = res.content
            structured = res.structured_output

            if structured is None and raw_content:
                try:
                    clean_content = re.sub(r'```json\n?|\n?```', '', raw_content).strip()
                    structured = json.loads(clean_content)
                except Exception:
                    m = re.search(r'\{[\s\S]*\}', raw_content)
                    if m:
                        try:
                            structured = json.loads(m.group(0))
                        except Exception:
                            pass

            if validate_json_payload(structured, mandatory_fields):
                return structured, raw_content

            logger.warning(
                f"[LLMClient] Attempt {attempt + 1}/{max_retries} failed: "
                f"empty {{}} or malformed JSON received from provider '{res.provider}'. "
                f"Raw response: '{raw_content}'"
            )

            if attempt < max_retries - 1:
                backoff = initial_backoff * (2 ** attempt)
                await asyncio.sleep(backoff)

        return {}, raw_content

    @abstractmethod
    async def is_available(self) -> bool:
        pass



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
                                except (json.JSONDecodeError, ValueError):
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
# CLIENT
# ═══════════════════════════════════════════════════════════════

class LLMClient:
    """Main client - now acts as a proxy to universal_llm_harness"""

    _instance: Optional[LLMProvider] = None

    @classmethod
    def get(cls) -> LLMProvider:
        if cls._instance is None:
            # We return an anonymous subclass of LLMProvider that just acts as the router
            class HarnessProxyProvider(LLMProvider):
                async def is_available(self) -> bool:
                    harness = get_llm()
                    if not harness:
                        await initialize_llm()
                        harness = get_llm()
                    return harness is not None and harness.active_provider is not None
            cls._instance = HarnessProxyProvider()
        return cls._instance

    @classmethod
    def set_provider(cls, provider: LLMProvider):
        cls._instance = provider

    @classmethod
    def _create_from_config(cls) -> LLMProvider:
        # No longer used since we proxy to harness
        pass


# Convenience functions
async def llm_extract(text: str, instruction: str, tier: TaskTier = TaskTier.SMALL) -> Dict:
    client = LLMClient.get()
    prompt = f"{instruction}\n\nInput:\n{text[:6000]}\n\nJSON only."
    return await client.generate_json(prompt, tier=tier)


async def llm_analyze(text: str, question: str, tier: TaskTier = TaskTier.LARGE) -> str:
    client = LLMClient.get()
    return await client.generate(f"{question}\n\n{text[:8000]}", tier=tier, max_tokens=2048)
