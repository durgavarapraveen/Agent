
import asyncio
import json
import logging
import os
import re
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Tuple

import httpx

from core.common.schemas import NormalizedLLMResponse



logger = logging.getLogger(__name__)


def validate_json_payload(data: Any, mandatory_fields: Optional[List[str]] = None) -> bool:
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

    def supports_native_tools(self) -> bool:
        # Delegate to the harness/provider. Without this method the proxy raised
        # AttributeError in central_brain's _run_phase native-tools check, which
        # was swallowed as False — so the native agentic tool loop was NEVER used
        # even for a tool-capable provider (the JSON-planner path ran instead).
        try:
            harness = get_llm()
            return bool(harness and harness.supports_native_tools())
        except Exception:
            return False

    async def generate_with_tools(self, messages, tools, tool_executor=None,
                                  max_rounds: int = 10, max_tokens: int = 4096,
                                  tier: TaskTier = TaskTier.SMALL):
        harness = get_llm()
        if not harness:
            await initialize_llm()
            harness = get_llm()
        harness_tier = HarnessTaskTier.SMALL if tier == TaskTier.SMALL else HarnessTaskTier.LARGE
        return await harness.generate_with_tools(
            messages=messages, tools=tools, tool_executor=tool_executor,
            max_rounds=max_rounds, max_tokens=max_tokens, tier=harness_tier)

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
# CLIENT
# ═══════════════════════════════════════════════════════════════

class LLMClient:

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
    # Mechanical extraction — no RAG analysis/recommendations prefix (see harness).
    from agents.universal_llm_harness import rag_disabled
    with rag_disabled():
        return await client.generate_json(prompt, tier=tier)


async def llm_analyze(text: str, question: str, tier: TaskTier = TaskTier.LARGE) -> str:
    client = LLMClient.get()
    return await client.generate(f"{question}\n\n{text[:8000]}", tier=tier, max_tokens=2048)
