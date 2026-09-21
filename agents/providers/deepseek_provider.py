"""DeepSeek provider — OpenAI-compatible chat/completions API.

Models: `deepseek-chat` (V3, fast, supports JSON mode) and `deepseek-reasoner`
(R1, chain-of-thought; no JSON-mode / function-calling). Selected from Settings
(LLM_PROVIDER=deepseek); key + models come from env / config:

  DEEPSEEK_API_KEY        required
  DEEPSEEK_BASE_URL       default https://api.deepseek.com
  DEEPSEEK_SMALL_MODEL    default deepseek-chat   (classification / SMALL tier)
  DEEPSEEK_LARGE_MODEL    default deepseek-chat   (reasoning / LARGE tier)

Native tool-calling is reported False so the engine drives DeepSeek through the
provider-agnostic JSON-planner path (works for any JSON-emitting model).
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

import httpx

from agents.universal_llm_harness import (LLMProvider, LLMResponse, ProviderType,
                                          UsageMetrics)
from core.common.schemas import TaskTier

logger = logging.getLogger(__name__)

_REASONER_HINT = "reasoner"  # models that don't support json_object / tools


class DeepSeekProvider(LLMProvider):

    def __init__(self, small_model: str, large_model: str, api_key: str = "",
                 base_url: str = "", budget=None):
        super().__init__(ProviderType.DEEPSEEK, budget)
        self.small_model = small_model or "deepseek-chat"
        self.large_model = large_model or "deepseek-chat"
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY", "")
        self.base_url = (base_url or os.getenv("DEEPSEEK_BASE_URL",
                                               "https://api.deepseek.com")).rstrip("/")
        self.timeout = 180

    async def is_available(self) -> bool:
        # Key present = usable; we don't spend a request just to health-check.
        if not self.api_key:
            logger.warning("[DeepSeek] DEEPSEEK_API_KEY not set — provider unavailable")
            return False
        return True

    def get_small_model(self) -> str:
        return self.small_model

    def get_large_model(self) -> str:
        return self.large_model

    def supports_native_tools(self) -> bool:
        # Route DeepSeek through the JSON-planner path (provider-agnostic).
        return False

    async def generate_response(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.3,
        response_format: Optional[str] = None,
        tier: TaskTier = TaskTier.SMALL,
    ) -> LLMResponse:
        model = self.get_model_for_tier(tier)
        is_reasoner = _REASONER_HINT in model.lower()
        want_json = response_format == "json"

        messages: List[Dict[str, str]] = []
        sys_txt = system or ""
        if want_json:
            # DeepSeek json_object mode requires the word "json" in the context.
            sys_txt = (sys_txt + "\nRespond ONLY with a valid JSON object.").strip()
        if sys_txt:
            messages.append({"role": "system", "content": sys_txt})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }
        # reasoner supports neither json_object mode nor temperature tuning.
        if want_json and not is_reasoner:
            payload["response_format"] = {"type": "json_object"}
        if is_reasoner:
            payload.pop("temperature", None)

        headers = {"Authorization": f"Bearer {self.api_key}",
                   "Content-Type": "application/json"}
        t0 = time.time()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(f"{self.base_url}/chat/completions",
                                      headers=headers, json=payload)
            latency = (time.time() - t0) * 1000.0
            if r.status_code != 200:
                err = f"HTTP {r.status_code}: {r.text[:200]}"
                logger.error("[DeepSeek] request failed: %s", err)
                return LLMResponse(content="", provider="deepseek", model=model,
                                   error=err, latency_ms=latency)
            data = r.json()
        except Exception as e:
            logger.error("[DeepSeek] request error: %s", e)
            return LLMResponse(content="", provider="deepseek", model=model,
                               error=str(e), latency_ms=(time.time() - t0) * 1000.0)

        try:
            choice = (data.get("choices") or [{}])[0]
            msg = choice.get("message", {}) or {}
            content = msg.get("content") or ""
            reasoning = msg.get("reasoning_content")
            usage = data.get("usage", {}) or {}
            in_tok = int(usage.get("prompt_tokens", 0) or 0)
            out_tok = int(usage.get("completion_tokens", 0) or 0)
        except Exception as e:
            return LLMResponse(content="", provider="deepseek", model=model,
                               error=f"parse error: {e}")

        cost = self._cost(model, in_tok, out_tok)
        if self.budget is not None:
            try:
                self.budget.log_request(UsageMetrics(
                    provider="deepseek", model=model, input_tokens=in_tok,
                    output_tokens=out_tok, total_tokens=in_tok + out_tok,
                    cost_usd=cost, latency_ms=latency))
            except Exception:
                pass
        return LLMResponse(
            content=content, provider="deepseek", model=model,
            finish_reason=choice.get("finish_reason"),
            usage={"input_tokens": in_tok, "output_tokens": out_tok},
            cost_usd=cost, latency_ms=latency, reasoning_content=reasoning)

    @staticmethod
    def _cost(model: str, in_tok: int, out_tok: int) -> float:
        # DeepSeek list pricing ($/1M): chat ~0.27 in / 1.10 out; reasoner
        # ~0.55 in / 2.19 out. Cache-miss rates; good enough for accounting.
        if _REASONER_HINT in model.lower():
            ci, co = 0.55, 2.19
        else:
            ci, co = 0.27, 1.10
        return (in_tok * ci + out_tok * co) / 1_000_000.0
