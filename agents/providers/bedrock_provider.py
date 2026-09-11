"""Phase 9.1 — Amazon Bedrock LLM provider.

Implements the harness ``LLMProvider`` interface over Bedrock's ``invoke_model``
for Anthropic Claude models. Supports both IAM-role auth (ECS/EC2 — boto3 finds
credentials automatically) and access-key auth (local dev, via the standard AWS
env vars). Registered in the harness provider factory as ``ProviderType.BEDROCK``.

boto3 is imported lazily so this module imports without it; tests inject a fake
client, so the provider is testable with no AWS.

.env:
    LLM_PROVIDER=bedrock
    AWS_REGION=us-east-1
    AWS_BEDROCK_SMALL_MODEL=us.anthropic.claude-haiku-4-5-v1
    AWS_BEDROCK_LARGE_MODEL=us.anthropic.claude-sonnet-4-v1
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Optional

from agents.universal_llm_harness import (
    LLMProvider,
    LLMResponse,
    ProviderType,
    TaskTier,
    TokenBudget,
)

logger = logging.getLogger(__name__)

# Approx Bedrock Claude pricing (USD per 1M tokens) for cost estimation.
_PRICING = {
    "haiku": (0.80, 4.0),
    "sonnet": (3.0, 15.0),
    "opus": (15.0, 75.0),
}


def _price_for(model: str) -> tuple:
    m = (model or "").lower()
    for key, price in _PRICING.items():
        if key in m:
            return price
    return (1.0, 3.0)


class BedrockProvider(LLMProvider):

    def __init__(self, small_model: str = "", large_model: str = "",
                 region: str = "", budget: Optional[TokenBudget] = None,
                 client: Any = None):
        super().__init__(ProviderType.BEDROCK, budget or TokenBudget())
        self.small_model = small_model or os.getenv("AWS_BEDROCK_SMALL_MODEL",
                                                    "us.anthropic.claude-haiku-4-5-v1")
        self.large_model = large_model or os.getenv("AWS_BEDROCK_LARGE_MODEL",
                                                    "us.anthropic.claude-sonnet-4-v1")
        self.region = region or os.getenv("AWS_REGION", "us-east-1")
        self._client = client  # injectable; lazily created from boto3 otherwise

    def _get_client(self):
        if self._client is None:
            import boto3  # lazy — only when actually invoked
            self._client = boto3.client("bedrock-runtime", region_name=self.region)
        return self._client

    async def is_available(self) -> bool:
        try:
            self._get_client()
            return True
        except Exception as e:
            logger.warning("BedrockProvider unavailable: %s", e)
            return False

    def get_small_model(self) -> str:
        return self.small_model

    def get_large_model(self) -> str:
        return self.large_model

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
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            body["system"] = system

        start = time.monotonic()
        try:
            client = self._get_client()
            resp = client.invoke_model(modelId=model, body=json.dumps(body))
            payload = resp["body"].read() if hasattr(resp.get("body"), "read") else resp.get("body", b"{}")
            data = json.loads(payload)
        except Exception as e:
            logger.warning("Bedrock invoke_model failed: %s", e)
            return LLMResponse(content="", provider="bedrock", model=model, error=str(e),
                               latency_ms=(time.monotonic() - start) * 1000)

        content = self._extract_text(data)
        usage = data.get("usage", {}) or {}
        in_tok = int(usage.get("input_tokens", 0))
        out_tok = int(usage.get("output_tokens", 0))
        pin, pout = _price_for(model)
        cost = (in_tok * pin + out_tok * pout) / 1_000_000

        structured = None
        if response_format == "json":
            structured = self._try_json(content)

        return LLMResponse(
            content=content, structured_output=structured,
            finish_reason=data.get("stop_reason"), provider="bedrock", model=model,
            usage={"input_tokens": in_tok, "output_tokens": out_tok,
                   "total_tokens": in_tok + out_tok},
            cost_usd=round(cost, 6), latency_ms=(time.monotonic() - start) * 1000)

    @staticmethod
    def _extract_text(data: dict) -> str:
        content = data.get("content")
        if isinstance(content, list):
            return "".join(block.get("text", "") for block in content
                           if isinstance(block, dict))
        if isinstance(content, str):
            return content
        return data.get("completion", "")  # legacy shape

    @staticmethod
    def _try_json(text: str):
        import re
        try:
            return json.loads(re.sub(r"```json\n?|\n?```", "", text or "").strip())
        except (ValueError, TypeError):
            m = re.search(r"\{[\s\S]*\}", text or "")
            if m:
                try:
                    return json.loads(m.group(0))
                except (ValueError, TypeError):
                    return None
            return None
