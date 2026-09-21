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

# Approx Bedrock pricing (USD per 1M tokens) for cost estimation.
_PRICING = {
    "haiku": (0.80, 4.0),
    "sonnet": (3.0, 15.0),
    "opus": (15.0, 75.0),
    "deepseek": (0.28, 0.42),
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
        # single source of truth (identical LLM dev & prod)
        from core.llm.bedrock_config import (
            small_model as _sm, large_model as _lm, bedrock_region as _rg,
            bedrock_base_url as _url, bedrock_api_token as _tok,
        )
        self.small_model = small_model or _sm()
        self.large_model = large_model or _lm()
        self.region = region or _rg()
        # OpenAI-compatible gateway (Bearer auth). When base_url is set, the HTTP
        # path is used instead of boto3 invoke_model. Auth prefers a freshly minted
        # short-term token (aws_bedrock_token_generator, from the AWS credential
        # chain) so it never expires mid-run; a static AWS_BEARER_TOKEN_BEDROCK is
        # the fallback.
        self.base_url = _url()
        self.api_token = _tok()
        self._client = client  # injectable; lazily created from boto3 otherwise

    def _sdk_base_url(self) -> str:
        """OpenAI SDK base_url: the '/v1' root (SDK appends '/chat/completions')."""
        u = self.base_url.rstrip("/")
        if u.endswith("/chat/completions"):
            u = u[: -len("/chat/completions")]
        return u

    def _mint_token(self) -> str:
        """Fresh short-term gateway token from the AWS credential chain; falls
        back to the static AWS_BEARER_TOKEN_BEDROCK when generation is unavailable."""
        try:
            from aws_bedrock_token_generator import provide_token
            return provide_token(region=self.region)
        except Exception as e:
            if self.api_token:
                return self.api_token
            raise RuntimeError(f"no Bedrock gateway token: {e}")

    def _can_auth(self) -> bool:
        if self.api_token:
            return True
        try:
            import aws_bedrock_token_generator  # noqa: F401
            import boto3
            return boto3.Session().get_credentials() is not None
        except Exception:
            return False

    def _use_gateway(self) -> bool:
        return bool(self.base_url and self._can_auth())

    def _get_client(self):
        if self._client is None:
            import boto3  # lazy — only when actually invoked
            self._client = boto3.client("bedrock-runtime", region_name=self.region)
        return self._client

    async def is_available(self) -> bool:
        if self._use_gateway():
            return True
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

    def supports_native_tools(self) -> bool:
        # generate_with_tools speaks the Anthropic Messages tool schema
        # (anthropic_version + input_schema) for Claude on Bedrock, AND — via the
        # OpenAI-compatible gateway — OpenAI function-calling, which every gateway
        # model (deepseek/qwen/gpt-oss/glm/…) supports. Enabling this unlocks the
        # native agentic loop for non-Claude models; the JSON-planner fallback used
        # to bypass OSINT/specialist agents. Opt out with BEDROCK_GATEWAY_TOOLS=0.
        m = (self.get_large_model() or "").lower()
        if "anthropic" in m or "claude" in m:
            return True
        if self._use_gateway() and os.getenv("BEDROCK_GATEWAY_TOOLS", "1") != "0":
            return True
        return False

    def count_tokens(self, text: str) -> int:
        try:
            import tiktoken
            enc = tiktoken.get_encoding("cl100k_base")
            return len(enc.encode(text))
        except Exception:
            return max(1, len(text) // 4)

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
        if self._use_gateway():
            return await self._gateway_chat(prompt, system, max_tokens, temperature,
                                            response_format, model)
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

    async def _gateway_chat(
        self,
        prompt: str,
        system: Optional[str],
        max_tokens: int,
        temperature: float,
        response_format: Optional[str],
        model: str,
    ) -> LLMResponse:
        """OpenAI-compatible chat call to the Bedrock (Mantle) gateway.

        Follows the console 'Getting started' pattern: the OpenAI SDK pointed at
        the gateway base_url, authenticated with a freshly minted short-term token
        (provide_token). Token accounting: the gateway returns usage.{prompt_tokens,
        completion_tokens, total_tokens}; these map to the harness's input/output/
        total counters so every call is metered.
        """
        sys_prompt = system or ""
        if response_format == "json":
            sys_prompt = (sys_prompt + "\n\nRespond with a single valid JSON object "
                          "only. No prose, no markdown fences.").strip()

        messages = []
        if sys_prompt:
            messages.append({"role": "system", "content": sys_prompt})
        messages.append({"role": "user", "content": prompt})

        start = time.monotonic()
        client = None
        try:
            from openai import AsyncOpenAI
            # Hard per-attempt timeout + bounded retries so a slow/hanging gateway
            # cannot block the main scan loop for minutes (default is 600s/attempt,
            # which stalled the planner and starved the phase no-progress guard).
            client = AsyncOpenAI(base_url=self._sdk_base_url(),
                                 api_key=self._mint_token(),
                                 timeout=90.0, max_retries=2)
            resp = await client.chat.completions.create(
                model=model, messages=messages,
                max_tokens=max_tokens, temperature=temperature)
        except Exception as e:
            logger.warning("Bedrock gateway request failed: %s", e)
            return LLMResponse(content="", provider="bedrock", model=model, error=str(e),
                               latency_ms=(time.monotonic() - start) * 1000)
        finally:
            if client is not None:
                try:
                    await client.close()
                except Exception:
                    pass

        latency = (time.monotonic() - start) * 1000
        content = ""
        finish_reason = None
        if resp.choices:
            content = resp.choices[0].message.content or ""
            finish_reason = resp.choices[0].finish_reason

        usage = resp.usage
        in_tok = int(getattr(usage, "prompt_tokens", 0) or 0)
        out_tok = int(getattr(usage, "completion_tokens", 0) or 0)
        total = int(getattr(usage, "total_tokens", in_tok + out_tok) or (in_tok + out_tok))
        pin, pout = _price_for(model)
        cost = (in_tok * pin + out_tok * pout) / 1_000_000

        logger.info("[Bedrock/gateway] %s tokens in=%d out=%d total=%d cost=$%.6f",
                    model, in_tok, out_tok, total, cost)

        structured = self._try_json(content) if response_format == "json" else None

        return LLMResponse(
            content=content, structured_output=structured,
            finish_reason=finish_reason, provider="bedrock", model=model,
            usage={"input_tokens": in_tok, "output_tokens": out_tok,
                   "total_tokens": total},
            cost_usd=round(cost, 6), latency_ms=latency)

    async def generate_with_tools(
        self,
        messages: list,
        tools: list,
        max_tokens: int = 4096,
        tier: TaskTier = TaskTier.SMALL,
        tool_executor=None,
        max_rounds: int = 10,
    ) -> LLMResponse:
        # Gateway models (deepseek/qwen/gpt-oss/…) speak OpenAI function-calling,
        # not the Anthropic tool schema — run the OpenAI tool loop over the gateway.
        if self._use_gateway():
            return await self._gateway_tools(
                messages, tools, max_tokens, tier, tool_executor, max_rounds)
        model = self.get_model_for_tier(tier)
        bedrock_tools = []
        for t in tools:
            fn = t.get("function", t)
            bedrock_tools.append({
                "name": fn["name"],
                "description": fn.get("description", ""),
                "input_schema": fn.get("parameters", {}),
            })

        total_in = total_out = 0
        total_cost = 0.0
        start = time.monotonic()
        conv_messages = list(messages)

        for _round in range(max_rounds):
            body: dict[str, Any] = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "messages": conv_messages,
                "tools": bedrock_tools,
            }
            sys_parts = [m["content"] for m in conv_messages if m.get("role") == "system"]
            conv_messages = [m for m in conv_messages if m.get("role") != "system"]
            body["messages"] = conv_messages
            if sys_parts:
                body["system"] = "\n\n".join(sys_parts)

            try:
                client = self._get_client()
                resp = client.invoke_model(modelId=model, body=json.dumps(body))
                payload = resp["body"].read() if hasattr(resp.get("body"), "read") else resp.get("body", b"{}")
                data = json.loads(payload)
            except Exception as e:
                return LLMResponse(content="", provider="bedrock", model=model, error=str(e),
                                   latency_ms=(time.monotonic() - start) * 1000)

            usage = data.get("usage", {}) or {}
            total_in += int(usage.get("input_tokens", 0))
            total_out += int(usage.get("output_tokens", 0))
            pin, pout = _price_for(model)
            total_cost += (int(usage.get("input_tokens", 0)) * pin +
                           int(usage.get("output_tokens", 0)) * pout) / 1_000_000

            stop_reason = data.get("stop_reason", "end_turn")
            content_blocks = data.get("content", [])

            tool_uses = [b for b in content_blocks if isinstance(b, dict) and b.get("type") == "tool_use"]

            if not tool_uses or stop_reason != "tool_use" or not tool_executor:
                text = self._extract_text(data)
                latency = (time.monotonic() - start) * 1000
                return LLMResponse(
                    content=text, provider="bedrock", model=model,
                    cost_usd=round(total_cost, 6), latency_ms=latency,
                    usage={"input_tokens": total_in, "output_tokens": total_out,
                           "total_tokens": total_in + total_out})

            conv_messages.append({"role": "assistant", "content": content_blocks})

            tool_results = []
            for tu in tool_uses:
                try:
                    import asyncio as _aio
                    result = tool_executor(tu["name"], tu.get("input", {}))
                    if _aio.iscoroutine(result):
                        result = await result
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tu["id"],
                        "content": str(result) if not isinstance(result, str) else result,
                    })
                except Exception as e:
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tu["id"],
                        "content": f"Error: {e}",
                        "is_error": True,
                    })
            conv_messages.append({"role": "user", "content": tool_results})

        text = self._extract_text(data)
        latency = (time.monotonic() - start) * 1000
        return LLMResponse(
            content=text, provider="bedrock", model=model,
            cost_usd=round(total_cost, 6), latency_ms=latency,
            usage={"input_tokens": total_in, "output_tokens": total_out,
                   "total_tokens": total_in + total_out})

    async def _gateway_tools(self, messages, tools, max_tokens, tier,
                             tool_executor, max_rounds) -> LLMResponse:
        """OpenAI function-calling tool loop over the gateway. Mirrors the
        Anthropic path's contract: runs up to max_rounds, calls
        tool_executor(name, args_dict) (sync or async) for each tool_call, feeds
        the result back as a role=tool message, and returns the final assistant
        text as an LLMResponse. Any gateway model (deepseek/qwen/gpt-oss/…) works."""
        import asyncio as _aio
        model = self.get_model_for_tier(tier)
        # PENTESTING_TOOLS are already OpenAI-shaped; normalize any bare fn dicts.
        oai_tools = [t if t.get("type") == "function"
                     else {"type": "function", "function": t} for t in (tools or [])]
        conv = list(messages)
        total_in = total_out = 0
        start = time.monotonic()
        last_text = ""
        client = None
        try:
            from openai import AsyncOpenAI
            client = AsyncOpenAI(base_url=self._sdk_base_url(),
                                 api_key=self._mint_token(),
                                 timeout=90.0, max_retries=2)
            for _round in range(max(1, max_rounds)):
                resp = await client.chat.completions.create(
                    model=model, messages=conv, tools=oai_tools,
                    tool_choice="auto", max_tokens=max_tokens)
                u = getattr(resp, "usage", None)
                if u:
                    total_in += int(getattr(u, "prompt_tokens", 0) or 0)
                    total_out += int(getattr(u, "completion_tokens", 0) or 0)
                msg = resp.choices[0].message
                tool_calls = list(getattr(msg, "tool_calls", None) or [])
                if msg.content:
                    last_text = msg.content
                if not tool_calls or not tool_executor:
                    break
                # Echo the assistant turn (with tool_calls) then each tool result.
                conv.append({
                    "role": "assistant",
                    "content": msg.content or "",
                    "tool_calls": [{
                        "id": tc.id, "type": "function",
                        "function": {"name": tc.function.name,
                                     "arguments": tc.function.arguments},
                    } for tc in tool_calls],
                })
                for tc in tool_calls:
                    try:
                        args = json.loads(tc.function.arguments or "{}")
                    except Exception:
                        args = {}
                    try:
                        result = tool_executor(tc.function.name, args)
                        if _aio.iscoroutine(result):
                            result = await result
                        result = result if isinstance(result, str) else str(result)
                    except Exception as e:
                        result = f"Error: {e}"
                    conv.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": result[:20000]})
            pin, pout = _price_for(model)
            cost = (total_in * pin + total_out * pout) / 1_000_000
            return LLMResponse(
                content=last_text, provider="bedrock", model=model,
                cost_usd=round(cost, 6), latency_ms=(time.monotonic() - start) * 1000,
                usage={"input_tokens": total_in, "output_tokens": total_out,
                       "total_tokens": total_in + total_out})
        except Exception as e:
            logger.warning("[Bedrock/gateway-tools] failed: %s", e)
            return LLMResponse(content=last_text, provider="bedrock", model=model,
                               error=str(e), latency_ms=(time.monotonic() - start) * 1000)
        finally:
            if client is not None:
                try:
                    await client.close()
                except Exception:
                    pass

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
