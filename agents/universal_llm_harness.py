"""
Universal LLM Harness - Provider-agnostic orchestration layer
Supports: OpenAI, Claude, Gemini, DeepSeek, Ollama, Groq, Azure, Custom

Core features:
  - Single interface for all providers
  - Token budget tracking & cost monitoring
  - Automatic retry & rate limiting
  - Response normalization
  - Structured JSON fallback parsing
  - Task-tier optimization (SMALL/LARGE)
  - Provider auto-discovery & fallback
"""

import asyncio
import hashlib
import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Optional, List, Any

import httpx

# DeepSeek V4 tokenizer (more accurate than tiktoken for DeepSeek models)
_ds_tokenizer = None

def _get_deepseek_tokenizer():
    global _ds_tokenizer
    if _ds_tokenizer is not None:
        return _ds_tokenizer
    try:
        import transformers, pathlib
        tok_dir = pathlib.Path(__file__).resolve().parent.parent / "deepseek_v4_tokenizer"
        if tok_dir.exists():
            _ds_tokenizer = transformers.AutoTokenizer.from_pretrained(
                str(tok_dir), trust_remote_code=True
            )
            return _ds_tokenizer
    except Exception:
        pass
    _ds_tokenizer = False  # sentinel: tried, failed
    return _ds_tokenizer

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# ENUMS & CONSTANTS
# ═══════════════════════════════════════════════════════════════

from core.common.schemas import TaskTier  # noqa: E402 — canonical enum


class ProviderType(Enum):
    """Supported LLM providers"""
    OPENAI = "openai"
    CLAUDE = "claude"
    CLAUDE_CLI = "claude_cli"
    GEMINI = "gemini"
    DEEPSEEK = "deepseek"
    GROQ = "groq"
    OLLAMA = "ollama"
    AZURE = "azure"
    CUSTOM = "custom"


# ═══════════════════════════════════════════════════════════════
# COST TRACKING
# ═══════════════════════════════════════════════════════════════

@dataclass
class PricingTier:
    """Pricing per 1M tokens (converted to per-token internally)"""
    input: float      # $/1M tokens (cache miss)
    output: float     # $/1M tokens
    cache_hit: float = 0.0  # $/1M tokens (cache hit, 0 = no cache discount)


# Global pricing reference — DeepSeek V4 (Sep 2026), others current
# All prices per 1M tokens (off-peak rates; peak = 2x during 01:00-04:00 & 06:00-10:00 UTC Mon-Fri)
PROVIDER_PRICING = {
    "openai": {
        "gpt-4": PricingTier(30.0, 60.0),
        "gpt-4-turbo": PricingTier(10.0, 30.0),
        "gpt-3.5-turbo": PricingTier(0.5, 1.5),
    },
    "anthropic": {
        "claude-3-opus": PricingTier(15.0, 75.0),
        "claude-3-sonnet": PricingTier(3.0, 15.0),
        "claude-3-haiku": PricingTier(0.25, 1.25),
    },
    "google": {
        "gemini-pro": PricingTier(0.5, 1.5),
        "gemini-pro-vision": PricingTier(1.0, 2.0),
    },
    "deepseek": {
        # V4 models — off-peak $/1M tokens
        "deepseek-v4-flash": PricingTier(0.22, 0.66, cache_hit=0.007),
        "deepseek-v4-pro": PricingTier(0.66, 1.98, cache_hit=0.022),
        "deepseek-v4-flash-vision-exp": PricingTier(0.22, 0.66, cache_hit=0.007),
        # Legacy aliases
        "deepseek-chat": PricingTier(0.22, 0.66, cache_hit=0.007),
        "deepseek-reasoner": PricingTier(0.66, 1.98, cache_hit=0.022),
    },
    "groq": {
        "mixtral-8x7b": PricingTier(0.0, 0.0),
        "llama2-70b": PricingTier(0.0, 0.0),
    },
    "ollama": {
        "any": PricingTier(0.0, 0.0),
    },
    "azure": {
        "gpt-4": PricingTier(30.0, 60.0),
        "gpt-35-turbo": PricingTier(1.5, 2.0),
    }
}


@dataclass
class UsageMetrics:
    """Track per-request & aggregate usage"""
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    latency_ms: float = 0.0
    error: Optional[str] = None
    cache_hit_tokens: int = 0
    cache_miss_tokens: int = 0
    reasoning_tokens: int = 0


class TokenBudget:
    """Multi-provider token & cost budget tracker"""
    
    def __init__(self, max_budget_usd: float = 100.0):
        self.max_budget_usd = max_budget_usd
        self.spent_usd = 0.0
        self.requests: List[UsageMetrics] = []
    
    def log_request(self, metric: UsageMetrics):
        """Log request metrics"""
        self.spent_usd += metric.cost_usd
        self.requests.append(metric)
        pct = (self.spent_usd / self.max_budget_usd) * 100
        logger.info(
            f"[COST] {metric.provider}/{metric.model} | "
            f"${self.spent_usd:.4f}/{self.max_budget_usd:.2f} ({pct:.1f}%) | "
            f"Tokens: {metric.total_tokens} | Latency: {metric.latency_ms:.0f}ms"
        )
    
    def can_afford(self, estimated_tokens: int, provider: str, model: str) -> bool:
        """Check if budget allows request"""
        if estimated_tokens <= 0:
            return True
        pricing = self._get_pricing(provider, model)
        estimated_cost = (estimated_tokens * pricing.input / 1_000_000) + \
                        (estimated_tokens * 2 * pricing.output / 1_000_000)
        remaining = self.max_budget_usd - self.spent_usd
        return estimated_cost <= remaining
    
    def _get_pricing(self, provider: str, model: str) -> PricingTier:
        """Get pricing for model"""
        provider_lower = provider.lower()
        model_lower = model.lower()
        
        if provider_lower not in PROVIDER_PRICING:
            return PricingTier(0.001, 0.001)  # Safe default
        
        provider_pricing = PROVIDER_PRICING[provider_lower]
        if model_lower in provider_pricing:
            return provider_pricing[model_lower]
        
        # Fallback to first available or default
        return next(iter(provider_pricing.values())) if provider_pricing else PricingTier(0.001, 0.001)
    
    def stats(self) -> Dict[str, Any]:
        """Get aggregate statistics"""
        total_cost = sum(r.cost_usd for r in self.requests)
        total_tokens = sum(r.total_tokens for r in self.requests)
        total_cache_hit = sum(r.cache_hit_tokens for r in self.requests)
        total_cache_miss = sum(r.cache_miss_tokens for r in self.requests)
        total_reasoning = sum(r.reasoning_tokens for r in self.requests)
        avg_latency = sum(r.latency_ms for r in self.requests) / len(self.requests) if self.requests else 0

        provider_breakdown = {}
        for req in self.requests:
            key = f"{req.provider}/{req.model}"
            if key not in provider_breakdown:
                provider_breakdown[key] = {"requests": 0, "tokens": 0, "cost": 0.0,
                                           "cache_hit_tokens": 0, "reasoning_tokens": 0}
            provider_breakdown[key]["requests"] += 1
            provider_breakdown[key]["tokens"] += req.total_tokens
            provider_breakdown[key]["cost"] += req.cost_usd
            provider_breakdown[key]["cache_hit_tokens"] += req.cache_hit_tokens
            provider_breakdown[key]["reasoning_tokens"] += req.reasoning_tokens

        return {
            "total_requests": len(self.requests),
            "total_tokens": total_tokens,
            "total_cost_usd": total_cost,
            "remaining_budget_usd": self.max_budget_usd - total_cost,
            "avg_latency_ms": avg_latency,
            "cache_hit_tokens": total_cache_hit,
            "cache_miss_tokens": total_cache_miss,
            "reasoning_tokens": total_reasoning,
            "provider_breakdown": provider_breakdown,
            "errors": [r.error for r in self.requests if r.error],
        }


# ═══════════════════════════════════════════════════════════════
# NORMALIZED RESPONSE
# ═══════════════════════════════════════════════════════════════

@dataclass
class LLMResponse:
    """Normalized response across all providers"""
    content: str
    structured_output: Optional[Dict[str, Any]] = None
    finish_reason: Optional[str] = None
    provider: str = "unknown"
    model: str = "unknown"
    usage: Optional[Dict[str, int]] = None
    cost_usd: float = 0.0
    error: Optional[str] = None
    latency_ms: float = 0.0
    reasoning_content: Optional[str] = None
    cache_hit_tokens: int = 0
    cache_miss_tokens: int = 0
    tool_calls: Optional[List[Dict[str, Any]]] = None


# ═══════════════════════════════════════════════════════════════
# PROVIDER BASE CLASS
# ═══════════════════════════════════════════════════════════════

class LLMProvider(ABC):
    """Abstract base for all LLM providers"""
    
    def __init__(self, provider_type: ProviderType, budget: TokenBudget):
        self.provider_type = provider_type
        self.budget = budget
        self.timeout = 120
        self.session: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self):
        self.session = httpx.AsyncClient(timeout=self.timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.aclose()
    
    @abstractmethod
    async def is_available(self) -> bool:
        """Check provider availability"""
        pass
    
    @abstractmethod
    def get_small_model(self) -> str:
        """Get small/fast model name"""
        pass
    
    @abstractmethod
    def get_large_model(self) -> str:
        """Get large/powerful model name"""
        pass
    
    def get_model_for_tier(self, tier: TaskTier) -> str:
        """Select model based on tier"""
        return self.get_small_model() if tier == TaskTier.SMALL else self.get_large_model()
    
    @abstractmethod
    async def generate_response(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.3,
        response_format: Optional[str] = None,
        tier: TaskTier = TaskTier.SMALL
    ) -> LLMResponse:
        """Generate LLM response"""
        pass
    
    async def generate_text(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.3,
        tier: TaskTier = TaskTier.SMALL
    ) -> str:
        """Generate plain text response"""
        resp = await self.generate_response(prompt, system, max_tokens, temperature, tier=tier)
        return resp.content if not resp.error else ""
    
    async def generate_json(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 2048,
        mandatory_fields: Optional[List[str]] = None,
        tier: TaskTier = TaskTier.SMALL
    ) -> Dict[str, Any]:
        """Generate JSON response with fallback parsing"""
        resp = await self.generate_response(
            prompt, system, max_tokens, 0.1, "json", tier
        )
        
        if resp.error:
            logger.error(f"JSON request failed: {resp.error}")
            return {}
        
        # Try structured output first
        if resp.structured_output:
            return resp.structured_output
        
        # Fallback: parse from content
        if resp.content:
            try:
                clean = re.sub(r'```json\n?|\n?```', '', resp.content).strip()
                parsed = json.loads(clean)
                return parsed
            except:
                # Try regex extraction
                match = re.search(r'\{[\s\S]*\}', resp.content)
                if match:
                    try:
                        return json.loads(match.group(0))
                    except:
                        pass
        
        logger.warning(f"Failed to parse JSON from response: {resp.content[:200]}")
        return {}
    
    def _parse_json_response(self, content: str) -> Optional[Dict]:
        """Robust JSON parsing with multiple fallbacks"""
        if not content:
            return None
        
        try:
            return json.loads(content)
        except:
            pass
        
        # Try without markdown
        try:
            clean = re.sub(r'```json\n?|\n?```', '', content).strip()
            return json.loads(clean)
        except:
            pass
        
        # Extract JSON object
        match = re.search(r'\{[\s\S]*\}', content)
        if match:
            try:
                return json.loads(match.group(0))
            except:
                pass
        
        # Extract JSON array
        match = re.search(r'\[[\s\S]*\]', content)
        if match:
            try:
                return json.loads(match.group(0))
            except:
                pass
        
        return None


# ═══════════════════════════════════════════════════════════════
# PROVIDER IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════════

class DeepSeekProvider(LLMProvider):
    """
    DeepSeek V4 API provider (OpenAI-compatible format).

    Models:
      - deepseek-v4-flash   : fast, cheap  (concurrency 2500)
      - deepseek-v4-pro     : powerful reasoning (concurrency 500)
      - deepseek-v4-flash-vision-exp : flash + image input

    Thinking mode is ON by default (reasoning_effort: high).
    Context caching is automatic — prompt_cache_hit_tokens in response.
    Pricing per 1M tokens (off-peak):
      flash  input $0.22 / cache-hit $0.007 / output $0.66
      pro    input $0.66 / cache-hit $0.022 / output $1.98
    Peak hours (2x): Mon-Fri 01:00-04:00 & 06:00-10:00 UTC.
    """

    MODEL_ALIASES = {
        "deepseek-chat": "deepseek-v4-flash",
        "deepseek-reasoner": "deepseek-v4-pro",
        "deepseek-coder": "deepseek-v4-flash",
    }

    def __init__(
        self,
        api_key: str,
        small_model: str = "deepseek-v4-flash",
        large_model: str = "deepseek-v4-pro",
        base_url: str = "https://api.deepseek.com",
        budget: Optional[TokenBudget] = None,
        reasoning_effort: str = "high",
        user_id: Optional[str] = None,
    ):
        super().__init__(ProviderType.DEEPSEEK, budget or TokenBudget())
        self.api_key = api_key
        self.small_model = self.MODEL_ALIASES.get(small_model, small_model)
        self.large_model = self.MODEL_ALIASES.get(large_model, large_model)
        self.base_url = base_url.rstrip("/")
        self.reasoning_effort = reasoning_effort
        self.timeout = 180
        self.user_id = user_id
        self._retry_count = 0
        self._max_retries = 3
        # Per-conversation reasoning_content store for tool-call multi-turn
        self._reasoning_history: Dict[str, str] = {}

    async def is_available(self) -> bool:
        if not self.api_key:
            logger.warning("[DeepSeek] no API key configured")
            return False
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.small_model,
                        "messages": [{"role": "user", "content": "hi"}],
                        "max_tokens": 1,
                        "thinking": {"type": "disabled"},
                    },
                )
                if r.status_code == 200:
                    return True
                logger.warning(f"[DeepSeek] availability check HTTP {r.status_code}: {r.text[:200]}")
                return r.status_code == 401  # Key exists but invalid — still "reachable"
        except httpx.ConnectTimeout:
            logger.warning("[DeepSeek] availability check: connection timeout (30s)")
            return False
        except httpx.ConnectError as e:
            logger.warning(f"[DeepSeek] availability check: connection error — {type(e).__name__}: {e}")
            return False
        except Exception as e:
            logger.warning(f"[DeepSeek] availability check: {type(e).__name__}: {e}")
            return False

    def get_small_model(self) -> str:
        return self.small_model

    def get_large_model(self) -> str:
        return self.large_model

    def _resolve_model(self, model: str) -> str:
        return self.MODEL_ALIASES.get(model, model)

    def count_tokens(self, text: str) -> int:
        tok = _get_deepseek_tokenizer()
        if tok:
            return len(tok.encode(text))
        return max(1, len(text) // 4)

    def _build_payload(
        self, messages: List[Dict], model: str, max_tokens: int,
        temperature: float, use_thinking: bool,
        response_format: Optional[str] = None,
        tools: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "stream": False,
        }

        if use_thinking:
            payload["thinking"] = {"type": "enabled"}
            payload["reasoning_effort"] = self.reasoning_effort
            # thinking mode ignores temperature/top_p
        else:
            payload["thinking"] = {"type": "disabled"}
            payload["temperature"] = temperature

        if response_format == "json":
            payload["response_format"] = {"type": "json_object"}

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        if self.user_id:
            payload["user_id"] = self.user_id

        return payload

    def _parse_response_data(self, data: Dict, model: str, latency_ms: float,
                              response_format: Optional[str] = None) -> LLMResponse:
        choice = data["choices"][0]
        message = choice.get("message", {})
        content = message.get("content") or ""
        reasoning_content = message.get("reasoning_content") or ""
        tool_calls = message.get("tool_calls")
        finish_reason = choice.get("finish_reason")

        if not content and reasoning_content and finish_reason != "tool_calls":
            content = reasoning_content

        usage = data.get("usage", {})
        input_tokens = usage.get("prompt_tokens", 0)
        output_tokens = usage.get("completion_tokens", 0)
        cache_hit = usage.get("prompt_cache_hit_tokens", 0)
        cache_miss = usage.get("prompt_cache_miss_tokens", 0)
        reasoning_tokens = 0
        if "completion_tokens_details" in usage:
            reasoning_tokens = usage["completion_tokens_details"].get("reasoning_tokens", 0)

        pricing = self.budget._get_pricing("deepseek", model)
        if cache_hit > 0 and pricing.cache_hit > 0:
            input_cost = (cache_hit * pricing.cache_hit / 1_000_000) + \
                         (cache_miss * pricing.input / 1_000_000)
        else:
            input_cost = input_tokens * pricing.input / 1_000_000
        output_cost = output_tokens * pricing.output / 1_000_000
        cost = input_cost + output_cost

        metric = UsageMetrics(
            provider="deepseek", model=model,
            input_tokens=input_tokens, output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens, cost_usd=cost,
            latency_ms=latency_ms,
            cache_hit_tokens=cache_hit, cache_miss_tokens=cache_miss,
            reasoning_tokens=reasoning_tokens,
        )
        self.budget.log_request(metric)

        structured = None
        if response_format == "json" and content:
            structured = self._parse_json_response(content)

        resp = LLMResponse(
            content=content, structured_output=structured,
            finish_reason=finish_reason,
            provider="deepseek", model=model, cost_usd=cost,
            usage=usage, latency_ms=latency_ms,
            reasoning_content=reasoning_content if reasoning_content else None,
            cache_hit_tokens=cache_hit, cache_miss_tokens=cache_miss,
        )
        # Attach raw tool_calls for callers that need them
        if tool_calls:
            resp.tool_calls = tool_calls
        return resp

    async def _post(self, payload: Dict, endpoint: str = "/chat/completions") -> httpx.Response:
        if not self.session:
            self.session = httpx.AsyncClient(timeout=self.timeout)

        # Retry policy:
        #   - Transient network errors (DNS glitches, connection resets, read
        #     timeouts): exponential backoff, up to 5 attempts.
        #   - HTTP 429 (rate limit) and 503 (service unavailable): honor
        #     `Retry-After` header if present, otherwise exponential backoff.
        #     Up to 5 attempts.
        #   - Other HTTP status codes: return immediately; the caller decides.
        import asyncio as _aio
        import random as _random

        max_attempts = 5
        last_exc = None
        for attempt in range(max_attempts):
            try:
                resp = await self.session.post(
                    f"{self.base_url}{endpoint}",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                if resp.status_code in (429, 503) and attempt < max_attempts - 1:
                    # Honor server-provided Retry-After when present. Cap at 30s
                    # to avoid unbounded stalls in interactive sessions.
                    ra_hdr = resp.headers.get("Retry-After", "")
                    try:
                        wait_s = float(ra_hdr) if ra_hdr else 0.0
                    except ValueError:
                        wait_s = 0.0
                    if wait_s <= 0.0:
                        # Full jitter exponential backoff: [0, base*2**attempt]
                        wait_s = _random.uniform(0, min(30.0, 0.5 * (2 ** attempt)))
                    logger.warning(
                        "LLM provider returned %d; backing off %.2fs (attempt %d/%d)",
                        resp.status_code, wait_s, attempt + 1, max_attempts,
                    )
                    await _aio.sleep(min(wait_s, 30.0))
                    continue
                return resp
            except (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError,
                    httpx.ReadTimeout, httpx.ConnectTimeout) as e:
                last_exc = e
                if attempt < max_attempts - 1:
                    wait_s = _random.uniform(0, min(30.0, 0.5 * (2 ** attempt)))
                    await _aio.sleep(wait_s)
                    continue
                raise
        # If we exited the loop from too many 429/503, bubble up the last response.
        if last_exc:
            raise last_exc
        return resp  # type: ignore[return-value]

    async def generate_response(
        self, prompt: str, system: Optional[str] = None, max_tokens: int = 1024,
        temperature: float = 0.3, response_format: Optional[str] = None,
        tier: TaskTier = TaskTier.SMALL
    ) -> LLMResponse:
        model = self._resolve_model(self.get_model_for_tier(tier))

        if not self.budget.can_afford(max_tokens, "deepseek", model):
            return LLMResponse(content="", provider="deepseek", model=model, error="Budget exceeded")

        start_time = datetime.now()
        # Thinking mode + JSON object mode don't mix well on DeepSeek: the model
        # emits its answer as reasoning_content and returns an empty "{}" as content,
        # which is exactly the empty-response failure seen during exploitation. Disable
        # thinking whenever structured JSON is requested so JSON tasks return real data.
        use_thinking = (tier == TaskTier.LARGE) and response_format != "json"

        messages = []
        if system:
            messages.append({"role": "system", "content": system})

        # JSON mode requires "json" in the prompt per API docs
        user_content = prompt
        if response_format == "json" and "json" not in prompt.lower():
            user_content = prompt + "\n\nRespond in JSON format."
        messages.append({"role": "user", "content": user_content})

        payload = self._build_payload(messages, model, max_tokens, temperature, use_thinking, response_format)

        try:
            r = await self._post(payload)
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000

            if r.status_code == 200:
                self._retry_count = 0
                return self._parse_response_data(r.json(), model, latency_ms, response_format)

            elif r.status_code == 429:
                self._retry_count += 1
                if self._retry_count > self._max_retries:
                    self._retry_count = 0
                    return LLMResponse(content="", provider="deepseek", model=model,
                                       error="Rate limited after max retries", latency_ms=latency_ms)
                backoff = min(5 * self._retry_count, 30)
                logger.warning(f"[DeepSeek] 429 rate limited, retry {self._retry_count}/{self._max_retries} in {backoff}s")
                await asyncio.sleep(backoff)
                return await self.generate_response(prompt, system, max_tokens, temperature, response_format, tier)
            else:
                error = f"HTTP {r.status_code}: {r.text[:300]}"
                logger.error(f"[DeepSeek] {error}")
                return LLMResponse(
                    content="", provider="deepseek", model=model,
                    error=error, latency_ms=latency_ms,
                )

        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as e:
            self._retry_count += 1
            if self._retry_count <= self._max_retries:
                backoff = min(10 * self._retry_count, 60)
                logger.warning(f"[DeepSeek] {type(e).__name__}, retry {self._retry_count}/{self._max_retries} in {backoff}s")
                await asyncio.sleep(backoff)
                return await self.generate_response(prompt, system, max_tokens, temperature, response_format, tier)
            self._retry_count = 0
            logger.error(f"[DeepSeek] {type(e).__name__} after {self._max_retries} retries: {e}")
            return LLMResponse(
                content="", provider="deepseek", model=model,
                error=str(e), latency_ms=(datetime.now() - start_time).total_seconds() * 1000,
            )
        except Exception as e:
            logger.error(f"[DeepSeek] request failed: {e}")
            return LLMResponse(
                content="", provider="deepseek", model=model,
                error=str(e), latency_ms=(datetime.now() - start_time).total_seconds() * 1000,
            )

    async def generate_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        model: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        tier: TaskTier = TaskTier.LARGE,
        tool_executor: Optional[Any] = None,
        max_rounds: int = 10,
    ) -> LLMResponse:
        """
        Tool-calling loop. Sends messages with tools, executes tool_calls
        via tool_executor callback, and loops until the model stops calling tools.

        tool_executor: async callable(name, arguments_dict) -> str
        When tools param is present, reasoning_content MUST be passed back
        in all subsequent turns per DeepSeek API requirement.
        """
        model = self._resolve_model(model or self.get_model_for_tier(tier))
        use_thinking = (tier == TaskTier.LARGE)
        conv_messages = list(messages)
        total_cost = 0.0
        all_content = []

        for round_i in range(max_rounds):
            start_time = datetime.now()
            payload = self._build_payload(
                conv_messages, model, max_tokens, temperature, use_thinking,
                tools=tools,
            )

            try:
                r = await self._post(payload)
                latency_ms = (datetime.now() - start_time).total_seconds() * 1000

                if r.status_code != 200:
                    error = f"HTTP {r.status_code}: {r.text[:300]}"
                    logger.error(f"[DeepSeek] tool round {round_i}: {error}")
                    return LLMResponse(content="\n".join(all_content), provider="deepseek",
                                       model=model, error=error, latency_ms=latency_ms)

                resp = self._parse_response_data(r.json(), model, latency_ms)
                total_cost += resp.cost_usd

                data = r.json()
                choice = data["choices"][0]
                message = choice.get("message", {})
                tool_calls = message.get("tool_calls")
                reasoning_content = message.get("reasoning_content")

                if not tool_calls or choice.get("finish_reason") != "tool_calls":
                    if resp.content:
                        all_content.append(resp.content)
                    resp.content = "\n".join(all_content) if all_content else resp.content
                    resp.cost_usd = total_cost
                    return resp

                # Append assistant message with reasoning_content (required for multi-turn with tools)
                assistant_msg: Dict[str, Any] = {"role": "assistant", "content": message.get("content")}
                if reasoning_content:
                    assistant_msg["reasoning_content"] = reasoning_content
                assistant_msg["tool_calls"] = tool_calls
                conv_messages.append(assistant_msg)

                # Execute each tool call
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    fn_name = fn.get("name", "")
                    try:
                        fn_args = json.loads(fn.get("arguments", "{}"))
                    except json.JSONDecodeError:
                        fn_args = {}

                    result = ""
                    if tool_executor:
                        try:
                            result = await tool_executor(fn_name, fn_args)
                        except Exception as e:
                            result = f"Error executing {fn_name}: {e}"
                            logger.error(f"[DeepSeek] tool exec error: {e}")
                    else:
                        result = f"Tool {fn_name} not implemented"

                    # P2.8: scrub the tool result (e.g. an HTTP response body)
                    # before it re-enters the model context.
                    _content = str(result)
                    try:
                        from core.utils.scan_flags import redact_llm_context
                        if redact_llm_context():
                            from core.security.llm_redact import redact_for_llm
                            _content = redact_for_llm(_content)
                    except Exception:
                        pass
                    conv_messages.append({
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": _content,
                    })

            except Exception as e:
                logger.error(f"[DeepSeek] tool round {round_i} failed: {type(e).__name__}: {e}", exc_info=True)
                return LLMResponse(content="\n".join(all_content), provider="deepseek",
                                   model=model, error=f"{type(e).__name__}: {e}", cost_usd=total_cost,
                                   latency_ms=(datetime.now() - start_time).total_seconds() * 1000)

        return LLMResponse(
            content="\n".join(all_content) if all_content else "",
            provider="deepseek", model=model, cost_usd=total_cost,
            error=f"Tool loop exceeded {max_rounds} rounds",
        )


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider"""
    
    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        small_model: str = "mistral",
        large_model: str = "llama2",
        budget: Optional[TokenBudget] = None
    ):
        super().__init__(ProviderType.OLLAMA, budget or TokenBudget())
        self.base_url = base_url.rstrip("/")
        self.small_model = small_model
        self.large_model = large_model
    
    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self.base_url}/api/tags")
                return r.status_code == 200
        except:
            return False
    
    def get_small_model(self) -> str:
        return self.small_model
    
    def get_large_model(self) -> str:
        return self.large_model
    
    async def generate_response(
        self, prompt: str, system: Optional[str] = None, max_tokens: int = 1024,
        temperature: float = 0.3, response_format: Optional[str] = None,
        tier: TaskTier = TaskTier.SMALL
    ) -> LLMResponse:
        model = self.get_model_for_tier(tier)
        start_time = datetime.now()
        
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
            if not self.session:
                self.session = httpx.AsyncClient(timeout=self.timeout)
            
            r = await self.session.post(f"{self.base_url}/api/chat", json=payload)
            
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            if r.status_code == 200:
                data = r.json()
                content = data.get("message", {}).get("content", "")
                
                # Ollama doesn't return usage, estimate
                tokens_estimated = len(prompt.split()) + len(content.split())
                
                structured = self._parse_json_response(content) if response_format == "json" else None
                
                return LLMResponse(
                    content=content, structured_output=structured,
                    provider="ollama", model=model, latency_ms=latency_ms,
                    usage={"prompt_tokens": 0, "completion_tokens": 0}
                )
            else:
                return LLMResponse(
                    content="", provider="ollama", model=model,
                    error=f"HTTP {r.status_code}", latency_ms=latency_ms
                )
        
        except Exception as e:
            logger.error(f"Ollama request failed: {e}")
            return LLMResponse(
                content="", provider="ollama", model=model, error=str(e),
                latency_ms=(datetime.now() - start_time).total_seconds() * 1000
            )


class GroqProvider(LLMProvider):
    """Groq cloud inference (free tier)"""
    
    def __init__(
        self,
        api_key: str,
        small_model: str = "mixtral-8x7b-32768",
        large_model: str = "mixtral-8x7b-32768",
        budget: Optional[TokenBudget] = None
    ):
        super().__init__(ProviderType.GROQ, budget or TokenBudget())
        self.api_key = api_key
        self.small_model = small_model
        self.large_model = large_model
        self.base_url = "https://api.groq.com/openai/v1"
    
    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"model": self.small_model, "messages": [{"role": "user", "content": "hi"}]}
                )
                return r.status_code == 200
        except:
            return False
    
    def get_small_model(self) -> str:
        return self.small_model
    
    def get_large_model(self) -> str:
        return self.large_model
    
    async def generate_response(
        self, prompt: str, system: Optional[str] = None, max_tokens: int = 1024,
        temperature: float = 0.3, response_format: Optional[str] = None,
        tier: TaskTier = TaskTier.SMALL
    ) -> LLMResponse:
        model = self.get_model_for_tier(tier)
        start_time = datetime.now()
        
        messages = [
            {"role": "system", "content": system or "You are a helpful assistant."},
            {"role": "user", "content": prompt}
        ]
        
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        
        if response_format == "json":
            payload["response_format"] = {"type": "json_object"}
        
        try:
            if not self.session:
                self.session = httpx.AsyncClient(timeout=self.timeout)
            
            r = await self.session.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json=payload
            )
            
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            if r.status_code == 200:
                data = r.json()
                choice = data["choices"][0]
                message = choice.get("message", {})
                content = message.get("content") or ""
                reasoning_content = message.get("reasoning_content") or ""
                if not content and reasoning_content:
                    content = reasoning_content
                usage = data.get("usage", {})
                
                structured = self._parse_json_response(content) if response_format == "json" else None
                
                return LLMResponse(
                    content=content, structured_output=structured,
                    finish_reason=choice.get("finish_reason"),
                    provider="groq", model=model,
                    usage=usage, latency_ms=latency_ms, cost_usd=0.0  # Free
                )
            else:
                return LLMResponse(
                    content="", provider="groq", model=model,
                    error=f"HTTP {r.status_code}", latency_ms=latency_ms
                )
        
        except Exception as e:
            logger.error(f"Groq request failed: {e}")
            return LLMResponse(
                content="", provider="groq", model=model, error=str(e),
                latency_ms=(datetime.now() - start_time).total_seconds() * 1000
            )


# ═══════════════════════════════════════════════════════════════
# CLAUDE CLI PROVIDER (uses `claude -p` from Claude Code Pro plan)
# ═══════════════════════════════════════════════════════════════

class ClaudeCLIProvider(LLMProvider):
    """Calls the local `claude` CLI in pipe mode — uses your Claude Code Pro subscription."""

    def __init__(
        self,
        small_model: str = "claude-haiku-4-5-20251001",
        large_model: str = "claude-sonnet-4-20250514",
        budget: Optional[TokenBudget] = None,
        claude_binary: str = "claude",
    ):
        super().__init__(ProviderType.CLAUDE_CLI, budget or TokenBudget())
        self.small_model = small_model
        self.large_model = large_model
        self.claude_binary = claude_binary
        self.timeout = 300

    async def is_available(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.claude_binary, "--version",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10)
            return proc.returncode == 0
        except Exception as e:
            logger.warning(f"[ClaudeCLI] not available: {e}")
            return False

    def get_small_model(self) -> str:
        return self.small_model

    def get_large_model(self) -> str:
        return self.large_model

    async def _run_claude(self, prompt: str, system: Optional[str],
                          max_tokens: int, model: str) -> str:
        cmd = [self.claude_binary, "-p", "--model", model, "--max-turns", "1"]
        if system:
            cmd.extend(["--system-prompt", system])
        cmd.extend(["--output-format", "text"])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=prompt.encode("utf-8")),
            timeout=self.timeout,
        )
        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"claude CLI exit {proc.returncode}: {err}")
        return stdout.decode("utf-8", errors="replace")

    async def generate_response(
        self, prompt: str, system: Optional[str] = None, max_tokens: int = 1024,
        temperature: float = 0.3, response_format: Optional[str] = None,
        tier: TaskTier = TaskTier.SMALL,
    ) -> LLMResponse:
        model = self.get_model_for_tier(tier)
        start_time = datetime.now()

        user_content = prompt
        if response_format == "json":
            if system:
                system += "\nYou MUST respond with ONLY valid JSON. No markdown, no explanation."
            else:
                system = "You MUST respond with ONLY valid JSON. No markdown, no explanation."
            if "json" not in prompt.lower():
                user_content = prompt + "\n\nRespond in JSON format."

        try:
            content = await self._run_claude(user_content, system, max_tokens, model)
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000

            structured = None
            if response_format == "json" and content:
                structured = self._parse_json_response(content)

            tokens_est = max(1, len(prompt) // 4) + max(1, len(content) // 4)
            metric = UsageMetrics(
                provider="claude_cli", model=model,
                input_tokens=max(1, len(prompt) // 4),
                output_tokens=max(1, len(content) // 4),
                total_tokens=tokens_est, cost_usd=0.0,
                latency_ms=latency_ms,
            )
            self.budget.log_request(metric)

            return LLMResponse(
                content=content.strip(), structured_output=structured,
                finish_reason="stop", provider="claude_cli", model=model,
                cost_usd=0.0, latency_ms=latency_ms,
                usage={"prompt_tokens": metric.input_tokens, "completion_tokens": metric.output_tokens},
            )
        except Exception as e:
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000
            logger.error(f"[ClaudeCLI] generate failed: {e}")
            return LLMResponse(
                content="", provider="claude_cli", model=model,
                error=str(e), latency_ms=latency_ms,
            )


# ═══════════════════════════════════════════════════════════════
# UNIVERSAL HARNESS
# ═══════════════════════════════════════════════════════════════

class UniversalLLMHarness:
    """
    Provider-agnostic LLM harness
    Auto-selects & falls back between providers
    """
    
    def __init__(
        self,
        primary_provider: ProviderType = ProviderType.DEEPSEEK,
        fallback_providers: Optional[List[ProviderType]] = None,
        max_budget_usd: float = 100.0,
        **provider_config
    ):
        self.budget = TokenBudget(max_budget_usd)
        self.primary_provider = primary_provider
        self.fallback_providers = fallback_providers or [
            ProviderType.GROQ,
            ProviderType.OLLAMA
        ]
        self.provider_config = provider_config
        self.active_provider: Optional[LLMProvider] = None
        # Economic controller (Feature #5) — set during initialize().
        self.governor: Optional[Any] = None

    async def initialize(self):
        """Initialize & test primary provider, fallback if needed"""
        logger.info(f"[HARNESS] Initializing {self.primary_provider.value}...")
        
        # Attach the budget governor (graded spend policy over the TokenBudget).
        # A missing governor is surfaced at WARNING level — previously the
        # silent debug-log made it look intentional; operators found out they
        # had no cost cap only after burning through the budget.
        try:
            from core.economics.budget_governor import get_budget_governor
            self.governor = get_budget_governor(self.budget)
            if self.governor:
                logger.info(f"[HARNESS] budget governor active "
                            f"(downgrade@{self.governor.downgrade_pct:.0%}, "
                            f"hard-stop@{self.governor.hard_stop_pct:.0%})")
            else:
                logger.warning(
                    "[HARNESS] budget governor returned None — LLM spend is "
                    "capped only by the raw TokenBudget hard limit.")
                self.governor = None
        except ImportError as e:
            logger.warning(
                "[HARNESS] budget governor module unavailable (%s); LLM spend "
                "will not be graded — only the raw TokenBudget hard limit applies.", e)
            self.governor = None
        except Exception as e:
            logger.warning(
                "[HARNESS] budget governor init failed (%s); LLM spend "
                "will not be graded — only the raw TokenBudget hard limit applies.", e)
            self.governor = None
            self.governor = None

        # Try primary
        self.active_provider = self._create_provider(self.primary_provider)
        if await self.active_provider.is_available():
            logger.info(f"✓ Using {self.primary_provider.value}")
            return
        
        logger.warning(f"✗ {self.primary_provider.value} unavailable, trying fallbacks...")
        
        # Try fallbacks
        for fb in self.fallback_providers:
            logger.info(f"[HARNESS] Trying {fb.value}...")
            self.active_provider = self._create_provider(fb)
            if await self.active_provider.is_available():
                logger.info(f"✓ Using {fb.value}")
                return
            logger.warning(f"✗ {fb.value} unavailable")
        
        raise RuntimeError("No LLM provider available!")
    
    def _create_provider(self, provider_type: ProviderType) -> LLMProvider:
        """Factory for provider instances"""
        if provider_type == ProviderType.DEEPSEEK:
            return DeepSeekProvider(
                api_key=self.provider_config.get("deepseek_api_key", ""),
                small_model=self.provider_config.get("deepseek_small_model", "deepseek-v4-flash"),
                large_model=self.provider_config.get("deepseek_large_model", "deepseek-v4-pro"),
                budget=self.budget,
                reasoning_effort=self.provider_config.get("deepseek_reasoning_effort", "high"),
                user_id=self.provider_config.get("deepseek_user_id"),
            )
        
        elif provider_type == ProviderType.GROQ:
            return GroqProvider(
                api_key=self.provider_config.get("groq_api_key", ""),
                small_model=self.provider_config.get("groq_small_model", "mixtral-8x7b-32768"),
                large_model=self.provider_config.get("groq_large_model", "mixtral-8x7b-32768"),
                budget=self.budget
            )
        
        elif provider_type == ProviderType.CLAUDE_CLI:
            return ClaudeCLIProvider(
                small_model=self.provider_config.get("claude_cli_small_model", "claude-haiku-4-5-20251001"),
                large_model=self.provider_config.get("claude_cli_large_model", "claude-sonnet-4-20250514"),
                budget=self.budget,
                claude_binary=self.provider_config.get("claude_binary", "claude"),
            )

        elif provider_type == ProviderType.OLLAMA:
            return OllamaProvider(
                base_url=self.provider_config.get("ollama_base_url", "http://localhost:11434"),
                small_model=self.provider_config.get("ollama_small_model", "mistral"),
                large_model=self.provider_config.get("ollama_large_model", "llama2"),
                budget=self.budget
            )

        else:
            raise ValueError(f"Unsupported provider: {provider_type}")
    
    async def generate_response(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.3,
        response_format: Optional[str] = None,
        tier: TaskTier = TaskTier.SMALL
    ) -> LLMResponse:
        """Generate response from active provider with mid-session fallback on fatal errors (402, 5xx)."""
        if not self.active_provider:
            await self.initialize()

        # RAG context injection: retrieve relevant security knowledge and prepend to system prompt
        system = await self._inject_rag_context(prompt, system)

        # P2.8: minimize sensitive data before it enters model context.
        try:
            from core.utils.scan_flags import redact_llm_context
            if redact_llm_context():
                from core.security.llm_redact import redact_for_llm
                prompt = redact_for_llm(prompt)
                system = redact_for_llm(system)
        except Exception:
            pass

        # Economic policy: hard-stop and tier downgrade before dispatch.
        if self.governor is not None:
            model_hint = self.active_provider.get_model_for_tier(tier) if self.active_provider else ""
            if not self.governor.allow_request(max_tokens, self.primary_provider.value, model_hint):
                return LLMResponse(content="", provider=self.primary_provider.value,
                                   model=model_hint, error="Budget governor: hard stop reached")
            tier = self.governor.adjust_tier(tier)

        resp = await self.active_provider.generate_response(
            prompt, system, max_tokens, temperature, response_format, tier
        )

        if resp.error and self._is_fatal_provider_error(resp.error):
            fallback = await self._try_fallback_provider(resp.error)
            if fallback:
                return await self.active_provider.generate_response(
                    prompt, system, max_tokens, temperature, response_format, tier
                )

        return resp

    def _is_fatal_provider_error(self, error: str) -> bool:
        """Return True only for errors that indicate the primary provider is
        unusable and we should permanently swap. Uses regex-anchored HTTP status
        codes so message bodies containing the string 'HTTP 500' don't false-
        trigger a swap. Transient (429/408/timeout/connection) errors are handled
        via retry/backoff at the provider layer, not here."""
        import re as _re
        err = str(error or "")
        # Payment / quota errors — permanent for this key
        if "402" in err or "Insufficient Balance" in err or "Payment Required" in err:
            return True
        # Explicit HTTP 5xx status (as reported by our http client, not free text)
        if _re.search(r'\bHTTP\s+5\d\d\b', err):
            return True
        if _re.search(r'\bstatus[_ ]?code[=:]\s*5\d\d\b', err, _re.IGNORECASE):
            return True
        return False

    async def _try_fallback_provider(self, original_error: str) -> bool:
        logger.warning(f"[HARNESS] Primary provider failed ({original_error}), attempting mid-session fallback...")
        for fb in self.fallback_providers:
            provider = self._create_provider(fb)
            if await provider.is_available():
                logger.info(f"[HARNESS] Mid-session failover to {fb.value}")
                self.active_provider = provider
                return True
            logger.warning(f"[HARNESS] Fallback {fb.value} unavailable")
        logger.error("[HARNESS] All fallback providers exhausted")
        return False
    
    async def generate_text(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 1024,
        tier: TaskTier = TaskTier.SMALL
    ) -> str:
        """Generate text"""
        resp = await self.generate_response(prompt, system, max_tokens, tier=tier)
        return resp.content if not resp.error else ""
    
    async def generate_json(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 2048,
        tier: TaskTier = TaskTier.SMALL
    ) -> Dict[str, Any]:
        """Generate JSON with fallback parsing"""
        resp = await self.generate_response(
            prompt, system, max_tokens, 0.1, "json", tier
        )
        return resp.structured_output or {}
    
    async def generate_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        tool_executor: Optional[Any] = None,
        max_tokens: int = 4096,
        tier: TaskTier = TaskTier.LARGE,
        max_rounds: int = 10,
    ) -> LLMResponse:
        """Tool-calling loop via active provider with mid-session fallback."""
        if not self.active_provider:
            await self.initialize()
        # Economic policy also governs the agentic tool loop (the biggest spender).
        if self.governor is not None:
            if not self.governor.allow_request(max_tokens, self.primary_provider.value):
                return LLMResponse(content="", provider=self.primary_provider.value,
                                   error="Budget governor: hard stop reached")
            tier = self.governor.adjust_tier(tier)
        # P2.8: redact the initial conversation before the tool loop dispatches.
        try:
            from core.utils.scan_flags import redact_llm_context
            if redact_llm_context():
                from core.security.llm_redact import redact_messages
                messages = redact_messages(messages)
        except Exception:
            pass
        if isinstance(self.active_provider, DeepSeekProvider):
            resp = await self.active_provider.generate_with_tools(
                messages, tools, max_tokens=max_tokens, tier=tier,
                tool_executor=tool_executor, max_rounds=max_rounds,
            )
            if resp.error and self._is_fatal_provider_error(resp.error):
                if await self._try_fallback_provider(resp.error):
                    if isinstance(self.active_provider, DeepSeekProvider):
                        return await self.active_provider.generate_with_tools(
                            messages, tools, max_tokens=max_tokens, tier=tier,
                            tool_executor=tool_executor, max_rounds=max_rounds,
                        )
            return resp
        return LLMResponse(content="", error="Tool calling not supported on this provider")

    def count_tokens(self, text: str) -> int:
        if isinstance(self.active_provider, DeepSeekProvider):
            return self.active_provider.count_tokens(text)
        return max(1, len(text) // 4)

    def stats(self) -> Dict[str, Any]:
        """Get usage statistics"""
        return self.budget.stats()

    async def _inject_rag_context(self, prompt: str, system: Optional[str]) -> Optional[str]:
        """Retrieve relevant security knowledge and augment the system prompt."""
        try:
            from core.rag.pipeline import get_rag
            rag = get_rag()
            if rag is None:
                return system
            docs = await rag.retrieve(prompt, top_k=3, min_similarity=0.05)
            if not docs:
                return system
            return rag.build_system_context(docs, system)
        except Exception as e:
            logger.debug(f"[HARNESS] RAG injection skipped: {e}")
            return system

    async def close(self):
        """Cleanup"""
        if self.active_provider and self.active_provider.session:
            await self.active_provider.session.aclose()


async def demo():
    """Example usage"""
    import os
    
    harness = UniversalLLMHarness(
        primary_provider=ProviderType.DEEPSEEK,
        fallback_providers=[ProviderType.GROQ, ProviderType.OLLAMA],
        max_budget_usd=50.0,
        deepseek_api_key=os.getenv("DEEPSEEK_API_KEY", ""),
        groq_api_key=os.getenv("GROQ_API_KEY", ""),
    )
    
    try:
        await harness.initialize()
        
        # Text generation
        text = await harness.generate_text("What is cybersecurity?", max_tokens=256)
        print(f"[TEXT]\n{text}\n")
        
        # JSON generation
        json_resp = await harness.generate_json(
            "List 3 security vulnerabilities in JSON format",
            max_tokens=512
        )
        print(f"[JSON]\n{json.dumps(json_resp, indent=2)}\n")
        
        # Stats
        print(f"[STATS]\n{json.dumps(harness.stats(), indent=2)}")
    
    finally:
        await harness.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(demo())
