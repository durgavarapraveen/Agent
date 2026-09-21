
import asyncio
import json
import logging
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Optional, List, Any

import httpx

_claude_tokenizer = None

def _get_claude_tokenizer():
    """Claude uses a ~100k BPE vocab. tiktoken's cl100k_base is the closest match."""
    global _claude_tokenizer
    if _claude_tokenizer is not None:
        return _claude_tokenizer
    try:
        import tiktoken
        _claude_tokenizer = tiktoken.get_encoding("cl100k_base")
        return _claude_tokenizer
    except Exception:
        pass
    _claude_tokenizer = False
    return _claude_tokenizer

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════

from core.common.schemas import TaskTier  # noqa: E402 — canonical enum


class ProviderType(Enum):
    BEDROCK = "bedrock"
    CLAUDE_CLI = "claude_cli"
    DEEPSEEK = "deepseek"


# ═══════════════════════════════════════════════════════════════
# COST TRACKING
# ═══════════════════════════════════════════════════════════════

@dataclass
class PricingTier:
    input: float      # $/1M tokens (cache miss)
    output: float     # $/1M tokens
    cache_hit: float = 0.0  # $/1M tokens (cache hit, 0 = no cache discount)


PROVIDER_PRICING = {
    "bedrock": {
        "us.anthropic.claude-haiku-4-5-20251001-v1:0": PricingTier(0.80, 4.00, cache_hit=0.08),
        "us.anthropic.claude-sonnet-4-20250514-v1:0": PricingTier(3.00, 15.00, cache_hit=0.30),
        "us.anthropic.claude-opus-4-6-v1": PricingTier(15.00, 75.00, cache_hit=1.50),
    },
    # Claude CLI (Max/Pro subscription). Nominal API-equivalent rates for
    # accounting — marginal cost on a Max plan is $0. Keyed by CLI model alias.
    "claude_cli": {
        "haiku": PricingTier(0.80, 4.00, cache_hit=0.08),
        "sonnet": PricingTier(3.00, 15.00, cache_hit=0.30),
        "opus": PricingTier(15.00, 75.00, cache_hit=1.50),
    },
    "deepseek": {
        "deepseek-chat": PricingTier(0.27, 1.10, cache_hit=0.07),
        "deepseek-reasoner": PricingTier(0.55, 2.19, cache_hit=0.14),
    },
}


@dataclass
class UsageMetrics:
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

    def __init__(self, max_budget_usd: float = 100.0):
        self.max_budget_usd = max_budget_usd
        self.spent_usd = 0.0
        self.requests: List[UsageMetrics] = []

    def log_request(self, metric: UsageMetrics):
        self.spent_usd += metric.cost_usd
        self.requests.append(metric)
        pct = (self.spent_usd / self.max_budget_usd) * 100
        logger.info(
            f"[COST] {metric.provider}/{metric.model} | "
            f"${self.spent_usd:.4f}/{self.max_budget_usd:.2f} ({pct:.1f}%) | "
            f"Tokens: {metric.total_tokens} | Latency: {metric.latency_ms:.0f}ms"
        )

    def can_afford(self, estimated_tokens: int, provider: str, model: str) -> bool:
        if estimated_tokens <= 0:
            return True
        pricing = self._get_pricing(provider, model)
        estimated_cost = (estimated_tokens * pricing.input / 1_000_000) + \
                        (estimated_tokens * 2 * pricing.output / 1_000_000)
        remaining = self.max_budget_usd - self.spent_usd
        return estimated_cost <= remaining

    def _get_pricing(self, provider: str, model: str) -> PricingTier:
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
        pass

    @abstractmethod
    def get_small_model(self) -> str:
        pass

    @abstractmethod
    def get_large_model(self) -> str:
        pass

    def get_model_for_tier(self, tier: TaskTier) -> str:
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
        pass

    async def generate_text(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.3,
        tier: TaskTier = TaskTier.SMALL
    ) -> str:
        resp = await self.generate_response(prompt, system, max_tokens, temperature, tier=tier)
        return resp.content if not resp.error else ""

    async def generate_json(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 4096,  # 2048 truncated large synth/verify JSON -> unparseable {} (fenced but cut mid-object)
        mandatory_fields: Optional[List[str]] = None,
        tier: TaskTier = TaskTier.SMALL
    ) -> Dict[str, Any]:
        resp = await self.generate_response(
            prompt, system, max_tokens, 0.1, "json", tier
        )

        if resp.error:
            logger.error(f"JSON request failed: {resp.error}")
            return {}

        if resp.structured_output:
            return resp.structured_output

        if resp.content:
            try:
                clean = re.sub(r'```json\n?|\n?```', '', resp.content).strip()
                parsed = json.loads(clean)
                return parsed
            except:
                match = re.search(r'\{[\s\S]*\}', resp.content)
                if match:
                    try:
                        return json.loads(match.group(0))
                    except:
                        pass

        if resp.content:
            try:
                from core.llm.json_enforcer import parse_with_repair
                repaired, method = parse_with_repair(resp.content)
                if repaired is not None:
                    logger.info(f"[JSON] recovered via json_enforcer ({method})")
                    return repaired
            except Exception:
                pass

        logger.warning(f"Failed to parse JSON from response: {resp.content[:200]}")
        return {}

    def _parse_json_response(self, content: str) -> Optional[Dict]:
        if not content:
            return None

        try:
            return json.loads(content)
        except:
            pass

        try:
            clean = re.sub(r'```json\n?|\n?```', '', content).strip()
            return json.loads(clean)
        except:
            pass

        match = re.search(r'\{[\s\S]*\}', content)
        if match:
            try:
                return json.loads(match.group(0))
            except:
                pass

        match = re.search(r'\[[\s\S]*\]', content)
        if match:
            try:
                return json.loads(match.group(0))
            except:
                pass

        return None


# ═══════════════════════════════════════════════════════════════
# UNIVERSAL HARNESS
# ═══════════════════════════════════════════════════════════════

class UniversalLLMHarness:

    def __init__(
        self,
        primary_provider: ProviderType = ProviderType.BEDROCK,
        fallback_providers: Optional[List[ProviderType]] = None,
        max_budget_usd: float = 100.0,
        **provider_config
    ):
        self.budget = TokenBudget(max_budget_usd)
        self.primary_provider = primary_provider
        self.fallback_providers = fallback_providers or []
        self.provider_config = provider_config
        self.active_provider: Optional[LLMProvider] = None
        self.governor: Optional[Any] = None

    async def initialize(self):
        logger.info(f"[HARNESS] Initializing {self.primary_provider.value}...")

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

        self.active_provider = self._create_provider(self.primary_provider)
        if await self.active_provider.is_available():
            logger.info(f"✓ Using {self.primary_provider.value}")
            return

        logger.warning(f"✗ {self.primary_provider.value} unavailable, trying fallbacks...")

        for fb in self.fallback_providers:
            logger.info(f"[HARNESS] Trying {fb.value}...")
            self.active_provider = self._create_provider(fb)
            if await self.active_provider.is_available():
                logger.info(f"✓ Using {fb.value}")
                return
            logger.warning(f"✗ {fb.value} unavailable")

        raise RuntimeError("No LLM provider available!")

    def _create_provider(self, provider_type: ProviderType) -> LLMProvider:
        if provider_type == ProviderType.BEDROCK:
            from agents.providers.bedrock_provider import BedrockProvider
            return BedrockProvider(
                small_model=self.provider_config.get(
                    "aws_bedrock_small_model", os.getenv("AWS_BEDROCK_SMALL_MODEL",
                                                         "us.anthropic.claude-haiku-4-5-20251001-v1:0")),
                large_model=self.provider_config.get(
                    "aws_bedrock_large_model", os.getenv("AWS_BEDROCK_LARGE_MODEL",
                                                         "us.anthropic.claude-sonnet-4-20250514-v1:0")),
                region=self.provider_config.get("aws_region", os.getenv("AWS_REGION", "us-west-2")),
                budget=self.budget,
            )
        if provider_type == ProviderType.CLAUDE_CLI:
            from agents.providers.claude_cli_provider import ClaudeCLIProvider
            return ClaudeCLIProvider(
                small_model=self.provider_config.get(
                    "cli_small_model", os.getenv("CLAUDE_CLI_SMALL_MODEL", "haiku")),
                large_model=self.provider_config.get(
                    "cli_large_model", os.getenv("CLAUDE_CLI_LARGE_MODEL", "sonnet")),
                bin_path=self.provider_config.get("cli_bin", os.getenv("CLAUDE_CLI_BIN", "")),
                budget=self.budget,
            )
        if provider_type == ProviderType.DEEPSEEK:
            from agents.providers.deepseek_provider import DeepSeekProvider
            return DeepSeekProvider(
                small_model=self.provider_config.get(
                    "deepseek_small_model", os.getenv("DEEPSEEK_SMALL_MODEL", "deepseek-chat")),
                large_model=self.provider_config.get(
                    "deepseek_large_model", os.getenv("DEEPSEEK_LARGE_MODEL", "deepseek-chat")),
                api_key=self.provider_config.get("deepseek_api_key", os.getenv("DEEPSEEK_API_KEY", "")),
                base_url=self.provider_config.get("deepseek_base_url", os.getenv("DEEPSEEK_BASE_URL", "")),
                budget=self.budget,
            )
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
        if not self.active_provider:
            await self.initialize()

        system = await self._inject_rag_context(prompt, system)

        try:
            from core.utils.scan_flags import redact_llm_context
            if redact_llm_context():
                from core.security.llm_redact import redact_for_llm
                prompt = redact_for_llm(prompt)
                system = redact_for_llm(system)
        except Exception:
            pass

        if self.governor is not None:
            model_hint = self.active_provider.get_model_for_tier(tier) if self.active_provider else ""
            if not self.governor.allow_request(max_tokens, self.primary_provider.value, model_hint):
                return LLMResponse(content="", provider=self.primary_provider.value,
                                   model=model_hint, error="Budget governor: hard stop reached")
            tier = self.governor.adjust_tier(tier)

        _model_hint = self.active_provider.get_model_for_tier(tier) if self.active_provider else ""

        _cache = None
        if os.getenv("ANTIGRAVITY_LLM_CACHE") == "1":
            try:
                from core.llm.response_cache import get_response_cache
                _cache = get_response_cache()
                cached = _cache.get(prompt, model=_model_hint, system=system or "")
                if cached is not None:
                    return cached
            except Exception:
                _cache = None

        resp = await self.active_provider.generate_response(
            prompt, system, max_tokens, temperature, response_format, tier
        )

        if resp.error and self._is_fatal_provider_error(resp.error):
            fallback = await self._try_fallback_provider(resp.error)
            if fallback:
                resp = await self.active_provider.generate_response(
                    prompt, system, max_tokens, temperature, response_format, tier
                )

        try:
            sid = os.getenv("ANTIGRAVITY_SCAN_ID", "")
            if sid and resp is not None and not resp.error:
                from core.economics.cost_log import get_cost_log
                _u = resp.usage or {}
                get_cost_log().record(
                    sid, resp.provider, resp.model,
                    input_tokens=int(_u.get("input_tokens", 0) or 0),
                    output_tokens=int(_u.get("output_tokens", 0) or 0),
                    cost_usd=float(resp.cost_usd or 0.0))
        except Exception:
            pass

        if _cache is not None and resp is not None and not resp.error:
            try:
                _cache.set(prompt, resp, model=_model_hint, system=system or "")
            except Exception:
                pass

        return resp

    def _is_fatal_provider_error(self, error: str) -> bool:
        import re as _re
        err = str(error or "")
        if "402" in err or "Insufficient Balance" in err or "Payment Required" in err:
            return True
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
        resp = await self.generate_response(prompt, system, max_tokens, tier=tier)
        return resp.content if not resp.error else ""

    def supports_native_tools(self) -> bool:
        """Whether the active provider+model can drive the native agentic tool
        loop. False → callers use the JSON-planner path (works for any model)."""
        p = self.active_provider
        if p is None:
            return False
        fn = getattr(p, "supports_native_tools", None)
        try:
            return bool(fn()) if callable(fn) else False
        except Exception:
            return False

    async def generate_json(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: int = 4096,  # 2048 truncated large synth/verify JSON -> unparseable {} (fenced but cut mid-object)
        mandatory_fields: Optional[List[str]] = None,
        tier: TaskTier = TaskTier.SMALL
    ) -> Dict[str, Any]:
        # `mandatory_fields`: callers may name keys that must appear in the JSON.
        # We nudge the model with a one-line hint; callers still validate the
        # result themselves, so this is advisory (kept for signature parity).
        if mandatory_fields:
            hint = "Include these keys: " + ", ".join(mandatory_fields) + "."
            system = f"{system}\n{hint}" if system else hint
        resp = await self.generate_response(
            prompt, system, max_tokens, 0.1, "json", tier
        )
        # A provider error (429/timeout/subprocess) leaves content empty; surface it
        # instead of silently returning {} (callers otherwise fall back blind).
        if resp.error:
            logger.error("[JSON] request failed: %s", resp.error)
            return {}
        if resp.structured_output:
            return resp.structured_output
        if resp.content:
            try:
                from core.llm.json_enforcer import parse_with_repair
                parsed, _method = parse_with_repair(resp.content)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
        logger.warning("[JSON] unparseable content -> {} (len=%d head=%r)",
                       len(resp.content or ""), (resp.content or "")[:200])
        return {}

    async def generate_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        tool_executor: Optional[Any] = None,
        max_tokens: int = 4096,
        tier: TaskTier = TaskTier.LARGE,
        max_rounds: int = 10,
    ) -> LLMResponse:
        if not self.active_provider:
            await self.initialize()
        if self.governor is not None:
            if not self.governor.allow_request(max_tokens, self.primary_provider.value):
                return LLMResponse(content="", provider=self.primary_provider.value,
                                   error="Budget governor: hard stop reached")
            tier = self.governor.adjust_tier(tier)
        try:
            from core.utils.scan_flags import redact_llm_context
            if redact_llm_context():
                from core.security.llm_redact import redact_messages
                messages = redact_messages(messages)
        except Exception:
            pass
        if hasattr(self.active_provider, 'generate_with_tools'):
            resp = await self.active_provider.generate_with_tools(
                messages, tools, max_tokens=max_tokens, tier=tier,
                tool_executor=tool_executor, max_rounds=max_rounds,
            )
            if resp.error and self._is_fatal_provider_error(resp.error):
                if await self._try_fallback_provider(resp.error):
                    if hasattr(self.active_provider, 'generate_with_tools'):
                        return await self.active_provider.generate_with_tools(
                            messages, tools, max_tokens=max_tokens, tier=tier,
                            tool_executor=tool_executor, max_rounds=max_rounds,
                        )
            return resp
        return LLMResponse(content="", error="Tool calling not supported on this provider")

    def count_tokens(self, text: str) -> int:
        if hasattr(self.active_provider, 'count_tokens'):
            return self.active_provider.count_tokens(text)
        tok = _get_claude_tokenizer()
        if tok:
            return len(tok.encode(text))
        return max(1, len(text) // 4)

    def stats(self) -> Dict[str, Any]:
        return self.budget.stats()

    async def _inject_rag_context(self, prompt: str, system: Optional[str]) -> Optional[str]:
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
        if self.active_provider and self.active_provider.session:
            await self.active_provider.session.aclose()


def get_llm_client():
    """Back-compat accessor used by several modules
    (``from agents.universal_llm_harness import get_llm_client``). Returns the
    shared harness instance created by the adapter. Lazy import avoids a circular
    import (the adapter imports this module)."""
    from agents.llm_harness_adapter import get_llm
    return get_llm()


async def demo():
    harness = UniversalLLMHarness(
        primary_provider=ProviderType.BEDROCK,
        max_budget_usd=50.0,
    )

    try:
        await harness.initialize()

        text = await harness.generate_text("What is cybersecurity?", max_tokens=256)
        print(f"[TEXT]\n{text}\n")

        json_resp = await harness.generate_json(
            "List 3 security vulnerabilities in JSON format",
            max_tokens=512
        )
        print(f"[JSON]\n{json.dumps(json_resp, indent=2)}\n")

        print(f"[STATS]\n{json.dumps(harness.stats(), indent=2)}")

    finally:
        await harness.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(demo())
