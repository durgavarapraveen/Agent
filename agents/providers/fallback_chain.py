"""Phase 9.2 — provider fallback chain.

An ordered list of providers; if the primary fails (timeout, rate limit, down),
automatically fall through to the next. Every fallback is logged with the reason.

Config: ``LLM_FALLBACK_CHAIN=ollama,bedrock,deepseek``.

Complements the model-level fallback in ``core.llm.model_routing`` (this operates
at the provider level). Providers are created by an injectable ``factory``, so
this is testable with fakes and no network.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable, List

logger = logging.getLogger(__name__)


@dataclass
class FallbackAttempt:
    provider: str
    ok: bool
    error: str = ""


@dataclass
class ChainResult:
    response: Any = None
    provider_used: str = ""
    attempts: List[FallbackAttempt] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.response is not None and not getattr(self.response, "error", None)


class FallbackChain:

    def __init__(self, providers: List[str], factory: Callable[[str], Any]):
        self.providers = [p.strip() for p in providers if p and p.strip()]
        self.factory = factory

    @classmethod
    def from_env(cls, factory: Callable[[str], Any], default: str = "deepseek") -> "FallbackChain":
        chain = os.getenv("LLM_FALLBACK_CHAIN", default)
        return cls([p for p in chain.split(",")], factory)

    async def generate(self, *args, **kwargs) -> ChainResult:
        result = ChainResult()
        for name in self.providers:
            try:
                provider = self.factory(name)
            except Exception as e:
                logger.warning("fallback_chain: cannot create '%s' (%s); trying next", name, e)
                result.attempts.append(FallbackAttempt(name, False, f"create failed: {e}"))
                continue
            try:
                resp = await provider.generate_response(*args, **kwargs)
            except Exception as e:
                logger.warning("fallback_chain: '%s' raised (%s); falling back", name, e)
                result.attempts.append(FallbackAttempt(name, False, str(e)))
                continue
            if resp is None or getattr(resp, "error", None):
                err = getattr(resp, "error", "empty response")
                logger.warning("fallback_chain: '%s' returned error (%s); falling back", name, err)
                result.attempts.append(FallbackAttempt(name, False, str(err)))
                continue
            result.attempts.append(FallbackAttempt(name, True))
            result.response = resp
            result.provider_used = name
            if len(result.attempts) > 1:
                logger.info("fallback_chain: succeeded on '%s' after %d fallback(s)",
                            name, len(result.attempts) - 1)
            return result
        logger.error("fallback_chain: all %d providers failed", len(self.providers))
        return result
