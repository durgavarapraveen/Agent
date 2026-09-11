"""Phase 9.3 — hybrid local + cloud routing.

Route SMALL-tier tasks to a fast free local model (Ollama) and LARGE-tier tasks
to a higher-quality cloud model (Bedrock/API). Auto-detect Ollama: if it is not
running, SMALL falls back to the cloud provider too.

Config: ``LLM_SMALL_PROVIDER=ollama``, ``LLM_LARGE_PROVIDER=bedrock``.

The Ollama health check is injectable, so routing is testable with no network.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Awaitable, Callable, Optional

logger = logging.getLogger(__name__)

# TaskTier import is light; guard so this module imports even if the harness
# import graph is being edited.
try:
    from core.common.schemas import TaskTier
except Exception:  # pragma: no cover
    TaskTier = None  # type: ignore


async def _default_ollama_check(base_url: str) -> bool:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=2) as c:
            r = await c.get(f"{base_url.rstrip('/')}/api/tags")
            return r.status_code == 200
    except Exception:
        return False


class HybridRouter:

    def __init__(self, small_provider: str = "ollama", large_provider: str = "bedrock",
                 cloud_fallback: str = "deepseek", ollama_base_url: str = "http://localhost:11434",
                 ollama_checker: Optional[Callable[[str], Awaitable[bool]]] = None):
        self.small_provider = small_provider
        self.large_provider = large_provider
        self.cloud_fallback = cloud_fallback
        self.ollama_base_url = ollama_base_url
        self._ollama_checker = ollama_checker or _default_ollama_check
        self._ollama_ok: Optional[bool] = None

    @classmethod
    def from_env(cls) -> "HybridRouter":
        return cls(
            small_provider=os.getenv("LLM_SMALL_PROVIDER", "ollama"),
            large_provider=os.getenv("LLM_LARGE_PROVIDER", "bedrock"),
            cloud_fallback=os.getenv("LLM_CLOUD_FALLBACK", "deepseek"),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        )

    async def ollama_available(self, refresh: bool = False) -> bool:
        if self._ollama_ok is None or refresh:
            self._ollama_ok = await self._ollama_checker(self.ollama_base_url)
            if not self._ollama_ok:
                logger.info("hybrid_router: Ollama not reachable at %s — SMALL tasks "
                            "will use cloud fallback '%s'", self.ollama_base_url, self.cloud_fallback)
        return self._ollama_ok

    def _is_small(self, tier: Any) -> bool:
        if TaskTier is not None and isinstance(tier, TaskTier):
            return tier == TaskTier.SMALL
        return str(getattr(tier, "value", tier)).lower() in ("small", "s")

    async def route(self, tier: Any) -> str:
        """Return the provider name to use for a task tier."""
        if not self._is_small(tier):
            return self.large_provider
        # SMALL tier → prefer local Ollama, fall back to cloud if it is down.
        if self.small_provider == "ollama" and not await self.ollama_available():
            return self.cloud_fallback
        return self.small_provider
