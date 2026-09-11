"""Phase 9.3 — hybrid local + cloud routing."""
from __future__ import annotations

import os
from unittest import mock

from agents.providers.hybrid_router import HybridRouter
from core.common.schemas import TaskTier


async def test_large_tier_goes_to_cloud():
    router = HybridRouter(small_provider="ollama", large_provider="bedrock",
                          ollama_checker=lambda url: _async(True))
    assert await router.route(TaskTier.LARGE) == "bedrock"


async def test_small_tier_uses_ollama_when_up():
    router = HybridRouter(small_provider="ollama", large_provider="bedrock",
                          ollama_checker=lambda url: _async(True))
    assert await router.route(TaskTier.SMALL) == "ollama"


async def test_small_tier_falls_back_when_ollama_down():
    router = HybridRouter(small_provider="ollama", large_provider="bedrock",
                          cloud_fallback="deepseek",
                          ollama_checker=lambda url: _async(False))
    assert await router.route(TaskTier.SMALL) == "deepseek"


async def test_ollama_health_cached():
    calls = {"n": 0}

    async def checker(url):
        calls["n"] += 1
        return True

    router = HybridRouter(ollama_checker=checker)
    await router.ollama_available()
    await router.ollama_available()
    assert calls["n"] == 1               # cached
    await router.ollama_available(refresh=True)
    assert calls["n"] == 2               # forced refresh


async def test_non_ollama_small_provider_not_health_checked():
    called = {"n": 0}

    async def checker(url):
        called["n"] += 1
        return False

    router = HybridRouter(small_provider="deepseek", large_provider="bedrock",
                          ollama_checker=checker)
    assert await router.route(TaskTier.SMALL) == "deepseek"
    assert called["n"] == 0              # no ollama check when small isn't ollama


def test_from_env():
    with mock.patch.dict(os.environ, {"LLM_SMALL_PROVIDER": "ollama",
                                      "LLM_LARGE_PROVIDER": "bedrock"}):
        router = HybridRouter.from_env()
    assert router.small_provider == "ollama"
    assert router.large_provider == "bedrock"


def _async(value):
    async def _coro():
        return value
    return _coro()
