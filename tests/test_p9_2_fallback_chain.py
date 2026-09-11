"""Phase 9.2 — provider fallback chain."""
from __future__ import annotations

import os
from unittest import mock

from agents.providers.fallback_chain import FallbackChain


class _Resp:
    def __init__(self, content="ok", error=None):
        self.content = content
        self.error = error


class _Provider:
    def __init__(self, name, behavior):
        self.name = name
        self.behavior = behavior  # "ok" | "error" | "raise"

    async def generate_response(self, *a, **k):
        if self.behavior == "raise":
            raise RuntimeError(f"{self.name} down")
        if self.behavior == "error":
            return _Resp(error=f"{self.name} error")
        return _Resp(content=f"{self.name} response")


def _factory(behaviors):
    return lambda name: _Provider(name, behaviors.get(name, "ok"))


async def test_uses_primary_when_ok():
    chain = FallbackChain(["ollama", "bedrock"], _factory({}))
    result = await chain.generate("prompt")
    assert result.succeeded
    assert result.provider_used == "ollama"
    assert len(result.attempts) == 1


async def test_falls_back_on_error():
    chain = FallbackChain(["ollama", "bedrock", "deepseek"],
                          _factory({"ollama": "error", "bedrock": "raise"}))
    result = await chain.generate("prompt")
    assert result.succeeded
    assert result.provider_used == "deepseek"
    assert len(result.attempts) == 3
    assert result.attempts[0].ok is False
    assert result.attempts[1].ok is False
    assert result.attempts[2].ok is True


async def test_all_fail():
    chain = FallbackChain(["a", "b"], _factory({"a": "raise", "b": "error"}))
    result = await chain.generate("prompt")
    assert not result.succeeded
    assert result.response is None
    assert len(result.attempts) == 2


async def test_factory_creation_failure_skipped():
    def factory(name):
        if name == "broken":
            raise ValueError("no config")
        return _Provider(name, "ok")

    chain = FallbackChain(["broken", "ollama"], factory)
    result = await chain.generate("prompt")
    assert result.provider_used == "ollama"


def test_from_env():
    with mock.patch.dict(os.environ, {"LLM_FALLBACK_CHAIN": "ollama, bedrock ,deepseek"}):
        chain = FallbackChain.from_env(_factory({}))
    assert chain.providers == ["ollama", "bedrock", "deepseek"]
