"""Phase 8.7 — prompt compression & system-prompt caching."""
from __future__ import annotations

from core.llm.prompt_compression import (
    PromptCompressor,
    cache_control_for,
    compress_executor_prompt,
    measure_prompt,
    strip_redundant_whitespace,
    supports_prompt_caching,
)


def test_measure_prompt():
    m = measure_prompt("hello world\nsecond line")
    assert m["chars"] == len("hello world\nsecond line")
    assert m["est_tokens"] >= 1
    assert m["lines"] == 2


def test_supports_prompt_caching():
    assert supports_prompt_caching("anthropic")
    assert supports_prompt_caching("bedrock")
    assert not supports_prompt_caching("ollama")


def test_cache_control_anthropic_large_prompt():
    big = "x" * 3000
    cc = cache_control_for("anthropic", big)
    assert cc == {"type": "ephemeral"}
    # Too small → no caching.
    assert cache_control_for("anthropic", "short") is None
    # Unsupported provider → None.
    assert cache_control_for("ollama", big) is None


def test_compress_executor_prompt_only_relevant_fields():
    out = compress_executor_prompt(
        "Test the endpoint for SQLi.",
        {"url": "https://x/api", "param": "id", "empty": "", "none": None})
    assert "url: https://x/api" in out
    assert "param: id" in out
    assert "empty" not in out and "none" not in out


def test_strip_redundant_whitespace():
    assert strip_redundant_whitespace("a   \n\n\n\nb") == "a\n\nb"


def test_compressor_system_block_and_savings():
    comp = PromptCompressor(provider="anthropic")
    big = "SYSTEM PROMPT " * 200  # > 2000 chars
    block = comp.system_block(big)
    assert block["cache_control"] == {"type": "ephemeral"}
    savings = comp.estimate_savings(big, calls=80)
    assert savings["cacheable"] is True
    assert savings["est_tokens_saved"] > 0


def test_no_savings_for_local_provider():
    comp = PromptCompressor(provider="ollama")
    savings = comp.estimate_savings("x" * 3000, calls=80)
    assert savings["cacheable"] is False
    assert savings["est_tokens_saved"] == 0
