"""Phase 8.1 — LLM response caching."""
from __future__ import annotations

from core.llm.response_cache import LLMResponseCache, cache_key, normalize_prompt


def test_normalize_collapses_instance_values():
    a = normalize_prompt("Test SQLi on https://x/api/products/1?id=1")
    b = normalize_prompt("Test SQLi on https://x/api/products/2?id=2")
    assert a == b  # instance-specific ids stripped → same template


def test_cache_key_stable_across_instances():
    k1 = cache_key("probe /users/1 for IDOR", "deepseek")
    k2 = cache_key("probe /users/999 for IDOR", "deepseek")
    assert k1 == k2
    # Different model → different key.
    assert cache_key("probe /users/1", "deepseek") != cache_key("probe /users/1", "bedrock")


def test_cache_hit_and_miss_and_stats():
    cache = LLMResponseCache()
    assert cache.get("SQLi on /a/1") is None          # miss
    cache.set("SQLi on /a/1", {"vuln": True})
    assert cache.get("SQLi on /a/2") == {"vuln": True}  # hit (same template)
    assert cache.stats.hits == 1
    assert cache.stats.misses == 1
    assert cache.stats.hit_rate == 0.5
    assert cache.stats.tokens_saved > 0


def test_ttl_expiry():
    clock = {"t": 1000.0}
    cache = LLMResponseCache(ttl_seconds=10, now=lambda: clock["t"])
    cache.set("p /1", "resp")
    clock["t"] = 1005.0
    assert cache.get("p /2") == "resp"      # within TTL
    clock["t"] = 1020.0
    assert cache.get("p /3") is None        # expired


def test_get_or_call_invokes_producer_once():
    cache = LLMResponseCache()
    calls = []

    def producer():
        calls.append(1)
        return "computed"

    assert cache.get_or_call("test /1", producer) == "computed"
    assert cache.get_or_call("test /2", producer) == "computed"  # served from cache
    assert len(calls) == 1


def test_persist_hook():
    persisted = []
    cache = LLMResponseCache(persist=lambda k, v: persisted.append((k, v)))
    cache.set("p", "r")
    assert len(persisted) == 1
