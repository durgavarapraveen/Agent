"""P3 — single-source endpoint store contract.

The endpoint store on SharedContextV2 is a canonical-id -> record DICT. Several
call sites used to reassign it to a bare list (target_memory liveness sweep,
js_bundle_analyzer fallback) or iterate it as records when it yields id KEYS
(DB persistence), so the report store and the DB store could silently disagree.
These lock the contract: one ingestion funnel (add_endpoints), one read path
(get_endpoints -> records), dict-preserving mutators for reset/prune.
"""
import pytest

from core.memory.shared_context import SharedContextV2
from core.security.authorization import TargetScopeValidator


@pytest.fixture(autouse=True)
def _scope():
    prev = TargetScopeValidator._instance
    TargetScopeValidator.set(TargetScopeValidator(["example.com"]))
    yield
    TargetScopeValidator._instance = prev


def _ctx():
    c = SharedContextV2("https://example.com", {"domains": ["example.com"]})
    c.add_endpoints([
        {"url": "https://example.com/a", "method": "GET"},
        {"url": "https://example.com/b", "method": "GET"},
        {"url": "https://example.com/c", "method": "GET"},
    ], source="crawl")
    return c


def test_store_is_dict_and_getter_yields_records_not_keys():
    c = _ctx()
    assert isinstance(c.endpoints, dict)
    recs = c.get_endpoints()
    # The DB-persistence regression: iterating the getter must yield RECORDS whose
    # url is a real URL, never the canonical-id key "GET:https://...".
    for r in recs:
        url = r if isinstance(r, str) else r.get("url")
        assert url and url.startswith("http")
        assert not url.startswith("GET:")


def test_clear_endpoints_keeps_dict_contract():
    c = _ctx()
    c.clear_endpoints()
    assert c.endpoints == {} and isinstance(c.endpoints, dict)
    # Funnel still works after a reset (would raise if store became a list).
    c.add_endpoints([{"url": "https://example.com/x", "method": "GET"}], source="crawl")
    assert len(c.get_endpoints()) == 1


def test_drop_endpoints_by_url_prunes_and_returns_count():
    c = _ctx()
    removed = c.drop_endpoints_by_url({"https://example.com/b"})
    assert removed == 1
    assert isinstance(c.endpoints, dict)
    urls = {e["url"] for e in c.get_endpoints()}
    assert urls == {"https://example.com/a", "https://example.com/c"}
    # Idempotent + no-op on empty.
    assert c.drop_endpoints_by_url(set()) == 0
    assert c.drop_endpoints_by_url({"https://example.com/b"}) == 0


def test_canonical_dedup_survives_prune_and_readd():
    c = _ctx()
    c.drop_endpoints_by_url({"https://example.com/a"})
    # Re-adding a duplicate spelling of a surviving endpoint must still dedup.
    c.add_endpoints([{"url": "https://EXAMPLE.com/c/", "method": "GET"}], source="crawl")
    urls = [e["url"] for e in c.get_endpoints()]
    assert sum(1 for u in urls if "/c" in u) == 1


def test_liveness_helper_roundtrip_matches_target_memory_usage():
    # Mirror the target_memory liveness sweep: collect live urls via the getter,
    # drop the dead set through the mutator, store stays a usable dict.
    c = _ctx()
    live_urls = [e["url"] for e in c.get_endpoints()]
    dead = {live_urls[0]}
    c.drop_endpoints_by_url(dead)
    assert dead.isdisjoint({e["url"] for e in c.get_endpoints()})
    assert isinstance(c.endpoints, dict)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
