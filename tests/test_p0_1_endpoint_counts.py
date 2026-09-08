"""P0.1 regression tests — endpoint count invariants & canonical identity.

Reproduces the log corruption (deduplicated 5173 > input 1265, transferred_to_v2
collapsing to 1-3) and proves it can no longer occur.
"""
import pytest

from core.domain.endpoint import Endpoint
from core.attack_surface.attack_surface_state import AttackSurfaceState


def _ep(method, url, path, host="app.test", scheme="https", port=443, eid=""):
    return Endpoint(endpoint_id=eid, url=url, path=path, method_set=[method],
                    host=host, scheme=scheme, port=port)


def test_canonical_id_stable_and_query_blind_path_norm():
    a = _ep("GET", "https://app.test/a", "/a")
    b = _ep("GET", "https://APP.test/a/", "/a/")   # case + trailing slash
    assert a.canonical_id() == b.canonical_id()
    assert a.normalized_key() == b.normalized_key()


def test_canonical_id_distinguishes_method_and_path():
    assert _ep("GET", "u", "/a").canonical_id() != _ep("POST", "u", "/a").canonical_id()
    assert _ep("GET", "u", "/a").canonical_id() != _ep("GET", "u", "/b").canonical_id()


def test_deduplicated_never_exceeds_input():
    surf = AttackSurfaceState("app.test")
    # 1265 unique endpoints, each fed 4 times across redundant feed paths.
    unique_n = 1265
    for _ in range(4):
        for i in range(unique_n):
            surf.add_endpoint(_ep("GET", f"https://app.test/p{i}", f"/p{i}"),
                              source="recon")
    c = surf.summary()["counts"]
    assert c["endpoints_unique"] == unique_n
    assert c["endpoints_raw_fed"] == unique_n * 4
    # The number that used to read 5173: deduplicated == removed duplicates.
    assert c["endpoints_deduplicated"] == unique_n * 4 - unique_n
    assert c["endpoints_deduplicated"] < c["endpoints_raw_fed"]     # never exceeds input
    assert surf.assert_endpoint_invariants() is True


def test_transferred_to_v2_reflects_actual_surface_not_last_delta():
    surf = AttackSurfaceState("app.test")
    for i in range(100):
        surf.add_endpoint(_ep("GET", f"https://app.test/p{i}", f"/p{i}"), source="recon")
    surf.mark_transferred_to_v2(new_endpoints=100, parameters=0)
    # Second wire pass finds everything already present -> new delta is small...
    for i in range(100):
        surf.add_endpoint(_ep("GET", f"https://app.test/p{i}", f"/p{i}"), source="recon2")
    surf.mark_transferred_to_v2(new_endpoints=0, parameters=0)
    c = surf.summary()["counts"]
    # ...but transferred_to_v2 must stay at the real surface size, not collapse to 0/1/3.
    assert c["endpoints_transferred_to_v2"] == 100
    assert c["endpoints_new_last_transfer"] == 0


def test_invariant_holds_with_mixed_ids():
    surf = AttackSurfaceState("app.test")
    # Feed with random-looking ids and empty ids — canonical id should dedup them.
    surf.add_endpoint(_ep("GET", "https://app.test/x", "/x", eid=""), source="a")
    surf.add_endpoint(_ep("GET", "https://app.test/x", "/x",
                          eid="123e4567-e89b-12d3-a456-426614174000"), source="b")
    assert len(surf.endpoints) == 1               # deduped despite different input ids
    assert surf.assert_endpoint_invariants() is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
