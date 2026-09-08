"""P3 Phase B — one canonical endpoint identity across ALL stores.

EndpointInventoryV2 (the projection feeding SecurityContextV2) used to dedup by
raw ``method:url`` and AttackSurfaceGraph by whatever ``endpoint_id`` a feed
happened to carry, so both could report a different unique endpoint count than
the authoritative stores for the same URLs under trivial spelling differences.
These lock every store to the single ``canonical_endpoint_key`` / ``canonical_id``.
"""
import pytest

from core.domain.endpoint import Endpoint, canonical_endpoint_key
from core.memory.shared_context import SharedContextV2
from core.attack_surface.endpoint_inventory import EndpointInventoryV2
from core.attack_surface.graph import AttackSurfaceGraph
from core.attack_surface.attack_surface_state import AttackSurfaceState


def _ep(url="https://h/a", path="/a", method="GET", endpoint_id=""):
    return Endpoint(endpoint_id=endpoint_id, url=url, path=path,
                    method_set=[method], scheme="https", host="h", port=443)


def test_single_identity_function_shared():
    # SharedContextV2 now delegates to the one canonical_endpoint_key.
    assert (SharedContextV2.canonical_endpoint_id("GET", "https://h/a")
            == canonical_endpoint_key("GET", "https://h/a"))
    # Spelling variants collapse.
    assert (canonical_endpoint_key("get", "https://H/a/?b=1&a=2")
            == canonical_endpoint_key("GET", "https://h/a?a=2&b=1"))


def test_inventory_canonical_dedup():
    inv = EndpointInventoryV2()
    inv.add_endpoint({"url": "https://H/a/", "method": "get"})
    inv.add_endpoint({"url": "https://h/a", "method": "GET"})
    inv.add_endpoint({"url": "https://h/a?a=2&b=1", "method": "GET"})
    inv.add_endpoint({"url": "https://h/a?b=1&a=2", "method": "GET"})
    # /a and /a/ are one; the two query orderings are one (distinct from /a).
    assert len(inv.list_endpoints()) == 2


def test_graph_canonicalizes_endpoint_id():
    g = AttackSurfaceGraph()
    g.add_endpoint(_ep(endpoint_id=""))                                   # empty id
    g.add_endpoint(_ep(endpoint_id="123e4567-e89b-12d3-a456-426614174000"))  # uuid id, same URL
    # Both resolve to the same canonical id -> one node, not two.
    assert len(g.endpoints) == 1
    (only_id,) = list(g.endpoints)
    assert only_id.startswith("ep_")


def test_graph_and_surface_counts_agree():
    feed = [_ep(url="https://h/a", path="/a"),
            _ep(url="https://h/a/", path="/a/"),      # dup spelling
            _ep(url="https://h/b", path="/b"),
            _ep(url="https://h/b", path="/b", endpoint_id="")]  # dup
    g = AttackSurfaceGraph()
    s = AttackSurfaceState("https://h")
    for e in feed:
        g.add_endpoint(_ep(url=e.url, path=e.path, endpoint_id=e.endpoint_id))
        s.add_endpoint(_ep(url=e.url, path=e.path, endpoint_id=e.endpoint_id))
    # Both stores dedup to the same {/a, /b} == 2 by the shared canonical id.
    assert len(g.endpoints) == 2
    assert len(s.endpoints) == 2
    assert set(g.endpoints) == set(s.endpoints)


def test_stable_ids_are_not_overwritten():
    g = AttackSurfaceGraph()
    g.add_endpoint(_ep(endpoint_id="operator-assigned-stable"))
    assert "operator-assigned-stable" in g.endpoints


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
