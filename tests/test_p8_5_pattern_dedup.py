"""Phase 8.5 — pattern-based endpoint dedup (route_normalizer)."""
from __future__ import annotations

from core.attack_surface.route_normalizer import RouteNormalizer


def _rest_endpoints():
    eps = [{"url": f"https://x/api/products/{i}", "method": "GET"} for i in range(1, 11)]
    eps += [{"url": f"https://x/api/users/{i}/orders", "method": "GET"} for i in range(1, 6)]
    eps += [{"url": "https://x/login", "method": "POST"}]
    return eps


def test_pattern_key():
    assert RouteNormalizer.pattern_key("https://x/api/products/42", "GET") == "GET /api/products/{id}"


def test_group_by_pattern():
    groups = RouteNormalizer.group_by_pattern(_rest_endpoints())
    assert len(groups) == 3
    assert len(groups["GET /api/products/{id}"]) == 10


def test_representatives_reduces_work():
    reps = RouteNormalizer.representatives(_rest_endpoints(), per_pattern=1)
    # 16 endpoints → 3 representatives (one per pattern).
    assert len(reps) == 3


def test_representatives_two_per_pattern():
    reps = RouteNormalizer.representatives(_rest_endpoints(), per_pattern=2)
    # products(10)→2, users/orders(5)→2, login(1)→1  = 5
    assert len(reps) == 5


def test_coverage_map():
    cov = RouteNormalizer.coverage_map(_rest_endpoints(), per_pattern=1)
    prod = cov["GET /api/products/{id}"]
    assert prod["total"] == 10
    assert prod["tested"] == 1
    assert prod["covered_by_pattern"] == 9
