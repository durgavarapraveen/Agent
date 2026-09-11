"""Phase 6.3 — parallel domain-specialist swarm."""
from __future__ import annotations

from core.orchestration.specialist_coordinator import (
    SpecialistCoordinator,
    assign_endpoints,
)


def _endpoints():
    return [
        {"url": "https://app.test/login", "method": "POST"},
        {"url": "https://app.test/api/cart", "method": "POST", "params": ["price"]},
        {"url": "https://app.test/api/products", "method": "GET"},
        {"url": "https://app.test/search?q=x", "method": "GET"},
    ]


def test_assign_routes_to_specialists():
    a = assign_endpoints(_endpoints())
    # login → auth
    assert any("login" in _url(e) for e in a.get("auth", []))
    # /api/cart → api + business_logic + injection (POST w/ params)
    assert any("cart" in _url(e) for e in a.get("business_logic", []))
    assert any("cart" in _url(e) for e in a.get("api", []))
    assert any("cart" in _url(e) for e in a.get("injection", []))
    # /search?q=x → injection (has query params)
    assert any("search" in _url(e) for e in a.get("injection", []))


def _url(e):
    return e.get("url", "") if isinstance(e, dict) else getattr(e, "url", "")


def test_assign_dedups_within_specialist():
    eps = [{"url": "https://app.test/api/users/1", "method": "GET"},
           {"url": "https://app.test/api/users/2", "method": "GET"}]  # same normalized route
    a = assign_endpoints(eps)
    # Both normalize to "GET /api/users/{id}" → api specialist gets it once.
    assert len(a.get("api", [])) == 1


async def test_coordinator_runs_specialists_and_dedups_feed():
    ran = []

    async def runner(specialist, endpoints):
        ran.append(specialist)
        # Each specialist reports one finding; auth + injection both report the
        # same duplicate finding to test the shared-feed dedup.
        if specialist in ("auth", "injection"):
            return [{"type": "dup", "url": "https://app.test/login"}]
        return [{"type": specialist, "url": endpoints[0].get("url") if endpoints else ""}]

    coord = SpecialistCoordinator(runner=runner)
    result = await coord.run(_endpoints())

    assert set(ran) == set(result.specialists_run)
    assert len(ran) >= 3  # auth, injection, business_logic, api all engaged
    # The duplicate finding reported by two specialists is collapsed to one.
    dup_findings = [f for f in result.findings if f["type"] == "dup"]
    assert len(dup_findings) == 1
    assert result.duplicates_dropped >= 1


async def test_coordinator_empty_endpoints():
    async def runner(s, e):
        return []
    result = await SpecialistCoordinator(runner=runner).run([])
    assert result.findings == [] and result.assignments == {}


async def test_specialist_failure_isolated():
    async def runner(specialist, endpoints):
        if specialist == "injection":
            raise RuntimeError("boom")
        return [{"type": specialist, "url": "u"}]

    result = await SpecialistCoordinator(runner=runner).run(_endpoints())
    # Injection failed but others still produced findings.
    assert "injection" not in result.specialists_run
    assert len(result.findings) >= 1
