"""Deterministic end-to-end regression for the data-flow spine.

No network, no LLM, no live tools: fake tool outputs are threaded through the
REAL SharedContextV2 / AttackSurfaceState / correlation / mutation / redaction
modules to simulate a full RECON -> ACTIVE_SCANNING -> EXPLOITATION -> REPORTING
run. It asserts the cross-module invariants the P0/P1 sprints established, so a
future refactor (e.g. P3 storage consolidation) that breaks the spine fails
here loudly instead of silently regressing a live scan.

Authorized host is example.com (the process-default scope); seeded explicitly
so the test is self-contained and order-independent.
"""
import asyncio

import pytest

from core.memory.shared_context import SharedContextV2
from core.attack_surface.attack_surface_state import AttackSurfaceState
from core.domain.endpoint import Endpoint
from core.analysis.correlation_engine import CorrelationEngine
from core.security.mutation_ledger import get_ledger
from core.security.llm_redact import redact_for_llm
from core.security.authorization import TargetScopeValidator


@pytest.fixture(autouse=True)
def _scope():
    prev = TargetScopeValidator._instance
    TargetScopeValidator.set(TargetScopeValidator(["example.com"]))
    yield
    TargetScopeValidator._instance = prev


def _ep(url, path, method="GET"):
    return Endpoint(endpoint_id="", url=url, path=path, method_set=[method],
                    scheme="https", host="example.com", port=443)


def test_full_pipeline_spine():
    ctx = SharedContextV2("https://example.com", {"domains": ["example.com"]})
    surface = AttackSurfaceState("https://example.com")

    # ---- RECON: crawler feeds endpoints with duplicate spellings + a synthetic
    # baseline probe + one out-of-scope host. -----------------------------------
    surface.add_endpoint(_ep("https://example.com/login", "/login"), source="crawl")
    surface.add_endpoint(_ep("https://EXAMPLE.com/login/", "/login/"), source="crawl")  # dup
    surface.add_endpoint(_ep("https://example.com/api/users", "/api/users"), source="crawl")
    assert surface.assert_endpoint_invariants()
    # 3 raw feeds, 2 unique, 1 deduped by canonical identity.
    assert surface._counts["endpoints_raw_fed"] == 3
    assert surface._counts["endpoints_unique"] == 2

    surface.mark_transferred_to_v2(new_endpoints=2, parameters=0)
    assert surface._counts["endpoints_transferred_to_v2"] == 2
    assert surface.assert_endpoint_invariants()

    ctx.add_endpoints([
        {"url": "https://example.com/login", "method": "GET"},
        {"url": "https://EXAMPLE.com/login/", "method": "GET"},          # canonical dup
        {"url": "https://example.com/__spa_detect_zzz", "method": "GET"},  # synthetic
        {"url": "https://evil.test/steal", "method": "GET"},              # out of scope
        {"url": "https://example.com/api/users", "method": "GET"},
    ], source="crawl")
    v2_urls = {ctx._endpoint_url(e) for e in ctx.get_endpoints()}
    assert "https://example.com/login" in v2_urls
    assert "https://example.com/api/users" in v2_urls
    assert len(ctx.get_endpoints()) == 2                # dup + synthetic + oos removed
    assert len(ctx.synthetic_endpoints) == 1
    assert any(d["url"] == "https://evil.test/steal" for d in ctx.external_dependencies)

    # ---- ACTIVE_SCANNING: a fake POST creates a resource (recorded for cleanup),
    # and a noisy 500-only finding must be classified INCONCLUSIVE and NOT mirrored
    # into exploit_results. ------------------------------------------------------
    led = get_ledger(ctx)
    m = led.record("POST", "https://example.com/api/users", 201,
                   body_text='{"id": 4271}', session_id="anonymous")
    assert m is not None and m.resource_url.endswith("/4271")

    ctx.add_vulnerability({
        "title": "Server error on /api/users",
        "type": "SERVER_ERROR", "location": "https://example.com/api/users",
        "severity": "medium", "status": "CONFIRMED",  # claims confirmed...
        "http_status": 500,                           # ...but only a 500 backs it
    })
    noisy = ctx.vulnerabilities[-1]
    assert noisy["confidence_label"] == "INCONCLUSIVE"
    assert not any(e.get("location") == "https://example.com/api/users"
                   for e in ctx.exploit_results), "500-only must not mirror as exploit"

    # ---- EXPLOITATION: a genuinely confirmed finding with concrete proof is
    # mirrored into exploit_results; its secret is redacted before any LLM sees it.
    secret = "sk_live_abcd1234efgh5678ijkl"
    ctx.add_vulnerability({
        "id": "vuln-sqli-1",
        "title": "SQL injection in login",
        "type": "SQL_INJECTION", "location": "https://example.com/login",
        "severity": "critical", "confirmed": True,
        "proof": f"extracted api key {secret} via UNION SELECT",
    })
    assert any("SQL injection" in (e.get("title") or "") for e in ctx.exploit_results)

    redacted = redact_for_llm(ctx.vulnerabilities[-1]["proof"])
    assert secret not in redacted

    # ---- REPORTING: correlate confirmed-only + evidence-linked. The downstream
    # finding depends on the SQLi's proof artifact, so a real chain forms; the
    # noisy INCONCLUSIVE finding is excluded. ------------------------------------
    ctx.add_vulnerability({
        "id": "vuln-idor-1",
        "title": "IDOR exposes accounts",
        "type": "IDOR", "location": "https://example.com/api/users",
        "severity": "high", "confirmed": True,
        "depends_on": f"api key {secret} from vuln-sqli-1",  # evidence dependency
    })
    engine = CorrelationEngine()
    chains = engine.correlate(ctx.vulnerabilities,
                              confirmed_only=True, require_evidence_link=True)
    assert chains, "expected at least one confirmed, evidence-linked chain"
    for ch in chains:
        assert ch.confirmed is True
        for f in ch.findings:
            assert f.get("confidence_label") != "INCONCLUSIVE"

    # ---- Scan-end cleanup: teardown is best-effort and never raises, even with
    # no live server (httpx DELETE fails -> reported, not thrown). ---------------
    report = asyncio.run(led.cleanup())
    assert report["total"] == 1
    assert report["cleaned"] + report["failed"] + report["skipped"] == 1

    # Spine still consistent at end of run.
    assert surface.assert_endpoint_invariants()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
