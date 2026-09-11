"""Phase 8.4 — progressive depth scanning (Tier 0/1/2)."""
from __future__ import annotations

from core.execution.progressive_depth import (
    TIER0,
    TIER1,
    TIER2,
    assign_tier,
    build_plan,
    is_high_risk,
)


def test_assign_tier():
    assert assign_tier({"url": "https://x/static/logo.png", "method": "GET"}) == TIER0
    assert assign_tier({"url": "https://x/search?q=1", "method": "GET"}) == TIER1
    assert assign_tier({"url": "https://x/api/payment", "method": "POST"}) == TIER2
    assert assign_tier({"url": "https://x/admin/users", "method": "GET"}) == TIER2


def test_flagged_endpoint_promoted_to_tier2():
    ep = {"url": "https://x/report", "method": "GET"}
    assert assign_tier(ep) in (TIER0, TIER1)
    assert assign_tier(ep, flagged=True) == TIER2


def test_high_risk_detection():
    assert is_high_risk({"url": "https://x/checkout"})
    assert not is_high_risk({"url": "https://x/blog"})


def test_build_plan_partitions():
    endpoints = [
        {"url": "https://x/static/a.css", "method": "GET"},   # tier0
        {"url": "https://x/search?q=1", "method": "GET"},     # tier1
        {"url": "https://x/api/pay", "method": "POST"},        # tier2 (high risk)
    ]
    plan = build_plan(endpoints)
    assert len(plan.tier0) == 3          # tier0 runs on all
    assert len(plan.tier1) == 1
    assert len(plan.tier2) == 1
    summary = plan.summary()
    assert summary == {"tier0": 3, "tier1": 1, "tier2": 1}


def test_ordered_schedules_each_endpoint_once():
    endpoints = [
        {"url": "https://x/static/a.css", "method": "GET"},
        {"url": "https://x/api/pay", "method": "POST"},
    ]
    plan = build_plan(endpoints)
    ordered = plan.ordered()
    # 2 endpoints total: 1 tier0-only (css) + 1 tier2 (pay)
    assert len(ordered) == 2


def test_flagged_urls_promote():
    endpoints = [{"url": "https://x/report", "method": "GET"}]
    plan = build_plan(endpoints, flagged_urls={"https://x/report"})
    assert len(plan.tier2) == 1
