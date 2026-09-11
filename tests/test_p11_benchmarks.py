"""Phase 11 — benchmark suites (catalog + scoring + mapping logic)."""
from __future__ import annotations

from tests.benchmarks._scan_adapter import findings_to_challenge_ids
from tests.benchmarks.dvwa_benchmark import (
    DVWA_CASES,
    expected_at_level,
    score_by_level,
)
from tests.benchmarks.juice_shop_benchmark import (
    JUICE_SHOP_CHALLENGES,
    categories,
    score_results,
)
from tests.benchmarks.token_benchmark import (
    TOKEN_BUDGET_LIMIT,
    assert_within_budget,
    detect_regression,
    result_from_budget,
)


# ── Juice Shop ────────────────────────────────────────────────────────────
def test_juice_shop_catalog_covers_categories():
    cats = categories()
    for expected in ("injection", "xss", "broken_access_control", "business_logic"):
        assert expected in cats
    assert len(JUICE_SHOP_CHALLENGES) >= 20


def test_juice_shop_scoring():
    solved = {"sqli-login", "xss-dom", "negative-qty"}
    result = score_results(solved)
    assert result["solved"] == 3
    assert result["total"] == len(JUICE_SHOP_CHALLENGES)
    assert 0 < result["score"] < 100
    assert result["per_category"]["injection"]["found"] == 1


def test_juice_shop_full_solve_is_100():
    all_ids = {c.id for c in JUICE_SHOP_CHALLENGES}
    assert score_results(all_ids)["score"] == 100.0


def test_findings_map_to_challenges():
    findings = [{"type": "sqli"}, {"vuln_class": "xss"}, {"test": "business_logic"}]
    solved = findings_to_challenge_ids(findings, JUICE_SHOP_CHALLENGES)
    assert "sqli-login" in solved       # sqli finding
    assert "xss-dom" in solved          # xss finding
    assert "negative-qty" in solved     # business_logic finding


# ── DVWA ──────────────────────────────────────────────────────────────────
def test_dvwa_expected_at_level():
    low = expected_at_level("low")
    impossible = expected_at_level("impossible")
    assert "sqli" in low
    assert len(impossible) < len(low)   # fewer exploitable at higher security


def test_dvwa_score_by_level_and_degradation():
    found = {"low": ["sqli", "xss_reflected", "csrf"],
             "medium": ["sqli", "xss_reflected"],
             "high": ["sqli"],
             "impossible": []}
    scored = score_by_level(found)
    assert scored["low"]["found"] >= scored["high"]["found"]
    assert scored["degrades_gracefully"] is True


# ── Token budget ────────────────────────────────────────────────────────────
def test_assert_within_budget():
    assert_within_budget(1_500_000)   # under 2M — ok
    try:
        assert_within_budget(3_000_000)
        assert False, "should have raised"
    except AssertionError:
        pass


def test_detect_regression():
    assert detect_regression(1_300_000, 1_000_000)["regression"] is True   # +30% > 20% threshold
    assert detect_regression(1_050_000, 1_000_000)["regression"] is False  # +5%
    assert detect_regression(500_000, 0)["regression"] is False            # no baseline


def test_result_from_budget():
    class _Budget:
        def stats(self):
            return {"total_tokens": 1_800_000, "total_cost_usd": 1.23}

    r = result_from_budget(_Budget(), by_phase={"RECON": 300_000})
    assert r.total_tokens == 1_800_000
    assert r.within_budget is True
    assert r.limit == TOKEN_BUDGET_LIMIT
    assert r.cost_usd == 1.23
