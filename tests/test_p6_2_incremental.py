"""Phase 6.2 — incremental scanning."""
from __future__ import annotations

from core.monitoring.incremental import IncrementalScanner, plan_incremental
from core.monitoring.surface_baseline import SurfaceBaseline


def _source(extra=None):
    eps = [
        {"url": "https://app.test/api/users/1", "method": "GET", "params": "id"},
        {"url": "https://app.test/login", "method": "POST"},
    ]
    if extra:
        eps.extend(extra)
    return {"target": "https://app.test", "endpoints": eps}


def test_full_scan_when_no_baseline():
    bl = SurfaceBaseline()
    current = bl.snapshot(_source())
    plan = plan_incremental(current, None)
    assert plan.full_scan
    assert len(plan.endpoints_to_scan) == 2


def test_no_changes_skips_everything():
    bl = SurfaceBaseline()
    current = bl.snapshot(_source())
    plan = plan_incremental(current, bl.snapshot(_source()))
    assert not plan.full_scan
    assert plan.endpoints_to_scan == []
    assert len(plan.skipped) == 2


def test_only_changed_endpoints_scanned():
    bl = SurfaceBaseline()
    baseline = bl.snapshot(_source())
    current = bl.snapshot(_source(extra=[{"url": "https://app.test/api/admin", "method": "GET"}]))
    plan = plan_incremental(current, baseline)
    assert not plan.full_scan
    assert "GET /api/admin" in plan.endpoints_to_scan
    assert "POST /login" in plan.skipped   # unchanged


def test_scanner_plan_incremental_disabled_is_full(tmp_path):
    scanner = IncrementalScanner()
    plan = scanner.plan("https://app.test", _source(), incremental=False)
    assert plan.full_scan


def test_scanner_roundtrip_commit_then_plan(tmp_path):
    scanner = IncrementalScanner()
    path = str(tmp_path / "bl.json")
    # First run: no baseline → full; commit baseline.
    scanner.commit("https://app.test", _source(), baseline_path=path)
    # Second run: same surface → nothing to scan.
    plan = scanner.plan("https://app.test", _source(), incremental=True, baseline_path=path)
    assert not plan.full_scan and plan.endpoints_to_scan == []
    # Third run: new endpoint → only it is scanned.
    plan2 = scanner.plan("https://app.test",
                         _source(extra=[{"url": "https://app.test/new", "method": "GET"}]),
                         incremental=True, baseline_path=path)
    assert "GET /new" in plan2.endpoints_to_scan


def test_filter_endpoints():
    bl = SurfaceBaseline()
    baseline = bl.snapshot(_source())
    live = _source(extra=[{"url": "https://app.test/api/admin", "method": "GET"}])["endpoints"]
    current = bl.snapshot({"target": "https://app.test", "endpoints": live})
    plan = plan_incremental(current, baseline)
    kept = IncrementalScanner.filter_endpoints(live, plan)
    kept_urls = {e["url"] for e in kept}
    assert "https://app.test/api/admin" in kept_urls
    assert "https://app.test/login" not in kept_urls
