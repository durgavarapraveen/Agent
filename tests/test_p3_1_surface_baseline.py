"""Phase 3.1 — attack-surface baseline & diff."""
from __future__ import annotations

from core.monitoring.surface_baseline import SurfaceBaseline, SurfaceSnapshot


def _source_v1():
    return {
        "target": "https://app.test",
        "subdomains": ["api.app.test", "www.app.test"],
        "endpoints": [
            {"url": "https://app.test/api/users/1", "method": "GET", "params": "id"},
            {"url": "https://app.test/login", "method": "POST"},
        ],
        "js_endpoints": [{"url": "https://app.test/app.js", "hash": "aaaa"}],
        "dns_records": ["A 1.2.3.4"],
    }


def test_snapshot_normalizes_endpoints():
    snap = SurfaceBaseline().snapshot(_source_v1())
    # /api/users/1 → normalized to /api/users/{id}
    assert "GET /api/users/{id}" in snap.endpoints
    assert "POST /login" in snap.endpoints
    assert "api.app.test" in snap.subdomains
    assert snap.js_hashes["https://app.test/app.js"] == "aaaa"


def test_diff_detects_new_and_changed():
    bl = SurfaceBaseline()
    old = bl.snapshot(_source_v1())

    v2 = _source_v1()
    v2["endpoints"].append({"url": "https://app.test/api/admin", "method": "GET"})  # new
    v2["endpoints"][0]["params"] = "id,expand"  # param added on existing endpoint
    v2["js_endpoints"] = [{"url": "https://app.test/app.js", "hash": "bbbb"}]  # changed hash
    v2["subdomains"].append("staging.app.test")
    new = bl.snapshot(v2)

    diff = bl.diff(old, new)
    assert diff["has_changes"]
    assert "GET /api/admin" in diff["endpoints"]["added"]
    assert "GET /api/users/{id}" in diff["params_changed"]
    assert "expand" in diff["params_changed"]["GET /api/users/{id}"]["added"]
    assert "https://app.test/app.js" in diff["js"]["changed"]
    assert "staging.app.test" in diff["subdomains"]["added"]


def test_no_changes_on_identical_snapshot():
    bl = SurfaceBaseline()
    s = bl.snapshot(_source_v1())
    diff = bl.diff(s, bl.snapshot(_source_v1()))
    assert not diff["has_changes"]


def test_changed_for_rescan():
    bl = SurfaceBaseline()
    old = bl.snapshot(_source_v1())
    v2 = _source_v1()
    v2["endpoints"].append({"url": "https://app.test/api/admin", "method": "GET"})
    v2["endpoints"][0]["params"] = "id,expand"
    diff = bl.diff(old, bl.snapshot(v2))
    rescan = bl.changed_for_rescan(diff)
    assert "GET /api/admin" in rescan
    assert "GET /api/users/{id}" in rescan  # param change → re-scan


def test_save_and_load_roundtrip(tmp_path):
    bl = SurfaceBaseline()
    snap = bl.snapshot(_source_v1())
    path = tmp_path / "baseline.json"
    bl.save(snap, path=str(path))
    loaded = bl.load_latest("https://app.test", path=str(path))
    assert loaded is not None
    assert set(loaded.endpoints) == set(snap.endpoints)
    assert loaded.js_hashes == snap.js_hashes


def test_load_missing_returns_none(tmp_path):
    assert SurfaceBaseline().load_latest("x", path=str(tmp_path / "nope.json")) is None
