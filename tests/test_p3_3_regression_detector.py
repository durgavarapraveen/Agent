"""Phase 3.3 — regression detection."""
from __future__ import annotations

from core.monitoring.regression_detector import (
    FIXED,
    REGRESSED,
    RegressionDetector,
)


def _finding(fid, sev="high"):
    return {"id": fid, "title": f"SQLi {fid}", "url": f"https://app.test/{fid}",
            "severity": sev, "method": "POST", "payload": "' OR 1=1--"}


def test_track_and_mark_fixed():
    det = RegressionDetector()
    tf = det.track(_finding("f1"))
    assert tf.status == "open"
    assert tf.test_case["payload"] == "' OR 1=1--"
    det.mark_fixed("f1", when="2026-01-01T00:00:00+00:00")
    assert det.findings["f1"].status == FIXED


def test_regression_detected_when_reproducible():
    # Reproducer says the vuln is still present → REGRESSED.
    det = RegressionDetector(reproducer=lambda tc: True)
    det.track(_finding("f1"))
    det.mark_fixed("f1")
    regressed = det.check_regressions()
    assert len(regressed) == 1
    assert det.findings["f1"].status == REGRESSED
    assert det.findings["f1"].regressed_at


def test_no_regression_when_not_reproducible():
    det = RegressionDetector(reproducer=lambda tc: False)
    det.track(_finding("f1"))
    det.mark_fixed("f1")
    assert det.check_regressions() == []
    assert det.findings["f1"].status == FIXED


def test_open_findings_not_checked():
    called = []
    det = RegressionDetector(reproducer=lambda tc: called.append(1) or True)
    det.track(_finding("f1"))  # left open, never marked fixed
    assert det.check_regressions() == []
    assert called == []  # open findings are not replayed


def test_mean_time_to_fix_and_regression_rate():
    det = RegressionDetector(reproducer=lambda tc: True)
    det.track(_finding("f1", "high"))
    det.findings["f1"].first_seen = "2026-01-01T00:00:00+00:00"
    det.mark_fixed("f1", when="2026-01-02T00:00:00+00:00")  # 24h
    det.track(_finding("f2", "high"))
    det.findings["f2"].first_seen = "2026-01-01T00:00:00+00:00"
    det.mark_fixed("f2", when="2026-01-01T12:00:00+00:00")  # 12h

    mttf = det.mean_time_to_fix()
    assert mttf["high"] == 18.0  # (24 + 12) / 2

    # Both fixed; regress one.
    det.findings["f1"].status = FIXED  # reset from any prior check
    det.check_regressions()
    assert det.regression_rate() == 1.0  # both reproduce → both regressed


def test_persistence_roundtrip(tmp_path):
    det = RegressionDetector(reproducer=lambda tc: False)
    det.track(_finding("f1"))
    det.mark_fixed("f1")
    p = det.save(path=str(tmp_path / "t.json"))

    det2 = RegressionDetector()
    det2.load(path=p)
    assert "f1" in det2.findings
    assert det2.findings["f1"].status == FIXED
