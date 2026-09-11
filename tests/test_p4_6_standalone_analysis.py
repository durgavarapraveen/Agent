"""Standalone (individual) APK/source analysis — no target/scan."""
from __future__ import annotations

from core.analysis.standalone_analysis import (
    analyze_mobile,
    analyze_source,
    run_standalone,
)


class _FakeMobileAnalysis:
    def to_dict(self):
        return {"endpoints": ["https://api.test/a", "https://api.test/b"],
                "secrets": [{"type": "aws_access_key", "match": "AKIA..."}],
                "deeplinks": ["myapp://pay"], "cert_pinning": True, "package": "com.x"}


def _patch_apk(monkeypatch):
    import core.discovery.mobile_analyzer as ma

    class FakeAnalyzer:
        def analyze(self, path):
            return _FakeMobileAnalysis()
    monkeypatch.setattr(ma, "MobileAnalyzer", FakeAnalyzer)


def test_analyze_mobile_apk(monkeypatch):
    _patch_apk(monkeypatch)
    r = analyze_mobile("/tmp/app.apk")
    assert r["kind"] == "apk"
    assert r["endpoint_count"] == 2
    assert r["secret_count"] == 1
    assert r["deeplink_count"] == 1
    assert r["cert_pinning"] is True


def test_analyze_mobile_ipa(monkeypatch):
    import core.discovery.ipa_analyzer as ia

    class FakeIPA:
        def analyze(self, path):
            return _FakeMobileAnalysis()
    monkeypatch.setattr(ia, "IPAAnalyzer", FakeIPA)
    r = analyze_mobile("/tmp/app.ipa")
    assert r["kind"] == "ipa"


def _patch_sast(monkeypatch, findings):
    import core.analysis.sast_bridge as sb

    class FakeBridge:
        def analyze(self, source_path="", source_repo=""):
            return findings
    monkeypatch.setattr(sb, "SastBridge", FakeBridge)


def test_analyze_source_groups(monkeypatch):
    _patch_sast(monkeypatch, [
        {"vuln_class": "sqli", "severity": "high", "file": "a.py", "line": 1},
        {"vuln_class": "sqli", "severity": "high", "file": "b.py", "line": 2},
        {"vuln_class": "xss", "severity": "medium", "file": "c.py", "line": 3},
    ])
    r = analyze_source(source_path="/repo")
    assert r["finding_count"] == 3
    assert r["by_class"]["sqli"] == 2
    assert r["by_severity"]["high"] == 2
    assert r["source_path"] == "/repo"


def test_run_standalone_source_only(monkeypatch):
    _patch_sast(monkeypatch, [{"vuln_class": "sqli", "severity": "high"}])
    report = run_standalone(source_path="/repo")
    assert report["mobile"] is None
    assert report["source"]["finding_count"] == 1


def test_run_standalone_mobile_only(monkeypatch):
    _patch_apk(monkeypatch)
    report = run_standalone(mobile_app="/tmp/app.apk")
    assert report["source"] is None
    assert report["mobile"]["endpoint_count"] == 2


def test_run_standalone_both(monkeypatch):
    _patch_apk(monkeypatch)
    _patch_sast(monkeypatch, [{"vuln_class": "xss", "severity": "medium"}])
    report = run_standalone(mobile_app="/tmp/app.apk", source_path="/repo")
    assert report["mobile"]["kind"] == "apk"
    assert report["source"]["finding_count"] == 1


def test_run_standalone_empty():
    report = run_standalone()
    assert report["mobile"] is None and report["source"] is None
