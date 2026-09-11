"""Phase 4.5 — SAST bridge & SAST/DAST correlation."""
from __future__ import annotations

import json

from core.analysis.sast_bridge import (
    SastBridge,
    classify_rule,
    correlate_and_persist,
    correlate_sast_dast,
    load_correlation,
    parse_semgrep_output,
)


def test_classify_rule():
    assert classify_rule("python.sql-injection", ["CWE-89: SQL Injection"]) == "sqli"
    assert classify_rule("js.xss.reflected") == "xss"
    assert classify_rule("generic.os-command-injection") == "command_injection"
    assert classify_rule("unknown.rule") == "generic"


SEMGREP_JSON = {
    "results": [
        {"check_id": "python.django.security.sql-injection",
         "path": "app/api/orders.py", "start": {"line": 42},
         "extra": {"severity": "ERROR", "message": "SQL injection",
                   "metadata": {"cwe": ["CWE-89: SQL Injection"]}}},
        {"check_id": "python.flask.security.xss",
         "path": "app/views/profile.py", "start": {"line": 10},
         "extra": {"severity": "WARNING", "message": "XSS",
                   "metadata": {"cwe": ["CWE-79"]}}},
    ]
}


def test_parse_semgrep_output():
    findings = parse_semgrep_output(SEMGREP_JSON)
    assert len(findings) == 2
    sqli = next(f for f in findings if f["vuln_class"] == "sqli")
    assert sqli["file"] == "app/api/orders.py"
    assert sqli["line"] == 42
    assert sqli["severity"] == "high"       # ERROR → high
    assert sqli["source"] == "sast"
    # Also accepts a JSON string.
    assert len(parse_semgrep_output(json.dumps(SEMGREP_JSON))) == 2


def test_correlate_confirmed_sast_and_dast():
    sast = parse_semgrep_output(SEMGREP_JSON)
    dast = [
        {"vuln_class": "sqli", "url": "https://app.test/api/orders/1", "severity": "high"},
        {"vuln_class": "ssrf", "url": "https://app.test/fetch", "severity": "medium"},
    ]
    result = correlate_sast_dast(sast, dast)
    # SQLi correlates (source file "orders.py" ↔ url "/api/orders/1" share 'orders')
    assert len(result["confirmed"]) == 1
    assert result["confirmed"][0]["vuln_class"] == "sqli"
    assert result["confirmed"][0]["confidence"] == "confirmed"
    # XSS is SAST-only (no matching DAST); SSRF is DAST-only.
    assert any(f["vuln_class"] == "xss" for f in result["sast_only"])
    assert any(f.get("vuln_class") == "ssrf" for f in result["dast_only"])
    assert all(f["confidence"] == "potential" for f in result["sast_only"])
    assert all(f["confidence"] == "confirmed_runtime" for f in result["dast_only"])


def test_correlation_requires_location_overlap():
    sast = [{"vuln_class": "sqli", "file": "app/billing/invoice.py", "severity": "high"}]
    dast = [{"vuln_class": "sqli", "url": "https://app.test/api/orders", "severity": "high"}]
    result = correlate_sast_dast(sast, dast)
    # Same class but different location → NOT confirmed.
    assert result["confirmed"] == []
    assert len(result["sast_only"]) == 1
    assert len(result["dast_only"]) == 1


def test_run_semgrep_graceful_without_tool(monkeypatch):
    bridge = SastBridge()
    monkeypatch.setattr(bridge, "semgrep_available", lambda: False)
    assert bridge.run_semgrep("/some/path") == []


def test_analyze_returns_empty_for_missing_path():
    assert SastBridge().analyze(source_path="/nonexistent/path/xyz") == []


def test_correlate_and_persist_roundtrip(tmp_path):
    sast = parse_semgrep_output(SEMGREP_JSON)
    dast = [{"vuln_class": "sqli", "url": "https://app.test/api/orders/1", "severity": "high"}]
    out = str(tmp_path)
    summary = correlate_and_persist("scan42", sast, dast, out_dir=out)
    assert summary["scan_id"] == "scan42"
    assert summary["counts"]["confirmed"] == 1
    # Persisted + reloadable.
    loaded = load_correlation("scan42", out_dir=out)
    assert loaded is not None
    assert loaded["counts"]["confirmed"] == 1


def test_load_correlation_missing(tmp_path):
    assert load_correlation("nope", out_dir=str(tmp_path)) is None
