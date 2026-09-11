"""Phase 8.3 — deterministic-first detectors."""
from __future__ import annotations

from core.execution.deterministic_detectors import (
    detect_cors,
    detect_error_based_sqli,
    detect_info_disclosure,
    detect_missing_security_headers,
    needs_llm,
    run_all,
)


def test_detect_cors_wildcard_with_credentials():
    f = detect_cors({"Access-Control-Allow-Origin": "*",
                     "Access-Control-Allow-Credentials": "true"})
    assert f and f["severity"] == "high"
    assert detect_cors({"Access-Control-Allow-Origin": "https://self.test"}) is None


def test_detect_missing_security_headers():
    f = detect_missing_security_headers({"content-type": "text/html"})
    assert f and "content-security-policy" in f["missing"]
    # All present → no finding.
    full = {h: "x" for h in ("x-frame-options", "content-security-policy",
                             "strict-transport-security", "x-content-type-options")}
    assert detect_missing_security_headers(full) is None


def test_detect_info_disclosure_stacktrace():
    assert detect_info_disclosure("Traceback (most recent call last): ...") is not None
    assert detect_info_disclosure("Server: nginx/1.25.3 running") is not None
    assert detect_info_disclosure("normal page content") is None


def test_detect_error_based_sqli():
    assert detect_error_based_sqli("You have an error in your SQL syntax; MySQL") is not None
    assert detect_error_based_sqli("ORA-01756: quoted string not properly terminated") is not None
    assert detect_error_based_sqli("all good") is None


def test_run_all_and_needs_llm():
    findings = run_all(headers={"Access-Control-Allow-Origin": "*"},
                       body="Traceback (most recent call last):")
    tests = {f["test"] for f in findings}
    assert "cors" in tests and "info_disclosure" in tests
    # Deterministic findings present → LLM not needed.
    assert needs_llm("Traceback ...", findings) is False
    # Nothing fired but body is substantial → LLM needed.
    assert needs_llm("x" * 100, []) is True
    # Trivial empty body → no LLM.
    assert needs_llm("", []) is False


def test_all_findings_marked_deterministic():
    findings = run_all(headers={"Access-Control-Allow-Origin": "*"}, body="ORA-00933")
    assert all(f.get("deterministic") for f in findings)
