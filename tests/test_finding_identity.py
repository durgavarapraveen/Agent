"""Canonical finding identity / fingerprint (spec Phase 20/21)."""
import pytest

from core.common.finding_ref import (
    finding_fingerprint, canonical_location, finding_location,
)


def test_same_bug_different_title_same_fingerprint():
    a = {"type": "SQLI", "title": "SQL injection in id",
         "location": "https://x/users?id=1", "parameter": "id"}
    b = {"type": "SQLI", "title": "Blind SQLi via id param (time-based)",
         "location": "https://x/users?id=999", "parameter": "id"}
    assert finding_fingerprint(a) == finding_fingerprint(b)


def test_distinct_param_class_auth_are_distinct():
    base = {"type": "IDOR", "location": "https://x/o", "parameter": "id",
            "identity": "alice"}
    fp = finding_fingerprint(base)
    assert fp != finding_fingerprint({**base, "parameter": "uid"})
    assert fp != finding_fingerprint({**base, "type": "XSS"})
    assert fp != finding_fingerprint({**base, "identity": "bob"})


def test_canonical_location_drops_query_values_keeps_names():
    assert canonical_location("https://X/A?id=1") == canonical_location("https://x/a?id=2")
    assert canonical_location("https://x/a?id=1") != canonical_location("https://x/a?token=1")


def test_finding_location_fallback_to_nonurl():
    assert finding_location({"location": "10.0.0.5"}) == "10.0.0.5"
    assert finding_location({}) == ""


def test_add_vulnerability_collapses_by_fingerprint_not_title():
    from core.memory.shared_context import SharedContextV2
    ctx = SharedContextV2(target="https://x/")
    ctx.add_vulnerability({"type": "SQLI", "title": "SQLi in id",
                           "location": "https://x/u?id=1", "parameter": "id"})
    ctx.add_vulnerability({"type": "SQLI", "title": "totally different wording",
                           "location": "https://x/u?id=42", "parameter": "id"})
    assert len(ctx.vulnerabilities) == 1                 # one canonical finding
    assert "https://x/u?id=42" in ctx.vulnerabilities[0].get("affected_endpoints", [])


def test_add_vulnerability_keeps_distinct_params():
    from core.memory.shared_context import SharedContextV2
    ctx = SharedContextV2(target="https://x/")
    ctx.add_vulnerability({"type": "IDOR", "title": "idor", "parameter": "id",
                           "location": "https://x/o"})
    ctx.add_vulnerability({"type": "IDOR", "title": "idor", "parameter": "account",
                           "location": "https://x/o"})
    assert len(ctx.vulnerabilities) == 2                 # distinct params, distinct findings


def test_host_level_findings_discriminated_by_title():
    # No parameter → title is the discriminator: distinct headers stay distinct,
    # the same header reported twice collapses.
    xfo = {"type": "MISSING_HEADER", "title": "Missing X-Frame-Options",
           "location": "https://x/"}
    csp = {"type": "MISSING_HEADER", "title": "Missing Content-Security-Policy",
           "location": "https://x/"}
    xfo2 = {"type": "MISSING_HEADER", "title": "missing x-frame-options header",
            "location": "https://x/"}
    assert finding_fingerprint(xfo) != finding_fingerprint(csp)
    assert finding_fingerprint(xfo) == finding_fingerprint(
        {"type": "MISSING_HEADER", "title": "Missing X-Frame-Options",
         "location": "https://x/"})


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
