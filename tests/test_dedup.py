"""Regression tests for the dedup fingerprint + `mark_resolved` scoping (#014)."""
from __future__ import annotations

import pytest

from core.validation.dedup import fingerprint, generate_dedup_key


class TestFingerprint:
    def test_stable_across_calls(self):
        a = fingerprint(cve_id="CVE-2020-1", target="example.com",
                         title="SQLi", vuln_type="sqli")
        b = fingerprint(cve_id="CVE-2020-1", target="example.com",
                         title="SQLi", vuln_type="sqli")
        assert a == b

    def test_target_normalized(self):
        # https://example.com/foo and example.com should hash the same host.
        a = fingerprint(target="https://example.com/foo", title="X", vuln_type="xss")
        b = fingerprint(target="example.com", title="X", vuln_type="xss")
        assert a == b

    def test_title_case_insensitive(self):
        a = fingerprint(target="ex.com", title="Reflected XSS", vuln_type="xss")
        b = fingerprint(target="ex.com", title="reflected xss", vuln_type="xss")
        assert a == b

    def test_type_case_insensitive(self):
        a = fingerprint(target="ex.com", title="X", vuln_type="XSS")
        b = fingerprint(target="ex.com", title="X", vuln_type="xss")
        assert a == b

    def test_different_types_differ(self):
        a = fingerprint(target="ex.com", title="X", vuln_type="xss")
        b = fingerprint(target="ex.com", title="X", vuln_type="sqli")
        assert a != b

    def test_different_targets_differ(self):
        a = fingerprint(target="a.com", title="X", vuln_type="xss")
        b = fingerprint(target="b.com", title="X", vuln_type="xss")
        assert a != b


class TestDedupKey:
    def test_shape(self):
        k = generate_dedup_key("port_scanning", "example.com", "80")
        assert k == "port_scanning:example.com:80"

    def test_url_stripped(self):
        k = generate_dedup_key("cap", "https://example.com/foo", "")
        # Should NOT contain the path or scheme.
        assert "https" not in k
        assert "/foo" not in k

    def test_port_from_target(self):
        k = generate_dedup_key("cap", "example.com:443", "")
        assert k == "cap:example.com:443"
