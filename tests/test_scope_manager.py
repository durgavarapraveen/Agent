"""Scope manager normalization regression tests (#079/#080/#081)."""
from __future__ import annotations

import pytest

from core.scope.manager import ScopeManager


@pytest.fixture
def sm():
    m = ScopeManager()
    m.allowed_domains.add("example.com")
    m.allowed_domains.add("acme.io")
    m.allowed_ips.add("10.0.0.0/8")
    return m


@pytest.mark.security
class TestScopeManager:
    def test_bare_hostname_matches(self, sm):
        assert sm.validate_url("http://example.com") is True

    def test_trailing_dot_matches(self, sm):
        assert sm.validate_url("http://example.com.") is True

    def test_case_insensitive_matches(self, sm):
        assert sm.validate_url("http://EXAMPLE.com/") is True

    def test_subdomain_matches(self, sm):
        assert sm.validate_url("https://api.example.com/foo") is True

    def test_unrelated_rejected(self, sm):
        assert sm.validate_url("https://evil.com") is False

    def test_ipv6_bracket_literal_recognised(self, sm):
        # 10.x is in scope, but this is a v6 not in scope.
        assert sm.validate_url("http://[2001:db8::1]:8080/") is False

    def test_ipv4_within_cidr(self, sm):
        assert sm.validate_ip("10.42.1.1") is True

    def test_ipv4_outside_cidr(self, sm):
        assert sm.validate_ip("192.168.1.1") is False

    def test_ipv4_literal_via_url(self, sm):
        assert sm.validate_url("http://10.42.1.1:8080/") is True

    def test_plan_rejects_ipv6_bracket_literal_out_of_scope(self, sm):
        result = sm.validate_plan("[2001:db8::1]:8080")
        assert result != ""  # non-empty = rejected
