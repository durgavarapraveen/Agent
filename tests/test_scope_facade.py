"""Regression tests for the unified `ScopeAuthority` (#082/#083)."""
from __future__ import annotations

import pytest

from core.security.scope_facade import ScopeAuthority, get_scope_authority


@pytest.fixture(autouse=True)
def _reset():
    ScopeAuthority.reset_for_tests()
    yield
    ScopeAuthority.reset_for_tests()


@pytest.mark.security
class TestScopeAuthority:
    def test_fails_closed_when_nothing_wired(self):
        auth = get_scope_authority()
        assert auth.is_authorized("https://example.com") is False

    def test_add_domain_bootstrap_allows_that_domain(self):
        auth = get_scope_authority()
        auth.add_domain("example.com")
        assert auth.is_authorized("https://example.com/foo") is True

    def test_add_domain_bootstrap_covers_subdomains(self):
        auth = get_scope_authority()
        auth.add_domain("example.com")
        assert auth.is_authorized("https://api.example.com/foo") is True

    def test_add_domain_bootstrap_rejects_unrelated(self):
        auth = get_scope_authority()
        auth.add_domain("example.com")
        assert auth.is_authorized("https://evil.com") is False

    def test_empty_target_rejected(self):
        auth = get_scope_authority()
        auth.add_domain("example.com")
        assert auth.is_authorized("") is False

    def test_multiple_backends_all_must_agree(self):
        """When two authorities are wired, `is_authorized` must return True
        only when BOTH agree."""
        auth = get_scope_authority()

        class _MockValidator:
            def __init__(self, verdict): self._verdict = verdict
            def validate(self, target): return self._verdict

        auth.wire_target_scope_validator(_MockValidator(True))
        # Add a second mock that says NO.
        class _NoValidator:
            def is_target_authorized(self, target): return False
        auth.wire_legal_validator(_NoValidator())

        assert auth.is_authorized("https://example.com") is False

    def test_enforcement_status_diagnostic(self):
        auth = get_scope_authority()
        s = auth.enforcement_status()
        assert set(s.keys()) >= {
            "scope_manager", "target_scope_validator",
            "legal_validator", "auto_scope_size",
        }
