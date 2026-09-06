"""PII masking regression tests (#147)."""
from __future__ import annotations

import pytest

from core.reporting.reporting import mask_sensitive_data


@pytest.mark.security
class TestMasking:
    def test_email_masked(self):
        out = mask_sensitive_data("contact alice@example.com for details")
        assert "alice@example.com" not in out
        assert "@example.com" in out

    def test_bearer_token_masked(self):
        out = mask_sensitive_data("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9")
        assert "eyJhbGciOiJIUzI1NiJ9" not in out or "[MASKED" in out

    def test_aws_access_key_masked(self):
        out = mask_sensitive_data("key: AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in out

    def test_gh_pat_masked(self):
        out = mask_sensitive_data("token=ghp_abc1234567890abcdef")
        assert "ghp_abc1234567890abcdef" not in out

    def test_openai_key_masked(self):
        out = mask_sensitive_data("api = sk-abcdef1234567890abcdef1234567890abcdef1234")
        assert "sk-abcdef1234567890abcdef1234567890abcdef1234" not in out

    def test_slack_token_masked(self):
        out = mask_sensitive_data("hook = xoxb-abcdef123456-abcdef123456-abcdef")
        assert "xoxb-abcdef123456-abcdef123456-abcdef" not in out

    def test_jwt_masked(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdef1234567890"
        out = mask_sensitive_data(f"token={jwt}")
        assert jwt not in out

    def test_credit_card_masked(self):
        out = mask_sensitive_data("card 4111111111111111 expires soon")
        assert "4111111111111111" not in out

    def test_ssn_masked(self):
        out = mask_sensitive_data("ssn 123-45-6789 on file")
        assert "123-45-6789" not in out

    def test_password_kv_masked(self):
        out = mask_sensitive_data("password: hunter2")
        assert "hunter2" not in out

    def test_private_key_block_masked(self):
        key = "-----BEGIN RSA PRIVATE KEY-----\nabcdef==\n-----END RSA PRIVATE KEY-----"
        out = mask_sensitive_data(f"here is a key:\n{key}")
        assert "abcdef==" not in out

    def test_disabled_returns_unchanged(self):
        out = mask_sensitive_data("password: hunter2", enabled=False)
        assert "hunter2" in out
