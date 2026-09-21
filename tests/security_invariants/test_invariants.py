"""Security-invariant tests (§21).

Property-level guarantees for the security kernel — these must hold regardless of
implementation detail. If any fails, the containment boundary has regressed.
Pure/offline: no DB, no network.
"""
from __future__ import annotations

import os
import pytest

from core.security.authorization import TargetScopeValidator


# ── Scope / authorization invariants ───────────────────────────────────
def _validator(scope, **kw):
    return TargetScopeValidator(scope, **kw)


def test_out_of_scope_host_denied():
    v = _validator(["example.com"])
    assert v.is_authorized("evil.com") is False


def test_in_scope_subdomain_allowed():
    v = _validator(["example.com"])
    assert v.is_authorized("api.example.com") is True


def test_discovery_cannot_expand_scope():
    # §3: a discovered out-of-scope host must NOT become authorized via add_target.
    v = _validator(["example.com"])
    added = v.add_target("attacker-controlled.net")
    assert added is False
    assert v.is_authorized("attacker-controlled.net") is False
    assert "attacker-controlled.net" in v.discovered_out_of_scope()


def test_discovery_in_contract_is_allowed():
    v = _validator(["example.com"])
    assert v.add_target("dev.example.com") is True
    assert v.is_authorized("dev.example.com") is True


def test_wildcard_denies_in_production():
    v = _validator(["*"], allow_wildcard=False)
    assert v.is_authorized("anything.com") is False


def test_wildcard_allows_only_in_lab_mode():
    v = _validator(["*"], allow_wildcard=True)
    assert v.is_authorized("anything.com") is True


def test_userinfo_bypass_denied():
    # http://example.com@evil.com must resolve to evil.com (out of scope), not example.com
    v = _validator(["example.com"])
    assert v.is_authorized("example.com@evil.com") is False


def test_trailing_dot_normalized():
    v = _validator(["example.com"])
    assert v.is_authorized("example.com.") is True


# ── Watchdog / budget / kill-switch invariants ─────────────────────────
def test_watchdog_budget_breach_stops():
    from core.security.watchdog import Watchdog, ScanBudget
    wd = Watchdog(ScanBudget(max_requests=2, max_runtime_s=1e9))
    assert wd.should_continue()
    wd.record_request(); wd.record_request()
    assert wd.should_continue() is False
    assert "max_requests" in (wd.breach_reason() or "")


def test_watchdog_kill_switch():
    from core.security.watchdog import Watchdog, ScanBudget, WatchdogTripped
    wd = Watchdog(ScanBudget(max_requests=1e9))
    wd.trigger_kill("test")
    assert wd.killed is True
    with pytest.raises(WatchdogTripped):
        wd.check()


def test_impact_tier_ceiling():
    from core.security.watchdog import Watchdog, ScanBudget
    wd = Watchdog(ScanBudget(max_impact="POC"))
    assert wd.impact_allowed("OBSERVE") is True
    assert wd.impact_allowed("POC") is True
    assert wd.impact_allowed("DESTRUCTIVE") is False


# ── Payload provenance invariant (§11) ─────────────────────────────────
def test_payload_carries_provenance_fields():
    from core.payloads.schema import Payload
    p = Payload(vuln_class="sqli", payload_text="' OR 1=1--")
    for field in ("source_ref", "source_url", "risk", "requires_oob", "requires_write", "stage"):
        assert hasattr(p, field)
    assert p.stage in ("staging", "canary", "production")


# ── Runtime install invariant (§10) ────────────────────────────────────
def test_runtime_install_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ALLOW_RUNTIME_INSTALL", raising=False)
    from core.tools.tool_installer import ToolInstaller
    ti = ToolInstaller.__new__(ToolInstaller)
    ti.failed = {}
    # is_installed would hit Docker; force the "not installed" path by stubbing
    ti.is_installed = lambda name: False
    assert ti.install("nmap") is False
    assert "runtime install disabled" in ti.failed.get("nmap", "")
