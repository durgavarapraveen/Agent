"""P0.1 — PolicyEngine unit tests.

Covers: allow, deny, error/fail-closed, structured decisions, all authorize_* methods.
"""
import pytest
from unittest.mock import patch, MagicMock
from core.security.policy_engine import (
    PolicyEngine, PolicyDecision, DenyReason, PolicyAction,
    get_policy_engine, _POLICY_VERSION,
)


@pytest.fixture(autouse=True)
def reset_engine():
    PolicyEngine.reset_for_tests()
    yield
    PolicyEngine.reset_for_tests()


# ── Decision structure ──────────────────────────────────────────────────

class TestPolicyDecision:
    def test_decision_is_frozen(self):
        d = PolicyDecision(allowed=True, action="test", reason="ok")
        with pytest.raises(AttributeError):
            d.allowed = False

    def test_to_dict_has_required_fields(self):
        d = PolicyDecision(allowed=False, action="test", reason="denied",
                           reason_code="TARGET_OUT_OF_SCOPE", target="evil.com")
        out = d.to_dict()
        assert out["allowed"] is False
        assert out["reason_code"] == "TARGET_OUT_OF_SCOPE"
        assert out["policy_version"] == _POLICY_VERSION
        assert "action_id" in out
        assert "timestamp" in out
        assert out["target"] == "evil.com"

    def test_action_id_is_unique(self):
        d1 = PolicyDecision(allowed=True, action="a", reason="ok")
        d2 = PolicyDecision(allowed=True, action="a", reason="ok")
        assert d1.action_id != d2.action_id


# ── Singleton ───────────────────────────────────────────────────────────

class TestSingleton:
    def test_get_returns_same_instance(self):
        a = PolicyEngine.get()
        b = PolicyEngine.get()
        assert a is b

    def test_reset_clears(self):
        a = PolicyEngine.get()
        PolicyEngine.reset_for_tests()
        b = PolicyEngine.get()
        assert a is not b


# ── authorize_target ────────────────────────────────────────────────────

class TestAuthorizeTarget:
    def test_empty_target_denied(self):
        engine = get_policy_engine()
        d = engine.authorize_target("")
        assert not d.allowed
        assert d.reason_code == DenyReason.SCHEMA_INVALID.value

    def test_none_target_denied(self):
        engine = get_policy_engine()
        d = engine.authorize_target(None)
        assert not d.allowed

    @patch("core.security.policy_engine.PolicyEngine._get_target_scope_validator")
    @patch("core.security.policy_engine.PolicyEngine._get_scope_authority")
    def test_authorized_target_allowed(self, mock_sa, mock_tsv):
        tsv = MagicMock()
        tsv.is_authorized.return_value = True
        mock_tsv.return_value = tsv
        sa = MagicMock()
        sa.enforcement_status.return_value = {"target_scope_validator": True}
        sa.is_authorized.return_value = True
        mock_sa.return_value = sa

        d = get_policy_engine().authorize_target("example.com")
        assert d.allowed
        assert d.action == PolicyAction.TARGET.value

    @patch("core.security.policy_engine.PolicyEngine._get_target_scope_validator")
    def test_out_of_scope_denied(self, mock_tsv):
        tsv = MagicMock()
        tsv.is_authorized.return_value = False
        mock_tsv.return_value = tsv

        d = get_policy_engine().authorize_target("evil.com")
        assert not d.allowed
        assert d.reason_code == DenyReason.TARGET_OUT_OF_SCOPE.value
        assert d.target == "evil.com"

    @patch("core.security.policy_engine.PolicyEngine._get_target_scope_validator")
    def test_validator_exception_fails_closed(self, mock_tsv):
        mock_tsv.side_effect = RuntimeError("DB down")
        d = get_policy_engine().authorize_target("example.com")
        assert not d.allowed
        assert d.reason_code == DenyReason.POLICY_ERROR.value


# ── authorize_command ───────────────────────────────────────────────────

class TestAuthorizeCommand:
    def test_empty_command_denied(self):
        d = get_policy_engine().authorize_command("")
        assert not d.allowed
        assert d.reason_code == DenyReason.SCHEMA_INVALID.value

    @patch("core.security.policy_engine.PolicyEngine._get_target_scope_validator")
    @patch("core.security.policy_engine.PolicyEngine._get_scope_authority")
    def test_safe_command_allowed(self, mock_sa, mock_tsv):
        tsv = MagicMock()
        tsv.extract_and_validate_command.return_value = None
        tsv.is_authorized.return_value = True
        mock_tsv.return_value = tsv
        sa = MagicMock()
        sa.enforcement_status.return_value = {}
        mock_sa.return_value = sa

        d = get_policy_engine().authorize_command("nmap -sV example.com",
                                                   target="example.com")
        assert d.allowed

    def test_blocked_command_denied(self):
        d = get_policy_engine().authorize_command("rm -rf /")
        assert not d.allowed
        assert d.reason_code == DenyReason.COMMAND_BLOCKED.value


# ── authorize_exploit ───────────────────────────────────────────────────

class TestAuthorizeExploit:
    @patch("core.security.policy_engine.PolicyEngine._get_target_scope_validator")
    @patch("core.security.policy_engine.PolicyEngine._get_scope_authority")
    def test_authorized_exploit_allowed(self, mock_sa, mock_tsv):
        tsv = MagicMock()
        tsv.is_authorized.return_value = True
        tsv.authorized_scope = ["example.com"]
        mock_tsv.return_value = tsv
        sa = MagicMock()
        sa.enforcement_status.return_value = {}
        mock_sa.return_value = sa

        d = get_policy_engine().authorize_exploit("example.com", "sql_injection", "POC")
        assert d.allowed

    @patch("core.security.policy_engine.PolicyEngine._get_target_scope_validator")
    def test_out_of_scope_exploit_denied(self, mock_tsv):
        tsv = MagicMock()
        tsv.is_authorized.return_value = False
        mock_tsv.return_value = tsv

        d = get_policy_engine().authorize_exploit("evil.com", "sql_injection")
        assert not d.allowed
        assert d.reason_code == DenyReason.TARGET_OUT_OF_SCOPE.value


# ── authorize_network ───────────────────────────────────────────────────

class TestAuthorizeNetwork:
    def test_empty_denied(self):
        d = get_policy_engine().authorize_network("")
        assert not d.allowed

    @patch("core.security.policy_engine.PolicyEngine._get_target_scope_validator")
    @patch("core.security.policy_engine.PolicyEngine._get_scope_authority")
    @patch("core.security.egress_firewall.assert_egress_allowed")
    def test_allowed_egress(self, mock_egress, mock_sa, mock_tsv):
        mock_egress.return_value = None
        tsv = MagicMock()
        tsv.is_authorized.return_value = True
        mock_tsv.return_value = tsv
        sa = MagicMock()
        sa.enforcement_status.return_value = {}
        mock_sa.return_value = sa

        d = get_policy_engine().authorize_network("https://example.com")
        assert d.allowed


# ── authorize_tool ──────────────────────────────────────────────────────

class TestAuthorizeTool:
    @patch("core.security.action_gate.ActionGate.evaluate")
    def test_action_gate_deny_propagates(self, mock_eval):
        from core.security.action_gate import GateDecision
        mock_eval.return_value = GateDecision(
            allowed=False, stage="scope", reason="out of scope"
        )
        invocation = MagicMock()
        invocation.target = "evil.com"
        invocation.operation = "sql_injection"
        invocation.tool_id = "sqlmap"
        invocation.params = {}

        d = get_policy_engine().authorize_tool(invocation)
        assert not d.allowed

    @patch("core.decisions.policy_engine.enforce")
    @patch("core.security.action_gate.ActionGate.evaluate")
    def test_action_gate_allow(self, mock_eval, mock_enforce):
        from core.security.action_gate import GateDecision
        from core.decisions.policy_engine import PolicyVerdict
        mock_eval.return_value = GateDecision(
            allowed=True, stage="allow", reason="passed"
        )
        mock_enforce.return_value = PolicyVerdict(allow=True)
        invocation = MagicMock()
        invocation.target = "example.com"
        invocation.operation = "port_scan"
        invocation.tool_id = "nmap"
        invocation.params = {}

        d = get_policy_engine().authorize_tool(invocation)
        assert d.allowed


# ── Fail-closed guarantee ───────────────────────────────────────────────

class TestFailClosed:
    """Every error path must deny, never allow."""

    @patch("core.security.policy_engine.PolicyEngine._get_target_scope_validator")
    def test_scope_validator_crash_denies(self, mock_tsv):
        mock_tsv.side_effect = Exception("crash")
        d = get_policy_engine().authorize_target("example.com")
        assert not d.allowed

    @patch("core.security.policy_engine.PolicyEngine._get_target_scope_validator")
    @patch("core.security.policy_engine.PolicyEngine._get_scope_authority")
    def test_scope_authority_crash_denies(self, mock_sa, mock_tsv):
        tsv = MagicMock()
        tsv.is_authorized.return_value = True
        mock_tsv.return_value = tsv
        mock_sa.side_effect = Exception("crash")

        d = get_policy_engine().authorize_target("example.com")
        assert not d.allowed
