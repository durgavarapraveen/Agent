"""P0.1 — Unified Policy Engine.

Single authority for ALL authorization decisions. Every security-sensitive
execution path routes through here. Delegates to existing validators internally
but provides one API surface with structured, auditable decisions.

Architecture:
    Caller → PolicyEngine.authorize_*() → PolicyDecision
                 ↓ (internal)
        TargetScopeValidator   (host/IP scope)
        ScopeAuthority         (composite scope facade)
        ActionGate             (pre-execution tool pipeline)
        ComplianceGate         (technique authorization)
        AuthorizationService   (identity/action policies)
        CommandPolicyValidator  (command safety)
        EgressFirewall         (network egress)
        PolicyVerdict          (LLM vs CODE boundary)
"""
from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_POLICY_VERSION = "v1.0.0"


# ── Decision model ──────────────────────────────────────────────────────────

class PolicyAction(str, Enum):
    TARGET = "authorize_target"
    NETWORK = "authorize_network"
    TOOL = "authorize_tool"
    EXPLOIT = "authorize_exploit"
    COMMAND = "authorize_command"
    SUBPROCESS = "authorize_subprocess"
    BROWSER = "authorize_browser_request"
    RESOURCE = "authorize_resource"
    IDENTITY_ACTION = "authorize_identity_action"


class DenyReason(str, Enum):
    TARGET_OUT_OF_SCOPE = "TARGET_OUT_OF_SCOPE"
    TECHNIQUE_NOT_AUTHORIZED = "TECHNIQUE_NOT_AUTHORIZED"
    TIER_EXCEEDED = "TIER_EXCEEDED"
    COMMAND_BLOCKED = "COMMAND_BLOCKED"
    EGRESS_BLOCKED = "EGRESS_BLOCKED"
    IDENTITY_DENIED = "IDENTITY_DENIED"
    POLICY_ERROR = "POLICY_ERROR"
    NO_SCOPE_CONFIGURED = "NO_SCOPE_CONFIGURED"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    REDIRECT_OUT_OF_SCOPE = "REDIRECT_OUT_OF_SCOPE"
    PRIVATE_IP_BLOCKED = "PRIVATE_IP_BLOCKED"
    DNS_REBIND_BLOCKED = "DNS_REBIND_BLOCKED"
    SUBPROCESS_BLOCKED = "SUBPROCESS_BLOCKED"
    PRECONDITION_FAILED = "PRECONDITION_FAILED"


@dataclass(frozen=True)
class PolicyDecision:
    """Immutable, structured authorization decision."""
    allowed: bool
    action: str
    reason: str
    reason_code: Optional[str] = None
    action_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    policy_version: str = _POLICY_VERSION
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    target: Optional[str] = None
    detail: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "allowed": self.allowed,
            "action": self.action,
            "reason": self.reason,
            "reason_code": self.reason_code,
            "action_id": self.action_id,
            "policy_version": self.policy_version,
            "timestamp": self.timestamp,
        }
        if self.target:
            d["target"] = self.target
        if self.detail:
            d["detail"] = self.detail
        return d


def _allow(action: str, target: str = None, detail: Dict = None) -> PolicyDecision:
    return PolicyDecision(
        allowed=True, action=action, reason="authorized",
        target=target, detail=detail,
    )


def _deny(action: str, reason: str, code: DenyReason,
          target: str = None, detail: Dict = None) -> PolicyDecision:
    return PolicyDecision(
        allowed=False, action=action, reason=reason,
        reason_code=code.value, target=target, detail=detail,
    )


# ── Audit logger ────────────────────────────────────────────────────────────

class PolicyAuditLogger:
    """Structured audit trail for every policy decision."""

    def log(self, decision: PolicyDecision) -> None:
        if decision.allowed:
            logger.info(
                "[POLICY] ALLOW action=%s target=%s id=%s",
                decision.action, decision.target or "-", decision.action_id,
            )
        else:
            logger.warning(
                "[POLICY] DENY action=%s target=%s reason=%s code=%s id=%s",
                decision.action, decision.target or "-",
                decision.reason, decision.reason_code, decision.action_id,
            )


# ── Policy Engine ───────────────────────────────────────────────────────────

class PolicyEngine:
    """Single authority for all authorization decisions.

    Fail-closed on every error path. No `except: pass` on security checks.
    Returns structured PolicyDecision for every call.
    """

    _instance: Optional["PolicyEngine"] = None
    _lock = threading.RLock()

    @classmethod
    def get(cls) -> "PolicyEngine":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def set(cls, engine: "PolicyEngine") -> None:
        with cls._lock:
            cls._instance = engine

    @classmethod
    def reset_for_tests(cls) -> None:
        with cls._lock:
            cls._instance = None

    def __init__(self, audit: Optional[PolicyAuditLogger] = None):
        self._audit = audit or PolicyAuditLogger()
        from core.security.platform_contract import get_contract
        self._contract = get_contract()

    # ── helpers ──────────────────────────────────────────────────────────

    def _emit(self, decision: PolicyDecision) -> PolicyDecision:
        self._audit.log(decision)
        try:
            from core.security.platform_contract import _log_enforcement, EnforcementRecord
            _log_enforcement(EnforcementRecord(
                rule=f"policy.{decision.action}",
                passed=decision.allowed,
                detail=decision.reason,
                caller="PolicyEngine",
                context={"target": decision.target, "reason_code": decision.reason_code},
            ))
        except Exception:
            pass
        return decision

    def _get_target_scope_validator(self):
        from core.security.authorization import TargetScopeValidator
        return TargetScopeValidator.get()

    def _get_scope_authority(self):
        from core.security.scope_facade import get_scope_authority
        return get_scope_authority()

    # ── authorize_target ─────────────────────────────────────────────────

    def authorize_target(self, target: str) -> PolicyDecision:
        """Check if a target (host/IP/URL) is within authorized scope.

        Delegates to TargetScopeValidator (the most widely used validator)
        and ScopeAuthority (the composite facade). Both must agree.
        Fails closed on any error.
        """
        action = PolicyAction.TARGET.value
        if not target or not target.strip():
            return self._emit(_deny(
                action, "empty target", DenyReason.SCHEMA_INVALID,
            ))

        # 1) TargetScopeValidator
        try:
            tsv = self._get_target_scope_validator()
            if not tsv.is_authorized(target):
                return self._emit(_deny(
                    action, f"target '{target}' not in authorized scope",
                    DenyReason.TARGET_OUT_OF_SCOPE, target=target,
                ))
        except Exception as e:
            return self._emit(_deny(
                action, f"scope check error: {e}",
                DenyReason.POLICY_ERROR, target=target,
            ))

        # 2) ScopeAuthority (composite — also checks LegalValidator etc.)
        try:
            sa = self._get_scope_authority()
            status = sa.enforcement_status()
            # Only consult if at least one backend is wired
            if any(v for k, v in status.items() if k != "auto_scope_size"):
                if not sa.is_authorized(target):
                    return self._emit(_deny(
                        action, f"scope authority denied '{target}'",
                        DenyReason.TARGET_OUT_OF_SCOPE, target=target,
                    ))
        except Exception as e:
            return self._emit(_deny(
                action, f"scope authority error: {e}",
                DenyReason.POLICY_ERROR, target=target,
            ))

        return self._emit(_allow(action, target=target))

    # ── authorize_network ────────────────────────────────────────────────

    def authorize_network(self, url_or_host: str,
                          purpose: str = "scan") -> PolicyDecision:
        """Check if outbound network access to a destination is allowed.

        Delegates to NetworkBroker (DNS rebinding protection, redirect
        revalidation, private IP blocking) with EgressFirewall fallback.
        """
        action = PolicyAction.NETWORK.value
        if not url_or_host:
            return self._emit(_deny(
                action, "empty destination", DenyReason.SCHEMA_INVALID,
            ))

        # Try NetworkBroker first (P0.2) — full DNS rebinding + IP checks
        try:
            from core.network.network_broker import get_network_broker
            broker = get_network_broker()
            decision = broker.check_url(url_or_host)
            if not decision.allowed:
                code = {
                    "SCHEMA_INVALID": DenyReason.SCHEMA_INVALID,
                    "PRIVATE_IP_BLOCKED": DenyReason.PRIVATE_IP_BLOCKED,
                    "DNS_REBIND_BLOCKED": DenyReason.DNS_REBIND_BLOCKED,
                    "EGRESS_BLOCKED": DenyReason.EGRESS_BLOCKED,
                    "BUDGET_EXCEEDED": DenyReason.BUDGET_EXCEEDED,
                    "POLICY_ERROR": DenyReason.POLICY_ERROR,
                }.get(decision.reason_code, DenyReason.EGRESS_BLOCKED)
                return self._emit(_deny(
                    action, decision.reason, code, target=url_or_host,
                ))
            return self._emit(_allow(action, target=url_or_host,
                                     detail={"purpose": purpose}))
        except ImportError:
            pass
        except Exception as e:
            logger.debug("NetworkBroker unavailable, falling back: %s", e)

        # Fallback: EgressFirewall only (no DNS rebinding protection)
        try:
            from core.security.egress_firewall import assert_egress_allowed
            assert_egress_allowed(url_or_host, purpose)
        except Exception as e:
            ename = type(e).__name__
            if ename == "EgressBlocked" or "egress" in str(e).lower():
                return self._emit(_deny(
                    action, str(e), DenyReason.EGRESS_BLOCKED,
                    target=url_or_host,
                ))
            return self._emit(_deny(
                action, f"egress check error: {e}",
                DenyReason.POLICY_ERROR, target=url_or_host,
            ))

        # Also check target scope
        target_decision = self.authorize_target(url_or_host)
        if not target_decision.allowed:
            return self._emit(_deny(
                action, target_decision.reason,
                DenyReason.TARGET_OUT_OF_SCOPE, target=url_or_host,
            ))

        return self._emit(_allow(action, target=url_or_host,
                                 detail={"purpose": purpose}))

    # ── authorize_tool ───────────────────────────────────────────────────

    def authorize_tool(self, invocation, ctx=None,
                       tier: str = "POC") -> PolicyDecision:
        """Pre-execution gate for tool invocations.

        Runs ActionGate pipeline (schema→scope→precondition→duplicate→risk).
        Also checks ComplianceGate for technique authorization.
        """
        action = PolicyAction.TOOL.value
        target = (getattr(invocation, "target", None)
                  or (getattr(invocation, "params", None) or {}).get("target", ""))
        operation = getattr(invocation, "operation", "") or ""

        # 1) ActionGate
        try:
            from core.security.action_gate import ActionGate
            gate_decision = ActionGate.evaluate(invocation, ctx, tier)
            if not gate_decision.allowed:
                return self._emit(_deny(
                    action,
                    f"ActionGate denied at stage '{gate_decision.stage}': {gate_decision.reason}",
                    DenyReason.PRECONDITION_FAILED
                    if gate_decision.stage in ("schema", "precondition")
                    else DenyReason.TARGET_OUT_OF_SCOPE,
                    target=str(target),
                    detail={"stage": gate_decision.stage, "flags": gate_decision.flags},
                ))
        except Exception as e:
            return self._emit(_deny(
                action, f"ActionGate error: {e}",
                DenyReason.POLICY_ERROR, target=str(target),
            ))

        # 2) Command safety (if invocation carries a command)
        command = None
        params = getattr(invocation, "params", None) or {}
        if isinstance(params, dict):
            command = params.get("command") or params.get("cmd")
        if command:
            cmd_decision = self.authorize_command(command, target=str(target))
            if not cmd_decision.allowed:
                return cmd_decision

        # 3) Deterministic policy boundary
        try:
            from core.decisions.policy_engine import enforce
            for topic in ("tool_health", "duplicate_suppression", "waf_mode"):
                verdict = enforce(topic, {
                    "target": str(target),
                    "tool": getattr(invocation, "tool_id", ""),
                    "operation": operation,
                    "tool_category": operation,
                })
                if not verdict.allow:
                    return self._emit(_deny(
                        action, verdict.reason,
                        DenyReason.PRECONDITION_FAILED,
                        target=str(target),
                        detail=verdict.detail,
                    ))
        except ImportError:
            pass
        except Exception as e:
            logger.debug("policy_engine.enforce skipped: %s", e)

        return self._emit(_allow(action, target=str(target),
                                 detail={"operation": operation, "tier": tier}))

    # ── authorize_exploit ────────────────────────────────────────────────

    def authorize_exploit(self, target: str, technique: str = "auto",
                          tier: str = "POC") -> PolicyDecision:
        """Full exploit authorization: target scope + technique + tier.

        Delegates to ComplianceGate and AuthorizationManager.
        """
        action = PolicyAction.EXPLOIT.value

        # 1) Target must be in scope
        target_decision = self.authorize_target(target)
        if not target_decision.allowed:
            return self._emit(_deny(
                action, target_decision.reason,
                DenyReason.TARGET_OUT_OF_SCOPE, target=target,
            ))

        # 2) ComplianceGate — technique authorization
        try:
            from core.security.compliance_gate import (
                ComplianceGate as TechniqueGate,
                ScopeValidator as CompScopeValidator,
            )
            tsv = self._get_target_scope_validator()
            comp_validator = CompScopeValidator(
                authorized_targets=tsv.authorized_scope,
            )
            gate = TechniqueGate(scope_validator=comp_validator)
            result = gate.check_before_exploit(target, technique)
            if not result.authorized:
                return self._emit(_deny(
                    action, result.reason,
                    DenyReason.TECHNIQUE_NOT_AUTHORIZED, target=target,
                    detail={"technique": technique},
                ))
        except ImportError:
            pass
        except Exception as e:
            return self._emit(_deny(
                action, f"compliance check error: {e}",
                DenyReason.POLICY_ERROR, target=target,
            ))

        # 3) Tier check via AuthorizationManager
        try:
            from agents.authorization import AuthorizationManager, ExploitTier
            tier_map = {"POC": ExploitTier.POC, "SHALLOW": ExploitTier.SHALLOW,
                        "DEEP": ExploitTier.DEEP}
            exploit_tier = tier_map.get(tier.upper(), ExploitTier.POC)
            auth_mgr = AuthorizationManager()
            if not auth_mgr.verify_tier(exploit_tier):
                return self._emit(_deny(
                    action, f"tier '{tier}' exceeds max authorized tier",
                    DenyReason.TIER_EXCEEDED, target=target,
                    detail={"requested_tier": tier},
                ))
        except ImportError:
            pass
        except Exception as e:
            return self._emit(_deny(
                action, f"tier check error: {e}",
                DenyReason.POLICY_ERROR, target=target,
            ))

        return self._emit(_allow(action, target=target,
                                 detail={"technique": technique, "tier": tier}))

    # ── authorize_command ────────────────────────────────────────────────

    def authorize_command(self, command: str,
                          target: str = None) -> PolicyDecision:
        """Validate a shell command for safety before execution."""
        action = PolicyAction.COMMAND.value
        if not command or not isinstance(command, str):
            return self._emit(_deny(
                action, "empty or non-string command",
                DenyReason.SCHEMA_INVALID,
            ))

        # 1) CommandPolicyValidator
        try:
            from core.security.policy_validator import CommandPolicyValidator
            allowed, reason = CommandPolicyValidator.is_allowed(command)
            if not allowed:
                return self._emit(_deny(
                    action, reason or "command blocked by policy",
                    DenyReason.COMMAND_BLOCKED, target=target,
                    detail={"command_preview": command[:200]},
                ))
        except ImportError:
            pass
        except Exception as e:
            return self._emit(_deny(
                action, f"command policy error: {e}",
                DenyReason.POLICY_ERROR, target=target,
            ))

        # 2) Target scope validation on embedded hosts
        if target:
            target_decision = self.authorize_target(target)
            if not target_decision.allowed:
                return self._emit(_deny(
                    action, target_decision.reason,
                    DenyReason.TARGET_OUT_OF_SCOPE, target=target,
                ))

        # 3) TargetScopeValidator command extraction
        try:
            tsv = self._get_target_scope_validator()
            tsv.extract_and_validate_command(command)
        except Exception as e:
            ename = type(e).__name__
            if ename == "AuthorizationError" or "scope" in str(e).lower():
                return self._emit(_deny(
                    action, str(e), DenyReason.TARGET_OUT_OF_SCOPE,
                    target=target,
                    detail={"command_preview": command[:200]},
                ))
            return self._emit(_deny(
                action, f"command target extraction error: {e}",
                DenyReason.POLICY_ERROR, target=target,
            ))

        return self._emit(_allow(action, target=target,
                                 detail={"command_preview": command[:80]}))

    # ── authorize_subprocess ─────────────────────────────────────────────

    def authorize_subprocess(self, executable: str, args: List[str] = None,
                              target: str = None) -> PolicyDecision:
        """Gate for subprocess/exec calls. Validates command safety + scope."""
        action = PolicyAction.SUBPROCESS.value
        full_cmd = f"{executable} {' '.join(args or [])}"
        return self.authorize_command(full_cmd, target=target)

    # ── authorize_browser_request ────────────────────────────────────────

    def authorize_browser_request(self, url: str,
                                   purpose: str = "crawl") -> PolicyDecision:
        """Gate for browser/actuator HTTP requests."""
        action = PolicyAction.BROWSER.value
        if not url:
            return self._emit(_deny(
                action, "empty URL", DenyReason.SCHEMA_INVALID,
            ))
        return self.authorize_network(url, purpose=purpose)

    # ── authorize_resource ───────────────────────────────────────────────

    def authorize_resource(self, resource_type: str, resource_id: str,
                            identity: str = None,
                            action_name: str = None) -> PolicyDecision:
        """Gate for resource access (filesystem, DB, etc.)."""
        action = PolicyAction.RESOURCE.value

        # Delegate to AuthorizationService if identity/action provided
        if identity and action_name:
            try:
                from core.security.authorization_service import AuthorizationService
                svc = AuthorizationService()
                if not svc.check_authorized(resource_id, identity, action_name):
                    return self._emit(_deny(
                        action,
                        f"identity '{identity}' denied action '{action_name}' on '{resource_id}'",
                        DenyReason.IDENTITY_DENIED,
                        detail={"resource_type": resource_type,
                                "identity": identity, "action": action_name},
                    ))
            except ImportError:
                pass
            except Exception as e:
                return self._emit(_deny(
                    action, f"resource auth error: {e}",
                    DenyReason.POLICY_ERROR,
                ))

        return self._emit(_allow(action,
                                 detail={"resource_type": resource_type,
                                         "resource_id": resource_id}))

    # ── authorize_identity_action ────────────────────────────────────────

    def authorize_identity_action(self, target: str, identity: str,
                                   action_name: str) -> PolicyDecision:
        """Check if an identity is authorized for an action on a target."""
        action = PolicyAction.IDENTITY_ACTION.value
        try:
            from core.security.authorization_service import AuthorizationService
            svc = AuthorizationService()
            if not svc.check_authorized(target, identity, action_name):
                return self._emit(_deny(
                    action,
                    f"identity '{identity}' not authorized for '{action_name}' on '{target}'",
                    DenyReason.IDENTITY_DENIED, target=target,
                    detail={"identity": identity, "action": action_name},
                ))
        except ImportError:
            return self._emit(_deny(
                action, "AuthorizationService not available",
                DenyReason.POLICY_ERROR, target=target,
            ))
        except Exception as e:
            return self._emit(_deny(
                action, f"identity auth error: {e}",
                DenyReason.POLICY_ERROR, target=target,
            ))

        return self._emit(_allow(action, target=target,
                                 detail={"identity": identity,
                                         "action": action_name}))


# ── Module-level accessor ───────────────────────────────────────────────────

def get_policy_engine() -> PolicyEngine:
    """Use this everywhere. Single import, single authority."""
    return PolicyEngine.get()
