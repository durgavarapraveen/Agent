"""Human-in-the-loop (HITL) choke for critical tasks.

A single, consistent gate every *critical* task must pass before it executes —
so no outward / state-changing / irreversible action runs autonomously unless the
operator explicitly opted into autonomy. Wraps the existing `EscalationGate`
(interactive prompt when attended, approval queue + safe-default-deny when
unattended) and the consent/auto-approve flags, so callers get one function
instead of re-implementing the pattern.

Critical-task kinds and their default risk are declared in `CRITICAL_TASKS`;
`request_approval` auto-approves anything at or below `AUTO_APPROVE_MAX_RISK`
(default MEDIUM), so HIGH/CRITICAL tasks require a human decision by default.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Critical task kind -> default risk name. These are the outward / state-changing
# / irreversible actions that must not run autonomously by default.
CRITICAL_TASKS: Dict[str, str] = {
    "account_creation": "HIGH",        # self-registration creates real accounts
    "file_upload": "HIGH",             # writes a file to the target
    "state_change": "HIGH",            # active state-changing request (biz-logic/workflow/race)
    "active_write": "HIGH",
    "shared_side_effect": "HIGH",      # affects OTHER users (cache poisoning, req smuggling)
    "denial_of_service": "HIGH",       # amplification / resource-exhaustion probing
    "credential_spray": "HIGH",        # authentication attempts against real accounts
    "msf_module": "HIGH",              # metasploit module dispatch
    "exploit_detonation": "CRITICAL",  # running a synthesized exploit
    "post_exploit": "CRITICAL",        # post-exploitation actions on a foothold
    "lateral_movement": "CRITICAL",
    "persistence": "CRITICAL",
    "data_exfiltration": "CRITICAL",
}


def _auto_approved() -> bool:
    """Operator explicitly opted into autonomy (consent flag or env)."""
    try:
        from core.security.consent import get_consent
        if get_consent().auto_approve:
            return True
    except Exception:
        pass
    return os.getenv("AUTO_APPROVE_EXPLOITS", "").lower() in ("1", "true", "yes")


async def require_human_approval(
    action: str,
    kind: str = "",
    target: str = "",
    risk: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ctx: Any = None,
) -> bool:
    """Gate a critical task on human approval. Returns True to proceed.

    - Honors consent.auto_approve / AUTO_APPROVE_EXPLOITS (operator opted into
      autonomy) — then proceeds without prompting.
    - Otherwise routes through the EscalationGate: MEDIUM-and-below auto-approve;
      HIGH/CRITICAL prompt (attended) or queue + wait (unattended), denying on
      timeout by default. Fail-closed: any gate error → DENY.
    """
    details = dict(details or {})
    details.setdefault("kind", kind)
    if _auto_approved():
        logger.info("[HITL] auto-approved '%s' (operator opted into autonomy)", action)
        _record(ctx, action, kind, target, True, "auto")
        return True
    try:
        from core.escalation import get_escalation_gate, RiskLevel
        risk_name = risk or CRITICAL_TASKS.get(kind, "HIGH")
        decision = await get_escalation_gate().request_approval(
            action=action, risk_level=RiskLevel.parse(risk_name, RiskLevel.HIGH),
            target=target, details=details)
        approved = bool(getattr(decision, "approved", False))
        logger.info("[HITL] '%s' (%s) -> %s", action, kind or "critical",
                    getattr(decision, "status", "?"))
        _record(ctx, action, kind, target, approved, getattr(decision, "status", ""))
        return approved
    except Exception as e:
        logger.warning("[HITL] gate error for '%s' — DENY (fail-closed): %s", action, e)
        _record(ctx, action, kind, target, False, "gate_error")
        return False


def _record(ctx, action, kind, target, approved, status) -> None:
    """Best-effort audit trail of the HITL decision on ctx (for the deconfliction
    log / report). Never raises."""
    if ctx is None:
        return
    try:
        store = getattr(ctx, "hitl_decisions", None)
        if not isinstance(store, list):
            store = []
        store.append({"action": action, "kind": kind, "target": target,
                      "approved": bool(approved), "status": str(status)})
        setattr(ctx, "hitl_decisions", store)
    except Exception:
        pass
