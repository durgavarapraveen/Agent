"""
Async human-in-the-loop escalation gates (Feature #2).

Replaces blocking TTY prompts with a file-backed approval queue so the agent can
run unattended: high-impact actions are parked as PENDING, an operator resolves
them out-of-band (CLI / API / generic webhook), and a safe default is applied on
timeout. No Slack dependency.
"""

from core.escalation.escalation_gate import (
    EscalationGate,
    ApprovalDecision,
    ApprovalStatus,
    RiskLevel,
    get_escalation_gate,
)

__all__ = [
    "EscalationGate",
    "ApprovalDecision",
    "ApprovalStatus",
    "RiskLevel",
    "get_escalation_gate",
]
