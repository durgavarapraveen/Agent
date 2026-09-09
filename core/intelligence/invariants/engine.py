"""
Security-invariant engine (spec P1.4 / Point F / Point K).

Runs the invariant library over collected response snapshots and reports
violations. This is an *oracle* layer: it consumes responses already gathered
by executors/recon (no new traffic of its own) and turns broken assumptions
into evidence-backed observations. It never declares a confirmed vulnerability;
it hands anomalies to the hypothesis/adjudication pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.intelligence.differential.comparison import ResponseSnapshot
from core.intelligence.invariants.library import BUILTIN_INVARIANTS, SecurityInvariant


@dataclass
class InvariantViolation:
    invariant: str
    category: str
    severity: str
    detail: str
    response_label: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "invariant": self.invariant, "category": self.category,
            "severity": self.severity, "detail": self.detail,
            "response_label": self.response_label,
            **{f"ev_{k}": v for k, v in self.evidence.items()},
        }


class InvariantEngine:
    def __init__(self, invariants: Optional[List[SecurityInvariant]] = None) -> None:
        self._invariants = invariants if invariants is not None else BUILTIN_INVARIANTS

    def check(self, snap: ResponseSnapshot) -> List[InvariantViolation]:
        out: List[InvariantViolation] = []
        for inv in self._invariants:
            try:
                detail = inv.check(snap)
            except Exception:
                detail = None
            if detail:
                out.append(InvariantViolation(
                    invariant=inv.name, category=inv.category, severity=inv.severity,
                    detail=detail, response_label=snap.label,
                    evidence={"status": snap.status, "body_hash": snap.body_hash},
                ))
        return out

    def check_all(self, snapshots: List[ResponseSnapshot]) -> List[InvariantViolation]:
        out: List[InvariantViolation] = []
        for s in snapshots:
            out.extend(self.check(s))
        return out

    @staticmethod
    def check_auth_pair(success: ResponseSnapshot,
                        failure: ResponseSnapshot) -> Optional[InvariantViolation]:
        """Point K/R: a *failed* auth must not establish a session that a
        *successful* auth establishes. Violated when the failure response sets a
        session cookie of the same name the success response sets."""
        def session_cookies(snap: ResponseSnapshot) -> set:
            names = set()
            for k, v in snap.headers.items():
                if k.lower() == "set-cookie" and "=" in v:
                    name = v.split("=", 1)[0].strip().lower()
                    if any(t in name for t in ("sess", "sid", "auth", "token", "jwt")):
                        names.add(name)
            return names
        shared = session_cookies(success) & session_cookies(failure)
        if shared and failure.status >= 400:
            return InvariantViolation(
                invariant="failed_auth_no_session", category="authn", severity="high",
                detail=f"failed auth ({failure.status}) set session cookie(s) "
                       f"{sorted(shared)} that successful auth also sets",
                response_label=failure.label,
                evidence={"success_status": success.status, "failure_status": failure.status},
            )
        return None
