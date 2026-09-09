"""
Finding state machine — enforces valid state transitions.
"""
from __future__ import annotations

from typing import Dict, List, Set

from core.findings.finding import Finding, FindingState

VALID_TRANSITIONS: Dict[FindingState, Set[FindingState]] = {
    FindingState.DISCOVERED: {FindingState.NORMALIZED, FindingState.VALIDATING},
    FindingState.NORMALIZED: {FindingState.DEDUPLICATED},
    FindingState.DEDUPLICATED: {FindingState.VALIDATION_PENDING},
    FindingState.VALIDATION_PENDING: {FindingState.VALIDATING},
    FindingState.VALIDATING: {
        FindingState.CONFIRMED,
        FindingState.REJECTED,
        FindingState.INCONCLUSIVE,
        FindingState.FALSE_POSITIVE,
    },
    FindingState.CONFIRMED: {FindingState.REPORTABLE, FindingState.SUPPRESSED},
    FindingState.REJECTED: set(),
    FindingState.INCONCLUSIVE: {FindingState.VALIDATING},
    FindingState.FALSE_POSITIVE: set(),
    FindingState.REPORTABLE: {FindingState.SUPPRESSED},
    FindingState.SUPPRESSED: set(),
}


class FindingStateMachine:

    def _transition(self, finding: Finding, new_state: FindingState) -> None:
        current = finding.state_enum
        allowed = VALID_TRANSITIONS.get(current, set())
        if new_state not in allowed:
            valid = [s.value for s in allowed]
            raise ValueError(
                f"Invalid transition {current.value} -> {new_state.value}. "
                f"Valid transitions from {current.value}: {valid}"
            )
        finding.update_state(new_state)

    def mark_validating(self, finding: Finding) -> None:
        self._transition(finding, FindingState.VALIDATING)

    def mark_confirmed(self, finding: Finding, evidence_ids: List[str],
                       bypass_gate: bool = False, reproduction_responses: Optional[List[Dict[str, Any]]] = None) -> None:
        if not bypass_gate:
            try:
                from core.verification.reproduction_gate import ReproductionGate
                rg = ReproductionGate()
                rg.check_reproducible(finding.finding_id, finding.to_dict(), responses=reproduction_responses)
                ok, repro_reason = rg.is_confirmation_allowed(finding.finding_id)
                if not ok:
                    raise ValueError(f"P0.8 reproduction gate rejected: {repro_reason}")
            except ImportError:
                pass

            try:
                from core.verification.finding_confirmation_gate import FindingConfirmationGate
                gate = FindingConfirmationGate()
                gate.register(finding.finding_id, finding.category or "GENERIC")
                stage, reason = gate.evaluate(finding.finding_id, finding.to_dict())
                if stage.value == "rejected":
                    raise ValueError(
                        f"P0.6 confirmation gate rejected: {reason}")
            except ImportError:
                pass
        self._transition(finding, FindingState.CONFIRMED)
        finding.evidence_ids.extend(evidence_ids)

    def mark_rejected(self, finding: Finding, reason: str) -> None:
        self._transition(finding, FindingState.REJECTED)
        finding.rejection_reason = reason

    def mark_inconclusive(self, finding: Finding, reason: str) -> None:
        self._transition(finding, FindingState.INCONCLUSIVE)
        finding.rejection_reason = reason

    def mark_false_positive(self, finding: Finding, reason: str) -> None:
        self._transition(finding, FindingState.FALSE_POSITIVE)
        finding.rejection_reason = reason

    def mark_reportable(self, finding: Finding) -> None:
        self._transition(finding, FindingState.REPORTABLE)

    def mark_suppressed(self, finding: Finding, reason: str) -> None:
        self._transition(finding, FindingState.SUPPRESSED)
        finding.rejection_reason = reason
