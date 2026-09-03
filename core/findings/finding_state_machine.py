from __future__ import annotations

from typing import Dict, List, Optional, Set

from core.findings.finding import Finding, FindingState

VALID_TRANSITIONS: Dict[FindingState, Set[FindingState]] = {
    FindingState.DISCOVERED: {FindingState.VALIDATING},
    FindingState.VALIDATING: {FindingState.CONFIRMED, FindingState.REJECTED, FindingState.INCONCLUSIVE},
    FindingState.CONFIRMED: set(),
    FindingState.REJECTED: set(),
    FindingState.INCONCLUSIVE: {FindingState.VALIDATING},
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

    def mark_confirmed(self, finding: Finding, evidence_ids: List[str]) -> None:
        self._transition(finding, FindingState.CONFIRMED)
        finding.evidence_ids.extend(evidence_ids)

    def mark_rejected(self, finding: Finding, reason: str) -> None:
        self._transition(finding, FindingState.REJECTED)
        finding.rejection_reason = reason

    def mark_inconclusive(self, finding: Finding, reason: str) -> None:
        self._transition(finding, FindingState.INCONCLUSIVE)
        finding.rejection_reason = reason
