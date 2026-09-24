"""Canonical finding lifecycle (spec Phase 6).

The codebase carried two divergent status vocabularies —
``core.domain.finding.FindingState`` (CANDIDATE/VALIDATED/REJECTED/MITIGATED)
and ``core.common.schemas`` status (OBSERVED/CANDIDATE/VALIDATING/CONFIRMED/
REJECTED) — and neither distinguished a *validated* vulnerability from an
*exploited* one or from *proven impact*. This module is the single source of
truth for the ordered lifecycle the spec requires:

    OBSERVED → SUSPECTED → REPRODUCED → VALIDATED → EXPLOITED → IMPACT_CONFIRMED
                                                          (REJECTED is terminal)

Findings mostly travel as plain dicts, so the helpers operate on dicts as well
as the pydantic model. Transitions are guarded and forward-only (any state may
move to REJECTED); IMPACT_CONFIRMED and REJECTED are terminal. Nothing here
uses an LLM — advancement is a deterministic, auditable rule.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional, Tuple


class FindingLifecycle(str, Enum):
    OBSERVED = "OBSERVED"                 # a scanner/tool saw something
    SUSPECTED = "SUSPECTED"              # looks like a vuln, unconfirmed
    REPRODUCED = "REPRODUCED"           # behavior reproduced deterministically
    VALIDATED = "VALIDATED"            # confirmed a real vulnerability
    EXPLOITED = "EXPLOITED"           # exploitation actually demonstrated
    IMPACT_CONFIRMED = "IMPACT_CONFIRMED"  # authorized proof-of-impact captured
    REJECTED = "REJECTED"           # disproven / false positive (terminal)


_ORDER = {
    FindingLifecycle.OBSERVED: 0,
    FindingLifecycle.SUSPECTED: 1,
    FindingLifecycle.REPRODUCED: 2,
    FindingLifecycle.VALIDATED: 3,
    FindingLifecycle.EXPLOITED: 4,
    FindingLifecycle.IMPACT_CONFIRMED: 5,
}
_TERMINAL = {FindingLifecycle.IMPACT_CONFIRMED, FindingLifecycle.REJECTED}


def rank(state: FindingLifecycle) -> int:
    return _ORDER.get(state, -1)


def can_transition(current: FindingLifecycle, target: FindingLifecycle) -> bool:
    """Forward-only along the chain; any non-terminal state may be REJECTED."""
    if current == target:
        return True
    if current in _TERMINAL:
        return False
    if target == FindingLifecycle.REJECTED:
        return True
    if current == FindingLifecycle.REJECTED:
        return False
    return rank(target) > rank(current)


def advance(current: FindingLifecycle, target: FindingLifecycle) -> FindingLifecycle:
    """Return target if the transition is allowed, else keep current."""
    return target if can_transition(current, target) else current


# ── legacy vocab mapping (both directions, non-destructive) ─────────────
_LEGACY_IN = {
    "OBSERVED": FindingLifecycle.OBSERVED,
    "CANDIDATE": FindingLifecycle.SUSPECTED,
    "SUSPECTED": FindingLifecycle.SUSPECTED,
    "VALIDATING": FindingLifecycle.REPRODUCED,
    "REPRODUCED": FindingLifecycle.REPRODUCED,
    "CONFIRMED": FindingLifecycle.VALIDATED,
    "VALIDATED": FindingLifecycle.VALIDATED,
    "EXPLOITED": FindingLifecycle.EXPLOITED,
    "IMPACT_CONFIRMED": FindingLifecycle.IMPACT_CONFIRMED,
    "REJECTED": FindingLifecycle.REJECTED,
    "MITIGATED": FindingLifecycle.VALIDATED,  # was real; now fixed
}


def from_legacy(status: Optional[str]) -> FindingLifecycle:
    if not status:
        return FindingLifecycle.OBSERVED
    return _LEGACY_IN.get(str(status).strip().upper(), FindingLifecycle.OBSERVED)


def to_legacy_state(state: FindingLifecycle) -> str:
    """Map back to core.domain.finding.FindingState values."""
    if state == FindingLifecycle.REJECTED:
        return "REJECTED"
    if rank(state) >= rank(FindingLifecycle.VALIDATED):
        return "VALIDATED"
    return "CANDIDATE"


# ── dict-finding helpers (findings usually travel as dicts) ─────────────
def infer_lifecycle(finding: Dict[str, Any]) -> FindingLifecycle:
    """Best-effort lifecycle from whatever signals a finding dict already has.

    Precedence: explicit ``lifecycle`` → impact/exploit evidence → legacy
    status/state fields → OBSERVED. Never regresses below what evidence proves.
    """
    if not isinstance(finding, dict):
        return FindingLifecycle.OBSERVED
    explicit = finding.get("lifecycle")
    if explicit:
        try:
            return FindingLifecycle(str(explicit).upper())
        except ValueError:
            pass

    if finding.get("impact_confirmed") or finding.get("impact_proven"):
        return FindingLifecycle.IMPACT_CONFIRMED
    if finding.get("exploited") or finding.get("exploit_confirmed"):
        return FindingLifecycle.EXPLOITED

    legacy = (finding.get("status") or finding.get("finding_state")
              or finding.get("state"))
    base = from_legacy(legacy)

    # A confirmed flag or attached evidence lifts an unconfirmed base to VALIDATED.
    if base == FindingLifecycle.OBSERVED and (
            finding.get("confirmed") or finding.get("evidence")
            or finding.get("evidence_ids")):
        base = FindingLifecycle.VALIDATED
    return base


def set_lifecycle(finding: Dict[str, Any],
                  target: FindingLifecycle) -> Tuple[FindingLifecycle, bool]:
    """Advance a finding dict's lifecycle under the transition guard.

    Returns (new_state, changed). Writes both ``lifecycle`` and a legacy-friendly
    ``finding_state`` so existing consumers keep working.
    """
    current = infer_lifecycle(finding)
    new = advance(current, target)
    finding["lifecycle"] = new.value
    finding["finding_state"] = to_legacy_state(new)
    return new, (new != current)
