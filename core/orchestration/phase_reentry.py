from __future__ import annotations

from enum import Enum
from typing import Dict, Set


class DependencyEvent(str, Enum):
    NEW_HOST = "NEW_HOST"
    NEW_PORT = "NEW_PORT"
    NEW_API_SCHEMA = "NEW_API_SCHEMA"
    NEW_AUTH_CONTEXT = "NEW_AUTH_CONTEXT"
    NEW_ENDPOINT_CLASS = "NEW_ENDPOINT_CLASS"
    NEW_PARAMETER = "NEW_PARAMETER"
    POSITIVE_FINDING_SIGNAL = "POSITIVE_FINDING_SIGNAL"


# Which completed phase a given event justifies re-entering.
_EVENT_TARGET_PHASE: Dict[DependencyEvent, str] = {
    DependencyEvent.NEW_HOST: "RECON",
    DependencyEvent.NEW_PORT: "RECON",
    DependencyEvent.NEW_API_SCHEMA: "RECON",
    DependencyEvent.NEW_AUTH_CONTEXT: "ACTIVE_SCANNING",
    DependencyEvent.NEW_ENDPOINT_CLASS: "ACTIVE_SCANNING",
    DependencyEvent.NEW_PARAMETER: "ACTIVE_SCANNING",
    DependencyEvent.POSITIVE_FINDING_SIGNAL: "EXPLOITATION",
}


def snapshot_ctx(ctx) -> Dict[str, int]:
    def _n(attr):
        v = getattr(ctx, attr, None)
        try:
            return len(v) if v is not None else 0
        except Exception:
            return 0
    return {
        "hosts": _n("subdomains"),
        "endpoints": _n("endpoints"),
        "vulns": _n("vulnerabilities"),
        "sessions": _n("sessions"),
    }


class PhaseReentryController:
    def __init__(self, budget_per_phase: int = 2):
        self._default_budget = budget_per_phase
        self._budget: Dict[str, int] = {}
        self._pending: Set[DependencyEvent] = set()

    def signal(self, event) -> None:
        try:
            ev = event if isinstance(event, DependencyEvent) else DependencyEvent(str(event))
        except Exception:
            return
        self._pending.add(ev)

    def detect(self, prev: Dict[str, int], cur: Dict[str, int]) -> None:
        if cur.get("hosts", 0) > prev.get("hosts", 0):
            self.signal(DependencyEvent.NEW_HOST)
        if cur.get("endpoints", 0) > prev.get("endpoints", 0):
            self.signal(DependencyEvent.NEW_ENDPOINT_CLASS)
        if cur.get("vulns", 0) > prev.get("vulns", 0):
            self.signal(DependencyEvent.POSITIVE_FINDING_SIGNAL)
        if cur.get("sessions", 0) > prev.get("sessions", 0):
            self.signal(DependencyEvent.NEW_AUTH_CONTEXT)

    def remaining(self, phase: str) -> int:
        return self._budget.get(phase, self._default_budget)

    def consume_reentries(self, completed: Set[str]) -> Set[str]:
        if not self._pending:
            return completed
        completed = set(completed)
        events = list(self._pending)
        self._pending.clear()
        reentered: Set[str] = set()
        for ev in events:
            target = _EVENT_TARGET_PHASE.get(ev)
            if not target or target not in completed or target in reentered:
                continue
            if self._budget.get(target, self._default_budget) <= 0:
                continue
            self._budget[target] = self._budget.get(target, self._default_budget) - 1
            completed.discard(target)
            reentered.add(target)
        return completed
