from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock
from typing import Dict, List, Optional


class HypothesisState(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
    UNSUPPORTED = "UNSUPPORTED"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"


@dataclass
class Hypothesis:
    hyp_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    vuln_class: str = ""
    target: str = ""
    endpoint: str = ""
    parameter: str = ""
    rationale: str = ""
    required_evidence: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    priority: float = 0.5
    cost_estimate: float = 1.0        # relative — lower is cheaper
    state: HypothesisState = HypothesisState.OPEN
    next_action: str = ""

    def score(self) -> float:
        gap = max(1, len(self.required_evidence) - len(self.evidence_ids))
        return (self.priority * gap) / max(0.1, self.cost_estimate)


class HypothesisEngine:
    def __init__(self):
        self._store: Dict[str, Hypothesis] = {}
        self._lock = Lock()

    def add(self, h: Hypothesis) -> str:
        with self._lock:
            self._store[h.hyp_id] = h
        return h.hyp_id

    def get(self, hyp_id: str) -> Optional[Hypothesis]:
        with self._lock:
            return self._store.get(hyp_id)

    def update_state(self, hyp_id: str, new_state: HypothesisState,
                     add_evidence: Optional[List[str]] = None) -> None:
        with self._lock:
            h = self._store.get(hyp_id)
            if not h:
                return
            h.state = new_state
            if add_evidence:
                for e in add_evidence:
                    if e not in h.evidence_ids:
                        h.evidence_ids.append(e)

    def next_best_action(self) -> Optional[Hypothesis]:
        with self._lock:
            candidates = [h for h in self._store.values()
                          if h.state in (HypothesisState.OPEN,
                                         HypothesisState.NEEDS_EVIDENCE,
                                         HypothesisState.INVESTIGATING)]
        if not candidates:
            return None
        return max(candidates, key=lambda h: h.score())

    def open_hypotheses(self) -> List[Hypothesis]:
        with self._lock:
            return [h for h in self._store.values()
                    if h.state not in (HypothesisState.REJECTED,
                                        HypothesisState.CONFIRMED)]

    def summary(self) -> Dict[str, int]:
        with self._lock:
            out: Dict[str, int] = {}
            for h in self._store.values():
                out[h.state.value] = out.get(h.state.value, 0) + 1
            return out


_SINGLETON: Optional[HypothesisEngine] = None


def get_engine() -> HypothesisEngine:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = HypothesisEngine()
    return _SINGLETON
