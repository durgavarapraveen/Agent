"""
P3-3: decision provenance.

Every action taken by the agent gets a Decision record with its
parent (what triggered it), the reason, and the artifacts it touched.
This is what makes the autonomous system explainable — if a scan
made a weird call, you can walk the chain back.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from threading import Lock
from time import time
from typing import Any, Dict, List, Optional


@dataclass
class Decision:
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_decision_id: str = ""
    topic: str = ""                  # e.g. "tool_call", "phase_transition"
    reason: str = ""                 # human-readable why
    evidence_ids: List[str] = field(default_factory=list)
    hypothesis_id: str = ""
    policy_result: str = ""          # "allow" | "deny" | "n/a"
    selected_tool: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "parent_decision_id": self.parent_decision_id,
            "topic": self.topic, "reason": self.reason,
            "evidence_ids": list(self.evidence_ids),
            "hypothesis_id": self.hypothesis_id,
            "policy_result": self.policy_result,
            "selected_tool": self.selected_tool,
            "payload": self.payload,
            "created_at": self.created_at,
        }


class DecisionLog:
    def __init__(self):
        self._store: Dict[str, Decision] = {}
        self._children: Dict[str, List[str]] = {}
        self._lock = Lock()

    def record(self, decision: Decision) -> str:
        with self._lock:
            self._store[decision.decision_id] = decision
            if decision.parent_decision_id:
                self._children.setdefault(decision.parent_decision_id, []).append(decision.decision_id)
        try:
            from core.observability.structured_logger import log_decision
            log_decision(decision.decision_id, decision.topic,
                         verdict=decision.policy_result or "n/a",
                         reason=decision.reason,
                         parent_id=decision.parent_decision_id,
                         selected_tool=decision.selected_tool,
                         hypothesis_id=decision.hypothesis_id)
        except Exception:
            pass
        return decision.decision_id

    def new(self, topic: str, reason: str, parent_id: str = "",
            **extra: Any) -> Decision:
        d = Decision(topic=topic, reason=reason,
                     parent_decision_id=parent_id, payload=extra)
        self.record(d)
        return d

    def chain(self, decision_id: str) -> List[Decision]:
        """Walk ancestor chain root-first."""
        out: List[Decision] = []
        cur = self._store.get(decision_id)
        while cur:
            out.append(cur)
            cur = self._store.get(cur.parent_decision_id) if cur.parent_decision_id else None
        return list(reversed(out))

    def children_of(self, decision_id: str) -> List[Decision]:
        return [self._store[c] for c in self._children.get(decision_id, [])
                if c in self._store]

    def snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [d.as_dict() for d in self._store.values()]


_SINGLETON: Optional[DecisionLog] = None


def get_decision_log() -> DecisionLog:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = DecisionLog()
    return _SINGLETON
