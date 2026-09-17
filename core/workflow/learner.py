"""WorkflowLearner (gaps §1) — build a state machine from recorded steps:
states, transitions (with preconditions = consumed values), and invariants
(numeric/ownership constraints) that violation testing will try to break.

Structure is derived from data dependencies (deterministic). Semantic step
labels ("this is the payment step") are refined by the LLM when Bedrock is
available (§5); until then the deterministic path-label is used.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List

from core.workflow.recorder import WorkflowStep

logger = logging.getLogger(__name__)


@dataclass
class Invariant:
    kind: str            # positive_number / amount_matches / owner_is_session / monotonic_step
    field: str = ""
    detail: str = ""


@dataclass
class Transition:
    src: int
    dst: int
    preconditions: List[str] = field(default_factory=list)   # consumed value keys
    carried: Dict[str, str] = field(default_factory=dict)    # value passed src→dst


@dataclass
class Workflow:
    steps: List[WorkflowStep]
    transitions: List[Transition] = field(default_factory=list)
    invariants: List[Invariant] = field(default_factory=list)

    def ordered(self) -> List[WorkflowStep]:
        return sorted(self.steps, key=lambda s: s.index)

    def is_multi_step(self) -> bool:
        return len(self.steps) >= 2


class WorkflowLearner:
    def learn(self, steps: List[WorkflowStep]) -> Workflow:
        wf = Workflow(steps=steps)
        # transitions: consecutive steps + data-dependency edges
        for i in range(1, len(steps)):
            prev, cur = steps[i - 1], steps[i]
            carried = {k: v for k, v in cur.consumed.items()}
            wf.transitions.append(Transition(
                src=prev.index, dst=cur.index,
                preconditions=list(cur.consumed.keys()), carried=carried))
        wf.invariants = self._infer_invariants(steps)
        logger.info("WorkflowLearner: %d steps, %d transitions, %d invariants",
                    len(steps), len(wf.transitions), len(wf.invariants))
        return wf

    def _infer_invariants(self, steps: List[WorkflowStep]) -> List[Invariant]:
        inv: List[Invariant] = []
        for s in steps:
            for fld, val in s.numeric_fields.items():
                low = fld.lower()
                if any(t in low for t in ("qty", "quantity", "amount", "price", "total", "count")):
                    inv.append(Invariant("positive_number", field=fld,
                                         detail=f"{fld} observed = {val}; expected > 0"))
                if any(t in low for t in ("amount", "total", "price")):
                    inv.append(Invariant("amount_matches", field=fld,
                                         detail=f"{fld} should equal server-computed total"))
        # ownership: a value produced under this identity should not be usable by another
        for s in steps:
            for k in s.consumed:
                if any(t in k.lower() for t in ("user", "account", "owner")):
                    inv.append(Invariant("owner_is_session", field=k,
                                         detail=f"{k} must belong to the acting session"))
        # de-dup
        seen = set(); out = []
        for i in inv:
            key = (i.kind, i.field)
            if key not in seen:
                seen.add(key); out.append(i)
        return out
