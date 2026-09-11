"""Phase 1.2 — Workflow state-machine crawler.

Multi-step flows (signup, checkout, password reset) encode business rules in
their *ordering*: you must add to cart before checkout, verify email before
login, etc. This module turns an observed request sequence into a state machine
(nodes = states, edges = request transitions), classifies each transition as
required (state-changing) or optional (idempotent navigation), and generates
negative test cases — skip a step, replay a step, reorder steps, or jump
straight to the final state.

Reuse:
  * ``WorkflowInventory`` (core.attack_surface.workflow_inventory) groups captured
    requests into per-session flows — used by :meth:`build_from_captured`.
  * ``RequestCapturer`` / ``BrowserActuator`` drive Playwright for live capture.
  * Generated test cases materialize into request dicts consumable by
    ``WorkflowInterceptor`` (Phase 1.1) for actual replay.

The state-machine construction and test-case generation are pure and fully
unit-testable against a synthetic step list — no browser or target required.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlparse

logger = logging.getLogger(__name__)

STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_NUM_SEG = re.compile(r"^\d+$")
_UUID_SEG = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                       r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_SEG = re.compile(r"^[0-9a-fA-F]{16,}$")


def normalize_path(url_or_path: str) -> str:
    """Collapse id-like path segments to ``{id}`` so /cart/42 and /cart/99 map
    to the same workflow state."""
    path = urlparse(url_or_path).path if "://" in url_or_path else url_or_path
    if not path:
        return "/"
    segs = []
    for seg in path.split("/"):
        if not seg:
            continue
        if _NUM_SEG.match(seg) or _UUID_SEG.match(seg) or _HEX_SEG.match(seg):
            segs.append("{id}")
        else:
            segs.append(seg)
    return "/" + "/".join(segs) if segs else "/"


@dataclass
class WorkflowStep:
    index: int
    method: str
    url: str
    path: str
    params: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    status: int = 0
    resource_type: str = ""
    post_data: str = ""

    @property
    def state_changing(self) -> bool:
        return self.method.upper() in STATE_CHANGING

    @classmethod
    def from_request(cls, req: Any, index: int) -> "WorkflowStep":
        def _g(k, default=None):
            if isinstance(req, dict):
                return req.get(k, default)
            return getattr(req, k, default)

        url = _g("url", "") or ""
        method = (_g("method", "GET") or "GET").upper()
        params = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        cookies = _g("cookies", {}) or {}
        if isinstance(cookies, str):  # raw cookie header
            cookies = dict(parse_qsl(cookies.replace("; ", "&"), keep_blank_values=True))
        return cls(
            index=index, method=method, url=url, path=normalize_path(url),
            params=params, cookies=dict(cookies) if isinstance(cookies, dict) else {},
            status=int(_g("status", 0) or 0),
            resource_type=_g("resource_type", "") or "",
            post_data=_g("post_data", "") or _g("body", "") or "",
        )


@dataclass
class WorkflowTransition:
    src: str
    dst: str
    method: str
    path: str
    step_index: int
    required: bool


@dataclass
class WorkflowTestCase:
    kind: str                       # skip_step | replay_step | reorder | direct_access_final
    description: str
    step_sequence: List[int]        # indices into the original steps
    target_step: int = -1


class WorkflowStateMachine:
    """A directed state machine for one observed flow."""

    ENTRY = "ENTRY"

    def __init__(self, name: str = "workflow"):
        self.name = name
        self.steps: List[WorkflowStep] = []
        self.states: Dict[str, str] = {self.ENTRY: "entry"}
        self.transitions: List[WorkflowTransition] = []

    def _state_id(self, step: WorkflowStep) -> str:
        return f"S{step.index}:{step.method}:{step.path}"

    def add_step(self, step: WorkflowStep) -> None:
        src = self.ENTRY if not self.steps else self._state_id(self.steps[-1])
        dst = self._state_id(step)
        self.states[dst] = f"{step.method} {step.path}"
        self.transitions.append(WorkflowTransition(
            src=src, dst=dst, method=step.method, path=step.path,
            step_index=step.index, required=step.state_changing))
        self.steps.append(step)

    def required_transitions(self) -> List[WorkflowTransition]:
        return [t for t in self.transitions if t.required]

    def optional_transitions(self) -> List[WorkflowTransition]:
        return [t for t in self.transitions if not t.required]

    @property
    def terminal_index(self) -> int:
        # Last state-changing step is the meaningful terminal (e.g. "pay");
        # fall back to the final step.
        sc = [s.index for s in self.steps if s.state_changing]
        return sc[-1] if sc else (self.steps[-1].index if self.steps else -1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "states": self.states,
            "transitions": [t.__dict__ for t in self.transitions],
            "required_steps": [t.step_index for t in self.required_transitions()],
            "terminal_index": self.terminal_index,
        }


class WorkflowCrawler:

    def __init__(self, max_steps: int = 50):
        self.max_steps = max_steps

    # ── Building ─────────────────────────────────────────────────────────────
    def build_from_requests(self, requests: List[Any], name: str = "workflow") -> WorkflowStateMachine:
        sm = WorkflowStateMachine(name=name)
        for i, req in enumerate(list(requests)[: self.max_steps]):
            sm.add_step(WorkflowStep.from_request(req, i))
        return sm

    def build_from_captured(self, requests: List[Any]) -> List[WorkflowStateMachine]:
        """Split a mixed capture into per-session flows via WorkflowInventory,
        then build a state machine for each."""
        try:
            from core.attack_surface.workflow_inventory import WorkflowInventory
            inv = WorkflowInventory()
            workflows = inv.discover_workflows_from_requests(requests)
        except Exception as e:
            logger.debug("workflow_crawler: inventory grouping unavailable (%s); "
                         "treating capture as one linear flow", e)
            workflows = []

        if not workflows:
            return [self.build_from_requests(requests)] if requests else []

        by_id = {getattr(r, "request_id", None): r for r in requests}
        machines: List[WorkflowStateMachine] = []
        for wf in workflows:
            reqs = [by_id[rid] for rid in getattr(wf, "request_ids", []) if rid in by_id]
            if len(reqs) >= 2:
                machines.append(self.build_from_requests(reqs, name=getattr(wf, "name", "workflow")))
        return machines

    def crawl(self, start_url: str, actions: Optional[List[Dict[str, Any]]] = None
              ) -> List[WorkflowStateMachine]:
        """Live capture via Playwright, then build state machines. Uses
        RequestCapturer's crawl (reuse); a scripted flow can be supplied via
        `actions` for BrowserActuator. Returns [] if capture yields nothing."""
        try:
            from core.exploitation.request_capture import RequestCapturer
            result = RequestCapturer().capture(start_url)
            reqs = result.api_requests() if hasattr(result, "api_requests") else []
            if not reqs:
                return []
            return self.build_from_captured(reqs)
        except Exception as e:
            logger.warning("workflow_crawler.crawl(%s) failed: %s", start_url, e)
            return []

    # ── Test-case generation ─────────────────────────────────────────────────
    def generate_test_cases(self, sm: WorkflowStateMachine) -> List[WorkflowTestCase]:
        cases: List[WorkflowTestCase] = []
        all_idx = [s.index for s in sm.steps]
        if len(all_idx) < 2:
            return cases
        terminal = sm.terminal_index

        # Skip each required (state-changing) prerequisite, still attempt terminal.
        for t in sm.required_transitions():
            if t.step_index == terminal:
                continue
            seq = [i for i in all_idx if i != t.step_index]
            cases.append(WorkflowTestCase(
                "skip_step",
                f"skip required step {t.step_index} ({t.method} {t.path}), reach terminal",
                seq, target_step=terminal))

        # Jump directly to the terminal state (force-browse the final action).
        if terminal >= 0:
            cases.append(WorkflowTestCase(
                "direct_access_final",
                f"access terminal step {terminal} directly",
                [terminal], target_step=terminal))

        # Reorder adjacent state-changing steps.
        sc = [s.index for s in sm.steps if s.state_changing]
        for a, b in zip(sc, sc[1:]):
            seq = list(all_idx)
            ia, ib = seq.index(a), seq.index(b)
            seq[ia], seq[ib] = seq[ib], seq[ia]
            cases.append(WorkflowTestCase(
                "reorder", f"reorder steps {a} and {b}", seq, target_step=b))

        # Replay (duplicate) each state-changing step.
        for i in sc:
            seq = list(all_idx)
            seq.insert(seq.index(i) + 1, i)
            cases.append(WorkflowTestCase(
                "replay_step", f"replay step {i}", seq, target_step=i))

        return cases

    @staticmethod
    def materialize(test_case: WorkflowTestCase, sm: WorkflowStateMachine) -> List[Dict[str, Any]]:
        """Turn a test case's step index sequence into replayable request dicts
        (consumable by WorkflowInterceptor's replayer)."""
        by_index = {s.index: s for s in sm.steps}
        out: List[Dict[str, Any]] = []
        for i in test_case.step_sequence:
            s = by_index.get(i)
            if s is None:
                continue
            out.append({"method": s.method, "url": s.url,
                        "headers": {}, "post_data": s.post_data})
        return out
