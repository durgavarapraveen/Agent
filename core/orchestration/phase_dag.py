from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Set


@dataclass
class PhaseNode:
    name: str
    depends_on: Set[str]
    # Returns True if `ctx` has the evidence this phase needs to be useful.
    prereq_predicate: Callable[[object], bool]
    # Returns True after the phase has produced its expected output.
    completion_predicate: Callable[[object], bool]


def _has_endpoints(ctx) -> bool:
    return bool(getattr(ctx, "endpoints", None) or getattr(ctx, "subdomains", None))


def _has_vulns(ctx) -> bool:
    return bool(getattr(ctx, "vulnerabilities", None))


def _has_exploits(ctx) -> bool:
    return bool(getattr(ctx, "exploit_results", None))


def _always_true(_ctx) -> bool:
    return True


# ── P1-F1: convergence-based completion ──────────────────────────────────
def _convergence_threshold() -> float:
    """Coverage fraction (0..1) at which a scanning/exploitation phase is
    considered done. Generic, env-tunable; defaults to a demanding 0.85."""
    try:
        return float(os.getenv("CONVERGENCE_THRESHOLD", "0.85"))
    except Exception:
        return 0.85


def _convergence_frac(ctx) -> Optional[float]:
    """Read the live convergence/coverage score for `ctx` and normalize it to a
    0..1 fraction. Returns None when no convergence engine is reachable (the
    predicate then falls back to the presence-based check). Fully generic — walks
    a brain back-reference if one is exposed on ctx, else a ctx-level engine."""
    brain = getattr(ctx, "brain", None) or getattr(ctx, "_brain", None)
    eng = (getattr(brain, "convergence_engine", None) if brain is not None
           else None) or getattr(ctx, "convergence_engine", None)
    if eng is None:
        return None
    fn = getattr(eng, "calculate_convergence", None)
    if not callable(fn):
        return None
    try:
        v = float(fn())
    except Exception:
        return None
    # Normalize a 0..100 percentage to a 0..1 fraction.
    if v > 1.5:
        v = v / 100.0
    return max(0.0, min(1.0, v))


def _scanning_complete(ctx) -> bool:
    # An elite team keeps scanning until coverage says so — not until finding #1.
    # Requires at least one finding AND convergence past threshold; degrades to
    # the presence check when convergence isn't wired (e.g. unit contexts).
    c = _convergence_frac(ctx)
    if c is None:
        return _has_vulns(ctx)
    return c >= _convergence_threshold()


def _exploitation_complete(ctx) -> bool:
    c = _convergence_frac(ctx)
    if c is None:
        return _has_exploits(ctx)
    return _has_exploits(ctx) and c >= _convergence_threshold()


def default_dag() -> Dict[str, PhaseNode]:
    return {
        "BUSINESS_UNDERSTANDING": PhaseNode(
            name="BUSINESS_UNDERSTANDING",
            depends_on=set(),
            prereq_predicate=_always_true,
            completion_predicate=_always_true,
        ),
        "RECON": PhaseNode(
            name="RECON",
            depends_on=set(),
            prereq_predicate=_always_true,
            completion_predicate=_has_endpoints,
        ),
        "ACTIVE_SCANNING": PhaseNode(
            name="ACTIVE_SCANNING",
            depends_on={"RECON"},
            prereq_predicate=_has_endpoints,   # don't scan blindly
            completion_predicate=_scanning_complete,  # P1-F1: coverage-based
        ),
        "EXPLOITATION": PhaseNode(
            name="EXPLOITATION",
            depends_on={"ACTIVE_SCANNING"},
            prereq_predicate=_has_vulns,
            completion_predicate=_exploitation_complete,  # P1-F1: coverage-based
        ),
        "REPORTING": PhaseNode(
            name="REPORTING",
            depends_on={"ACTIVE_SCANNING"},
            prereq_predicate=lambda ctx: _has_vulns(ctx) or _has_endpoints(ctx),
            completion_predicate=_always_true,
        ),
    }


class PhaseScheduler:

    def __init__(self, dag: Dict[str, PhaseNode], allowed: Optional[Set[str]] = None):
        self.dag = dag
        self.allowed = allowed or set(dag.keys())

    def next_ready(self, ctx, completed: Set[str]) -> Optional[str]:
        for name, node in self.dag.items():
            if name in completed or name not in self.allowed:
                continue
            if not node.depends_on.issubset(completed):
                continue
            if not node.prereq_predicate(ctx):
                continue
            return name
        return None

    def blocked_reasons(self, ctx, completed: Set[str]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for name, node in self.dag.items():
            if name in completed or name not in self.allowed:
                continue
            missing = node.depends_on - completed
            if missing:
                out[name] = f"waiting on {sorted(missing)}"
                continue
            if not node.prereq_predicate(ctx):
                out[name] = "prerequisite evidence not present in context"
                continue
        return out
