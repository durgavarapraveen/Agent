from __future__ import annotations

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


def default_dag() -> Dict[str, PhaseNode]:
    return {
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
            completion_predicate=_has_vulns,
        ),
        "EXPLOITATION": PhaseNode(
            name="EXPLOITATION",
            depends_on={"ACTIVE_SCANNING"},
            prereq_predicate=_has_vulns,
            completion_predicate=_has_exploits,
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
