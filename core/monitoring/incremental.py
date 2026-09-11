"""Phase 6.2 — incremental scanning.

Reuses the Phase 3.1 attack-surface baseline: load the previous surface for a
target, diff it against the current one, and scan only the new/changed endpoints
instead of the whole surface — then persist the new baseline.

The planning logic is pure and unit-testable; ``CentralBrain`` calls
:meth:`IncrementalScanner.plan` after RECON and :meth:`commit` after the scan.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, List, Optional

from core.monitoring.surface_baseline import SurfaceBaseline, SurfaceSnapshot

logger = logging.getLogger(__name__)


@dataclass
class IncrementalPlan:
    full_scan: bool
    endpoints_to_scan: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {"full_scan": self.full_scan, "scan": self.endpoints_to_scan,
                "skipped": self.skipped, "reason": self.reason}


def plan_incremental(current: SurfaceSnapshot,
                     baseline: Optional[SurfaceSnapshot]) -> IncrementalPlan:
    """Decide what to scan given the current surface and a prior baseline."""
    if baseline is None:
        return IncrementalPlan(full_scan=True, endpoints_to_scan=list(current.endpoints),
                               reason="no baseline — full scan")
    diff = SurfaceBaseline().diff(baseline, current)
    if not diff["has_changes"]:
        return IncrementalPlan(full_scan=False, endpoints_to_scan=[],
                               skipped=list(current.endpoints),
                               reason="surface unchanged — nothing to re-scan")
    to_scan = set(SurfaceBaseline().changed_for_rescan(diff))
    skipped = [e for e in current.endpoints if e not in to_scan]
    return IncrementalPlan(full_scan=False, endpoints_to_scan=sorted(to_scan),
                           skipped=skipped,
                           reason=f"{len(to_scan)} changed/new endpoint(s) to re-scan")


class IncrementalScanner:

    def __init__(self, baseline: Optional[SurfaceBaseline] = None):
        self.baseline = baseline or SurfaceBaseline()

    def plan(self, target: str, current_source: Any, incremental: bool = False,
             baseline_path: Optional[str] = None) -> IncrementalPlan:
        current = self.baseline.snapshot(current_source, target=target)
        if not incremental:
            return IncrementalPlan(full_scan=True, endpoints_to_scan=list(current.endpoints),
                                   reason="incremental disabled — full scan")
        prior = self.baseline.load_latest(target, path=baseline_path)
        plan = plan_incremental(current, prior)
        logger.info("incremental: %s (%d to scan, %d skipped)", plan.reason,
                    len(plan.endpoints_to_scan), len(plan.skipped))
        return plan

    def commit(self, target: str, current_source: Any,
               baseline_path: Optional[str] = None) -> str:
        snap = self.baseline.snapshot(current_source, target=target)
        return self.baseline.save(snap, path=baseline_path)

    @staticmethod
    def filter_endpoints(endpoints: List[Any], plan: IncrementalPlan) -> List[Any]:
        """Filter a live endpoint list down to those the plan says to scan.
        A full scan keeps everything."""
        if plan.full_scan:
            return endpoints
        wanted = set(plan.endpoints_to_scan)
        out = []
        for ep in endpoints:
            url = ep.get("url", "") if isinstance(ep, dict) else getattr(ep, "url", str(ep))
            method = (ep.get("method", "GET") if isinstance(ep, dict)
                      else getattr(ep, "method", "GET")) or "GET"
            from core.discovery.workflow_crawler import normalize_path
            key = f"{method.upper()} {normalize_path(url)}"
            if key in wanted:
                out.append(ep)
        return out
