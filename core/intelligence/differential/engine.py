"""
Differential testing engine (spec Point A / P1.5).

    Input A -> representation 1 -> Output A
    Input A -> representation 2 -> Output B
    A != B  =>  potential parsing / authorisation / protocol inconsistency.

The engine is deterministic and network-agnostic: it takes a set of requests
that *should* be equivalent, sends them via an injected probe, and reports
every divergence. It never mutates target state beyond issuing the requests it
is given, and it never labels a divergence a confirmed vulnerability — it emits
anomalies for the hypothesis/adjudication pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.intelligence.differential.comparison import (
    Divergence,
    ResponseSnapshot,
    compare_snapshots,
)
from core.intelligence.differential.representations import (
    HttpRequest,
    ProbeFn,
    representation_variants,
    send,
)


@dataclass
class DifferentialResult:
    baseline: Optional[ResponseSnapshot]
    snapshots: List[ResponseSnapshot] = field(default_factory=list)
    divergences: List[Divergence] = field(default_factory=list)

    @property
    def diverged(self) -> bool:
        return bool(self.divergences)

    def max_severity(self) -> str:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3}
        if not self.divergences:
            return "none"
        return max((d.severity for d in self.divergences), key=lambda s: order.get(s, 0))

    def observations(self) -> List[Dict[str, Any]]:
        return [d.to_dict() for d in self.divergences]


class DifferentialEngine:
    """Compare responses across a set of supposedly-equivalent requests."""

    def __init__(self, probe: ProbeFn, ignore_statuses: Optional[set] = None,
                 **compare_kwargs: Any) -> None:
        self._probe = probe
        # Statuses that mean "this representation isn't supported here" rather
        # than a security-relevant divergence (e.g. POSTing to a GET-only page).
        self._ignore_statuses = ignore_statuses or set()
        self._compare_kwargs = compare_kwargs

    def run(self, requests: List[HttpRequest]) -> DifferentialResult:
        """Send every request and compare each against the baseline (first)."""
        snapshots = [send(self._probe, r) for r in requests]
        # Drop requests that never reached the target (status 0) so a single
        # network blip is not misread as a divergence, plus any status the
        # caller marked as "representation unsupported".
        live = [s for s in snapshots
                if s.status != 0 and s.status not in self._ignore_statuses]
        if len(live) < 2:
            return DifferentialResult(baseline=live[0] if live else None,
                                      snapshots=snapshots, divergences=[])
        baseline = live[0]
        divergences: List[Divergence] = []
        for other in live[1:]:
            divergences.extend(
                compare_snapshots(baseline, other, **self._compare_kwargs))
        return DifferentialResult(baseline=baseline, snapshots=snapshots,
                                  divergences=divergences)

    def run_equivalence(
        self,
        base_url: str,
        params: Dict[str, str],
        *,
        auth_headers: Optional[Dict[str, str]] = None,
        include_multipart: bool = False,
    ) -> DifferentialResult:
        """Differential across GET/form/json (+multipart) representations."""
        variants = representation_variants(
            base_url, params, auth_headers=auth_headers,
            include_multipart=include_multipart)
        return self.run(variants)
