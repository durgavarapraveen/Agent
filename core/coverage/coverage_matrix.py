from __future__ import annotations

import time
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class CoverageState(Enum):
    NOT_APPLICABLE = "not_applicable"
    NOT_DISCOVERED = "not_discovered"
    NOT_TESTED = "not_tested"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"


class CoverageMatrix:

    def __init__(self, endpoints: List[str], tests: List[str],
                 applicable: Optional[set] = None) -> None:
        # `applicable`: set of (endpoint_id, test_id) pairs that actually apply to
        # each endpoint (from the applicability engine). When given, every OTHER
        # cell starts NOT_APPLICABLE instead of NOT_TESTED — otherwise the full
        # endpoints×tests cross-product counts as applicable and the coverage
        # denominator explodes (e.g. 278×200≈55k), pinning coverage near 0% and
        # starving convergence → runtime watchdog. When None, legacy behaviour
        # (all cells NOT_TESTED) is preserved.
        self._matrix: Dict[str, Dict[str, Dict[str, Any]]] = {}
        _app = set(applicable) if applicable is not None else None
        for ep in endpoints:
            self._matrix[ep] = {}
            for t in tests:
                if _app is not None and (ep, t) not in _app:
                    st = CoverageState.NOT_APPLICABLE
                else:
                    st = CoverageState.NOT_TESTED
                self._matrix[ep][t] = {
                    "state": st,
                    "evidence_id": None,
                    "timestamp": time.time(),
                }

    def update_state(
        self,
        endpoint_id: str,
        test_id: str,
        state: CoverageState,
        evidence_id: Optional[str] = None,
    ) -> None:
        if endpoint_id not in self._matrix:
            self._matrix[endpoint_id] = {}
        self._matrix[endpoint_id][test_id] = {
            "state": state,
            "evidence_id": evidence_id,
            "timestamp": time.time(),
        }
        # Observability: track coverage transitions (P4 hypothesis/coverage metrics).
        try:
            from core.observability.metrics import record_coverage_transition
            record_coverage_transition(getattr(state, "name", str(state)))
        except Exception:
            pass

    def get_state(self, endpoint_id: str, test_id: str) -> CoverageState:
        ep = self._matrix.get(endpoint_id, {})
        cell = ep.get(test_id)
        if cell is None:
            return CoverageState.NOT_TESTED
        return cell["state"]

    def get_coverage(self) -> float:
        applicable = 0
        resolved = 0
        for ep_id, tests in self._matrix.items():
            for test_id, cell in tests.items():
                s = cell["state"]
                if s in (CoverageState.NOT_APPLICABLE, CoverageState.NOT_DISCOVERED):
                    continue
                applicable += 1
                if s in (CoverageState.CONFIRMED, CoverageState.REJECTED):
                    resolved += 1
        return resolved / applicable if applicable else 0.0

    def get_coverage_by_category(self, test_category_map: Dict[str, str]) -> Dict[str, float]:
        cat_totals: Dict[str, int] = {}
        cat_resolved: Dict[str, int] = {}
        for ep_id, tests in self._matrix.items():
            for test_id, cell in tests.items():
                s = cell["state"]
                if s in (CoverageState.NOT_APPLICABLE, CoverageState.NOT_DISCOVERED):
                    continue
                cat = test_category_map.get(test_id, "unknown")
                cat_totals[cat] = cat_totals.get(cat, 0) + 1
                if s in (CoverageState.CONFIRMED, CoverageState.REJECTED):
                    cat_resolved[cat] = cat_resolved.get(cat, 0) + 1
        return {
            cat: cat_resolved.get(cat, 0) / total if total else 0.0
            for cat, total in cat_totals.items()
        }

    def get_gaps(self) -> List[Tuple[str, str]]:
        gaps = []
        for ep_id, tests in self._matrix.items():
            for test_id, cell in tests.items():
                if cell["state"] == CoverageState.NOT_TESTED:
                    gaps.append((ep_id, test_id))
        return gaps

    def get_stalled(self, ttl_seconds: float = 900.0) -> List[Tuple[str, str]]:
        """Cells stuck in a non-terminal state (SCHEDULED/RUNNING/INCONCLUSIVE)
        past ``ttl_seconds`` — e.g. a crashed worker that never wrote a terminal
        state. These depress coverage% invisibly; surface them so they can be
        re-queued or reported as blind spots."""
        now = time.time()
        stuck_states = (CoverageState.SCHEDULED, CoverageState.RUNNING,
                        CoverageState.INCONCLUSIVE)
        out = []
        for ep_id, tests in self._matrix.items():
            for test_id, cell in tests.items():
                if cell["state"] in stuck_states and (now - cell.get("timestamp", now)) >= ttl_seconds:
                    out.append((ep_id, test_id))
        return out

    def get_not_discovered(self) -> List[Tuple[str, str]]:
        nd = []
        for ep_id, tests in self._matrix.items():
            for test_id, cell in tests.items():
                if cell["state"] == CoverageState.NOT_DISCOVERED:
                    nd.append((ep_id, test_id))
        return nd

    def promote_discovered(self, endpoint_id: str, test_id: str) -> None:
        ep = self._matrix.get(endpoint_id, {})
        cell = ep.get(test_id)
        if cell and cell["state"] == CoverageState.NOT_DISCOVERED:
            cell["state"] = CoverageState.NOT_TESTED

    def get_blocked(self) -> List[Tuple[str, str]]:
        blocked = []
        for ep_id, tests in self._matrix.items():
            for test_id, cell in tests.items():
                if cell["state"] == CoverageState.BLOCKED:
                    blocked.append((ep_id, test_id))
        return blocked

    def state_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for _ep, tests in self._matrix.items():
            for _t, cell in tests.items():
                k = cell["state"].value if hasattr(cell["state"], "value") else str(cell["state"])
                counts[k] = counts.get(k, 0) + 1
        return counts

    def coverage_summary(self) -> Dict[str, Any]:
        counts = self.state_counts()
        total = sum(counts.values())
        na = counts.get(CoverageState.NOT_APPLICABLE.value, 0)
        nd = counts.get(CoverageState.NOT_DISCOVERED.value, 0)
        applicable = total - na - nd
        executed = sum(counts.get(s.value, 0) for s in (
            CoverageState.CONFIRMED, CoverageState.REJECTED,
            CoverageState.INCONCLUSIVE, CoverageState.BLOCKED,
            CoverageState.RUNNING))
        resolved = counts.get(CoverageState.CONFIRMED.value, 0) + \
            counts.get(CoverageState.REJECTED.value, 0)
        return {
            "total_cells": total,
            "applicable": applicable,
            "executed": executed,
            "resolved": resolved,
            "not_tested": counts.get(CoverageState.NOT_TESTED.value, 0),
            "blocked": counts.get(CoverageState.BLOCKED.value, 0),
            "pct_executed": round(executed / applicable, 4) if applicable else 0.0,
            "pct_resolved": round(resolved / applicable, 4) if applicable else 0.0,
            "by_state": counts,
        }

    def get_matrix(self) -> Dict[str, Dict[str, CoverageState]]:
        result: Dict[str, Dict[str, CoverageState]] = {}
        for ep_id, tests in self._matrix.items():
            result[ep_id] = {}
            for test_id, cell in tests.items():
                result[ep_id][test_id] = cell["state"]
        return result
