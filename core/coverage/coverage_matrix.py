from __future__ import annotations

import time
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class CoverageState(Enum):
    NOT_APPLICABLE = "not_applicable"
    NOT_TESTED = "not_tested"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"


class CoverageMatrix:

    def __init__(self, endpoints: List[str], tests: List[str]) -> None:
        self._matrix: Dict[str, Dict[str, Dict[str, Any]]] = {}
        for ep in endpoints:
            self._matrix[ep] = {}
            for t in tests:
                self._matrix[ep][t] = {
                    "state": CoverageState.NOT_TESTED,
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
                if s == CoverageState.NOT_APPLICABLE:
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
                if s == CoverageState.NOT_APPLICABLE:
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

    def get_blocked(self) -> List[Tuple[str, str]]:
        blocked = []
        for ep_id, tests in self._matrix.items():
            for test_id, cell in tests.items():
                if cell["state"] == CoverageState.BLOCKED:
                    blocked.append((ep_id, test_id))
        return blocked

    def get_matrix(self) -> Dict[str, Dict[str, CoverageState]]:
        result: Dict[str, Dict[str, CoverageState]] = {}
        for ep_id, tests in self._matrix.items():
            result[ep_id] = {}
            for test_id, cell in tests.items():
                result[ep_id][test_id] = cell["state"]
        return result
