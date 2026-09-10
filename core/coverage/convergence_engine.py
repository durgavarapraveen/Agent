from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

CONVERGENCE_THRESHOLD = 0.85
STALL_MINUTES = 10


@dataclass
class ConvergenceStatus:
    is_converged: bool = False
    coverage_pct: float = 0.0
    tests_remaining: int = 0
    tests_blocked: int = 0
    tests_inconclusive: int = 0
    is_stalled: bool = False
    stall_minutes: int = 0
    budget_exhausted: bool = False
    target_paused: bool = False
    reason: str = ""


class ConvergenceEngine:

    def __init__(self, coverage_matrix=None) -> None:
        self.matrix = coverage_matrix
        self._last_coverage: float = 0.0
        self._last_change_time: float = time.time()
        self._history: List[Tuple[float, float]] = []

    def calculate_convergence(self) -> float:
        if not self.matrix:
            return 0.0
        coverage = self.matrix.get_coverage()
        if coverage != self._last_coverage:
            self._last_coverage = coverage
            self._last_change_time = time.time()
        self._history.append((time.time(), coverage))
        return coverage

    def evaluate(
        self,
        remaining_tests: int = 0,
        blocked_tests: int = 0,
        inconclusive_tests: int = 0,
        budget_exhausted: bool = False,
        target_paused: bool = False,
        high_value_remaining: int = 0,
    ) -> ConvergenceStatus:
        coverage = self.calculate_convergence()
        elapsed = (time.time() - self._last_change_time) / 60.0
        is_stalled = elapsed >= STALL_MINUTES

        status = ConvergenceStatus(
            coverage_pct=coverage,
            tests_remaining=remaining_tests,
            tests_blocked=blocked_tests,
            tests_inconclusive=inconclusive_tests,
            is_stalled=is_stalled,
            stall_minutes=int(elapsed),
            budget_exhausted=budget_exhausted,
            target_paused=target_paused,
        )

        if budget_exhausted:
            status.is_converged = True
            status.reason = "BUDGET_EXHAUSTED"
        elif target_paused and remaining_tests > 0:
            status.is_converged = False
            status.reason = "TARGET_PAUSED"
        elif high_value_remaining == 0 and remaining_tests == 0:
            status.is_converged = True
            status.reason = "ALL_TESTS_COMPLETE"
        elif coverage >= CONVERGENCE_THRESHOLD and high_value_remaining == 0:
            status.is_converged = True
            status.reason = "THRESHOLD_MET_NO_HIGH_VALUE"
        elif is_stalled and remaining_tests == blocked_tests + inconclusive_tests:
            status.is_converged = True
            status.reason = "STALLED_ONLY_BLOCKED_REMAINING"
        elif is_stalled and coverage >= CONVERGENCE_THRESHOLD:
            status.is_converged = True
            status.reason = "STALLED_ABOVE_THRESHOLD"
        else:
            status.is_converged = False
            status.reason = f"IN_PROGRESS coverage={coverage:.1f}% remaining={remaining_tests}"

        if status.is_converged:
            logger.info(f"CONVERGENCE_REACHED reason={status.reason} "
                        f"coverage={coverage:.1f}% blocked={blocked_tests} "
                        f"inconclusive={inconclusive_tests}")
        return status

    def is_converged(self) -> bool:
        coverage = self.calculate_convergence()
        if coverage < CONVERGENCE_THRESHOLD:
            return False
        if self.matrix:
            gaps = self.matrix.get_gaps()
            if gaps:
                return False
        return True

    def get_remaining_gaps(self) -> List[Tuple[str, str]]:
        if self.matrix:
            return self.matrix.get_gaps()
        return []

    def get_stall_status(self) -> Tuple[bool, int]:
        self.calculate_convergence()
        elapsed = (time.time() - self._last_change_time) / 60.0
        return elapsed >= STALL_MINUTES, int(elapsed)

    def summary(self) -> Dict[str, Any]:
        coverage = self.calculate_convergence()
        is_stalled, stall_min = self.get_stall_status()
        return {
            "coverage_pct": round(coverage, 1),
            "is_stalled": is_stalled,
            "stall_minutes": stall_min,
            "history_points": len(self._history),
        }
