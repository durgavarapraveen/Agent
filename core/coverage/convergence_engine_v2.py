from __future__ import annotations

import time
from typing import List, Tuple

from core.coverage.coverage_matrix import CoverageMatrix, CoverageState

CONVERGENCE_THRESHOLD = 0.85
STALL_MINUTES = 10


class ConvergenceEngine:

    def __init__(self, coverage_matrix: CoverageMatrix) -> None:
        self.matrix = coverage_matrix
        self._last_coverage: float = 0.0
        self._last_change_time: float = time.time()

    def calculate_convergence(self) -> float:
        coverage = self.matrix.get_coverage()
        if coverage != self._last_coverage:
            self._last_coverage = coverage
            self._last_change_time = time.time()
        return coverage

    def is_converged(self) -> bool:
        coverage = self.calculate_convergence()
        if coverage < CONVERGENCE_THRESHOLD:
            return False
        gaps = self.matrix.get_gaps()
        if gaps:
            return False
        return True

    def get_remaining_gaps(self) -> List[Tuple[str, str]]:
        return self.matrix.get_gaps()

    def get_stall_status(self) -> Tuple[bool, int]:
        self.calculate_convergence()
        elapsed = (time.time() - self._last_change_time) / 60.0
        is_stalled = elapsed >= STALL_MINUTES
        return is_stalled, int(elapsed)
