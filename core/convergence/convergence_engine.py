import logging
import time
from enum import Enum
from typing import List, Dict, Optional, Tuple
from core.coverage.coverage_engine import CoverageEngine
from core.coverage.test_definition import SecurityTestDefinition
from core.domain.coverage import TestState

logger = logging.getLogger(__name__)

MINIMUM_COVERAGE_PCT = 85.0
STALL_TIMEOUT_SECONDS = 600  # 10 minutes

TERMINAL_STATES = {TestState.CONFIRMED, TestState.REJECTED, TestState.BLOCKED, TestState.NOT_APPLICABLE}
TESTED_STATES = {TestState.CONFIRMED, TestState.REJECTED}


class ConvergenceState(str, Enum):
    CONVERGING = "CONVERGING"
    STALLED = "STALLED"
    CONVERGED = "CONVERGED"
    COMPLETE = "COMPLETE"


class ConvergenceMetrics:
    __slots__ = ("convergence_score", "gap_count", "applicable_count", "confirmed_count",
                 "rejected_count", "blocked_count", "state")

    def __init__(self):
        self.convergence_score: float = 0.0
        self.gap_count: int = 0
        self.applicable_count: int = 0
        self.confirmed_count: int = 0
        self.rejected_count: int = 0
        self.blocked_count: int = 0
        self.state: ConvergenceState = ConvergenceState.CONVERGING


class ConvergenceEngine:
    def __init__(self, coverage_engine: CoverageEngine):
        self.coverage_engine = coverage_engine
        self._last_progress_time: float = time.monotonic()
        self._last_score: Optional[float] = None

    def calculate_convergence(self) -> float:
        stats = self._compute_stats()
        if stats.applicable_count == 0:
            return 100.0
        terminal = stats.confirmed_count + stats.rejected_count + stats.blocked_count
        score = (terminal / stats.applicable_count) * 100.0
        self._update_stall_tracker(score)
        return score

    def is_converged(self) -> bool:
        score = self.calculate_convergence()
        if score < MINIMUM_COVERAGE_PCT:
            return False
        gaps = self.get_remaining_gaps()
        return len(gaps) == 0

    def get_remaining_gaps(self) -> List[SecurityTestDefinition]:
        gap_ids = self.coverage_engine.get_coverage_gaps()
        remaining = []
        for gid in gap_ids:
            test_def = self.coverage_engine.catalog.get_test(gid)
            if test_def:
                remaining.append(test_def)
        return remaining

    def get_state(self) -> ConvergenceState:
        score = self.calculate_convergence()
        gaps = self.get_remaining_gaps()
        gap_count = len(gaps)

        not_tested = self._count_not_tested()

        if gap_count == 0 and score >= MINIMUM_COVERAGE_PCT and not_tested == 0:
            return ConvergenceState.CONVERGED

        if score >= MINIMUM_COVERAGE_PCT and self._is_stalled():
            return ConvergenceState.STALLED

        return ConvergenceState.CONVERGING

    def get_metrics(self) -> ConvergenceMetrics:
        stats = self._compute_stats()
        m = ConvergenceMetrics()
        m.convergence_score = self.calculate_convergence()
        m.gap_count = len(self.coverage_engine.get_coverage_gaps())
        m.applicable_count = stats.applicable_count
        m.confirmed_count = stats.confirmed_count
        m.rejected_count = stats.rejected_count
        m.blocked_count = stats.blocked_count
        m.state = self.get_state()
        return m

    def _compute_stats(self):
        class _S:
            applicable_count = 0
            confirmed_count = 0
            rejected_count = 0
            blocked_count = 0

        s = _S()
        for test_id, run_state in self.coverage_engine.state.coverage_map.items():
            if run_state.status == TestState.NOT_APPLICABLE:
                continue
            s.applicable_count += 1
            if run_state.status == TestState.CONFIRMED:
                s.confirmed_count += 1
            elif run_state.status == TestState.REJECTED:
                s.rejected_count += 1
            elif run_state.status == TestState.BLOCKED:
                s.blocked_count += 1
        return s

    def _count_not_tested(self) -> int:
        count = 0
        for run_state in self.coverage_engine.state.coverage_map.values():
            if run_state.status == TestState.NOT_TESTED:
                count += 1
        return count

    def _update_stall_tracker(self, current_score: float):
        if self._last_score is None:
            self._last_score = current_score
            self._last_progress_time = time.monotonic()
        elif current_score != self._last_score:
            self._last_score = current_score
            self._last_progress_time = time.monotonic()

    def _is_stalled(self) -> bool:
        elapsed = time.monotonic() - self._last_progress_time
        return elapsed >= STALL_TIMEOUT_SECONDS

    def force_stall_for_testing(self):
        if self._last_score is None:
            self._last_score = self.calculate_convergence()
        self._last_progress_time = time.monotonic() - STALL_TIMEOUT_SECONDS - 1
