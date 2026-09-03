import logging
from typing import List, Tuple
from core.coverage.coverage_engine import CoverageEngine
from core.convergence.convergence_engine import ConvergenceEngine, ConvergenceState, MINIMUM_COVERAGE_PCT

logger = logging.getLogger(__name__)


class CompletionValidator:
    def __init__(self, coverage_engine: CoverageEngine, convergence_engine: ConvergenceEngine):
        self.coverage_engine = coverage_engine
        self.convergence_engine = convergence_engine

    def validate_completion(self) -> Tuple[bool, List[str]]:
        reasons = []

        score = self.convergence_engine.calculate_convergence()
        if score < MINIMUM_COVERAGE_PCT:
            reasons.append(f"Coverage {score:.1f}% below minimum {MINIMUM_COVERAGE_PCT}%")

        gaps = self.convergence_engine.get_remaining_gaps()
        if gaps:
            gap_ids = [g.test_id for g in gaps]
            reasons.append(f"{len(gaps)} unaddressed gaps: {', '.join(gap_ids[:5])}")

        blocked = self.coverage_engine.get_blocked_tests()
        if blocked:
            reasons.append(f"{len(blocked)} blocked tests: {', '.join(blocked[:5])}")

        state = self.convergence_engine.get_state()
        if state == ConvergenceState.STALLED:
            reasons.append("Convergence stalled — no progress detected")

        is_valid = len(reasons) == 0
        if is_valid:
            logger.info("Completion validation passed")
        else:
            logger.warning(f"Completion validation failed: {reasons}")

        return is_valid, reasons
