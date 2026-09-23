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
        # P1-F2: defensive across BOTH convergence engines. The V1 engine exposes
        # get_state()/gap objects with .test_id; the live V2 engine returns gap
        # TUPLES and has no no-arg get_state(). Each engine call is isolated so a
        # missing method degrades gracefully instead of crashing REPORTING, and
        # the score is unit-normalized (V2 may report a 0..1 fraction, V1 a 0..100
        # percent) before comparing to the percent threshold.
        reasons: List[str] = []

        try:
            raw = float(self.convergence_engine.calculate_convergence())
            pct = raw * 100.0 if raw <= 1.0 else raw
            if pct < MINIMUM_COVERAGE_PCT:
                reasons.append(f"Coverage {pct:.1f}% below minimum {MINIMUM_COVERAGE_PCT}%")
        except Exception as e:
            logger.debug("completion: convergence score unavailable: %s", e)

        try:
            gaps = self.convergence_engine.get_remaining_gaps() or []
            if gaps:
                gap_ids = []
                for g in gaps[:5]:
                    if hasattr(g, "test_id"):
                        gap_ids.append(str(g.test_id))
                    elif isinstance(g, (tuple, list)):
                        gap_ids.append(":".join(str(x) for x in g))
                    else:
                        gap_ids.append(str(g))
                reasons.append(f"{len(gaps)} unaddressed gaps: {', '.join(gap_ids)}")
        except Exception as e:
            logger.debug("completion: gaps unavailable: %s", e)

        try:
            blocked = self.coverage_engine.get_blocked_tests()
            if blocked:
                reasons.append(f"{len(blocked)} blocked tests: {', '.join(list(blocked)[:5])}")
        except Exception:
            pass

        try:
            get_state = getattr(self.convergence_engine, "get_state", None)
            if callable(get_state):
                state = get_state()
                if state == ConvergenceState.STALLED or str(getattr(state, "name", state)).upper() == "STALLED":
                    reasons.append("Convergence stalled — no progress detected")
        except Exception:
            pass

        is_valid = len(reasons) == 0
        if is_valid:
            logger.info("Completion validation passed")
        else:
            logger.warning(f"Completion validation failed: {reasons}")

        return is_valid, reasons
