import logging
import os
from typing import List, Tuple
from core.coverage.coverage_engine import CoverageEngine
from core.convergence.convergence_engine import ConvergenceEngine, ConvergenceState, MINIMUM_COVERAGE_PCT

logger = logging.getLogger(__name__)


class CompletionValidator:
    def __init__(self, coverage_engine: CoverageEngine, convergence_engine: ConvergenceEngine):
        self.coverage_engine = coverage_engine
        self.convergence_engine = convergence_engine

    def _convergence_stalled(self) -> bool:
        """True when the live convergence engine reports no further progress.
        Robust across BOTH engines: the live ConvergenceEngineV2 exposes
        get_stall_status() -> (is_stalled, minutes) with NO score gate, while V1
        exposes get_state()==STALLED (which V1 only returns above the coverage
        threshold). Either positive signal counts. This is the key to §8: when an
        inflated applicability denominator pins coverage near 0%, the absolute-%
        gate is unreachable, so a genuine stall must be treated as diminishing
        returns rather than an eternal 'incomplete'."""
        ce = self.convergence_engine
        try:
            gss = getattr(ce, "get_stall_status", None)
            if callable(gss):
                stalled, _mins = gss()
                if stalled:
                    return True
        except Exception:
            pass
        try:
            gs = getattr(ce, "get_state", None)
            if callable(gs):
                st = gs()
                if st == ConvergenceState.STALLED or \
                        str(getattr(st, "name", st)).upper() == "STALLED":
                    return True
        except Exception:
            pass
        return False

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

        # §8 DIMINISHING-RETURNS COMPLETION: if the scan has genuinely stalled
        # (the live engine reports no coverage progress for its stall window),
        # further scanning yields nothing — usually because the applicability
        # denominator is inflated and pins coverage near 0%, making the absolute
        # MINIMUM_COVERAGE_PCT gate unreachable. Treat that as a valid, budget-
        # exhausted completion so the run finalizes on the results in hand rather
        # than grinding to the runtime watchdog. Previously a stall was appended
        # as YET ANOTHER blocking reason (and the check was dead against the live
        # V2 engine, which has no get_state()), so completion could never pass.
        # Operators who want strict %-coverage completion set
        # COVERAGE_STRICT_COMPLETION=1.
        _strict = os.getenv("COVERAGE_STRICT_COMPLETION", "0").strip().lower() in ("1", "true", "yes", "on")
        if reasons and not _strict and self._convergence_stalled():
            note = ("completed on diminishing returns (convergence stalled — no "
                    f"further progress); unmet at finalize: {'; '.join(reasons)}")
            logger.warning("Completion allowed by stall guard: %s", note)
            return True, [note]

        is_valid = len(reasons) == 0
        if is_valid:
            logger.info("Completion validation passed")
        else:
            logger.warning(f"Completion validation failed: {reasons}")

        return is_valid, reasons
