"""UnifiedCoverage — one facade over the two parallel coverage systems
(CoverageMatrix + CoverageEngine, plus IdentityCoverageEngine). Delegates each
call to whichever backend owns it and normalizes percentages to 0-1, so callers
(BlindSpotDetector, AdaptivePlanner, report) read a single consistent API."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)


class UnifiedCoverage:
    def __init__(self, matrix=None, engine=None, identity=None):
        self.matrix = matrix
        self.engine = engine
        self.identity = identity

    @classmethod
    def from_brain(cls, brain) -> "UnifiedCoverage":
        return cls(getattr(brain, "coverage_matrix", None),
                   getattr(brain, "coverage_engine", None),
                   getattr(brain, "identity_coverage", None))

    def pct_executed(self) -> float:
        """Fraction 0-1 of applicable tests executed (prefers the matrix)."""
        try:
            if self.matrix and hasattr(self.matrix, "coverage_summary"):
                return float(self.matrix.coverage_summary().get("pct_executed", 0.0))
        except Exception:
            pass
        try:
            if self.engine and hasattr(self.engine, "calculate_coverage_pct"):
                return float(self.engine.calculate_coverage_pct()) / 100.0
        except Exception:
            pass
        return 0.0

    def gaps(self) -> List[Dict[str, Any]]:
        """Merged untested cells from both systems."""
        out: List[Dict[str, Any]] = []
        try:
            if self.matrix and hasattr(self.matrix, "get_gaps"):
                for ep, test in self.matrix.get_gaps():
                    out.append({"endpoint": ep, "test_id": test, "source": "matrix"})
        except Exception as e:
            logger.debug("matrix gaps failed: %s", e)
        try:
            if self.engine and hasattr(self.engine, "get_coverage_gaps"):
                for t in self.engine.get_coverage_gaps():
                    out.append({"test_id": str(t), "source": "engine"})
        except Exception as e:
            logger.debug("engine gaps failed: %s", e)
        return out

    def summary(self) -> Dict[str, Any]:
        s: Dict[str, Any] = {"pct_executed": round(self.pct_executed(), 3),
                             "gap_count": len(self.gaps())}
        try:
            if self.matrix and hasattr(self.matrix, "coverage_summary"):
                s["matrix"] = self.matrix.coverage_summary()
        except Exception:
            pass
        try:
            if self.engine and hasattr(self.engine, "get_coverage_status"):
                s["engine"] = self.engine.get_coverage_status()
        except Exception:
            pass
        try:
            if self.identity and hasattr(self.identity, "summary"):
                s["identity"] = self.identity.summary()
        except Exception:
            pass
        return s
