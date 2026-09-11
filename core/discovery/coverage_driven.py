"""Phase 14.2 — Coverage-driven exploration.

Uses coverage objectives over assets, interfaces, methods, identities,
workflows, states, parameter classes, technologies, and security properties.
Prioritizes unexplored high-value regions. Convergence based on diminishing
expected value, not arbitrary loop counts.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_EXPLORATION_CONFIG: Dict[str, Any] = {
    "min_expected_value": 0.05,
    "decay_factor": 0.85,
    "max_exploration_rounds": 500,
    "priority_weights": {
        "uncovered_asset": 1.0,
        "uncovered_method": 0.8,
        "uncovered_identity": 0.9,
        "uncovered_parameter_class": 0.7,
        "uncovered_security_property": 1.0,
        "uncovered_technology": 0.6,
    },
}


class CoverageDimension(str, Enum):
    ASSET = "asset"
    INTERFACE = "interface"
    METHOD = "method"
    IDENTITY = "identity"
    WORKFLOW = "workflow"
    STATE = "state"
    PARAMETER_CLASS = "parameter_class"
    TECHNOLOGY = "technology"
    SECURITY_PROPERTY = "security_property"


@dataclass
class CoverageObjective:
    dimension: CoverageDimension
    target: str
    covered: bool = False
    attempts: int = 0
    last_attempt: float = 0.0
    expected_value: float = 1.0
    priority: float = 0.0


@dataclass
class ExplorationCandidate:
    candidate_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    objective: CoverageObjective = field(default_factory=lambda: CoverageObjective(CoverageDimension.ASSET, ""))
    expected_value: float = 0.0
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "dimension": self.objective.dimension.value,
            "target": self.objective.target,
            "expected_value": self.expected_value,
            "rationale": self.rationale,
        }


class CoverageDrivenExplorer:
    """Prioritize experiments by coverage gaps and expected value."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = {**DEFAULT_EXPLORATION_CONFIG, **(config or {})}
        self._lock = threading.RLock()
        self._objectives: Dict[str, CoverageObjective] = {}
        self._exploration_log: List[Dict[str, Any]] = []
        self._round = 0

    def add_objective(self, dimension: CoverageDimension, target: str,
                      priority: float = 0.0) -> str:
        key = f"{dimension.value}:{target}"
        with self._lock:
            if key not in self._objectives:
                self._objectives[key] = CoverageObjective(
                    dimension=dimension, target=target, priority=priority,
                )
        return key

    def mark_covered(self, dimension: CoverageDimension, target: str) -> None:
        key = f"{dimension.value}:{target}"
        with self._lock:
            obj = self._objectives.get(key)
            if obj:
                obj.covered = True

    def record_attempt(self, dimension: CoverageDimension, target: str) -> None:
        key = f"{dimension.value}:{target}"
        with self._lock:
            obj = self._objectives.get(key)
            if obj:
                obj.attempts += 1
                obj.last_attempt = time.time()
                obj.expected_value *= self._config["decay_factor"]

    def next_candidates(self, limit: int = 10) -> List[ExplorationCandidate]:
        with self._lock:
            uncovered = [o for o in self._objectives.values() if not o.covered]
        for obj in uncovered:
            weight = self._config["priority_weights"].get(
                f"uncovered_{obj.dimension.value}", 0.5)
            obj.expected_value = weight * (self._config["decay_factor"] ** obj.attempts)
            if obj.priority > 0:
                obj.expected_value *= (1 + obj.priority)
        uncovered = [o for o in uncovered
                     if o.expected_value >= self._config["min_expected_value"]]
        uncovered.sort(key=lambda o: o.expected_value, reverse=True)
        candidates = []
        for obj in uncovered[:limit]:
            rationale = (f"Uncovered {obj.dimension.value} '{obj.target}' "
                         f"(EV={obj.expected_value:.3f}, attempts={obj.attempts})")
            candidates.append(ExplorationCandidate(
                objective=obj, expected_value=obj.expected_value, rationale=rationale,
            ))
        self._round += 1
        return candidates

    def has_converged(self) -> bool:
        if self._round >= self._config["max_exploration_rounds"]:
            return True
        candidates = self.next_candidates(limit=1)
        if not candidates:
            return True
        return candidates[0].expected_value < self._config["min_expected_value"]

    def coverage_report(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._objectives)
            covered = sum(1 for o in self._objectives.values() if o.covered)
            by_dim: Dict[str, Dict[str, int]] = {}
            for o in self._objectives.values():
                d = o.dimension.value
                by_dim.setdefault(d, {"total": 0, "covered": 0})
                by_dim[d]["total"] += 1
                if o.covered:
                    by_dim[d]["covered"] += 1
        return {
            "total": total, "covered": covered,
            "coverage_pct": (covered / total * 100) if total else 0,
            "round": self._round,
            "by_dimension": by_dim,
        }
