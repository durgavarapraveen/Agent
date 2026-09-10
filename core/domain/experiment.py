from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ExperimentState(Enum):
    CREATED = "created"
    READY = "ready"
    RUNNING = "running"
    EVIDENCE_COLLECTED = "evidence_collected"
    VALIDATING = "validating"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"
    ERROR = "error"


VALID_EXPERIMENT_TRANSITIONS = {
    ExperimentState.CREATED: {ExperimentState.READY, ExperimentState.SKIPPED},
    ExperimentState.READY: {ExperimentState.RUNNING, ExperimentState.SKIPPED},
    ExperimentState.RUNNING: {
        ExperimentState.EVIDENCE_COLLECTED,
        ExperimentState.ERROR,
        ExperimentState.SKIPPED,
    },
    ExperimentState.EVIDENCE_COLLECTED: {
        ExperimentState.VALIDATING,
        ExperimentState.CONFIRMED,
        ExperimentState.REJECTED,
        ExperimentState.INCONCLUSIVE,
    },
    ExperimentState.VALIDATING: {
        ExperimentState.CONFIRMED,
        ExperimentState.REJECTED,
        ExperimentState.INCONCLUSIVE,
    },
    ExperimentState.CONFIRMED: set(),
    ExperimentState.REJECTED: set(),
    ExperimentState.INCONCLUSIVE: {ExperimentState.READY},
    ExperimentState.SKIPPED: set(),
    ExperimentState.ERROR: {ExperimentState.READY},
}


@dataclass
class ExperimentResult:
    status: str = ""
    raw_response: str = ""
    status_code: int = 0
    response_time_ms: float = 0.0
    matched_signals: List[str] = field(default_factory=list)
    unmatched_signals: List[str] = field(default_factory=list)
    confidence: float = 0.0
    notes: str = ""


@dataclass
class SecurityExperiment:
    hypothesis_id: str
    endpoint_id: str
    capability: str
    identity_id: str = ""
    experiment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    test_id: str = ""
    payload_ids: List[str] = field(default_factory=list)
    priority: float = 0.5
    state: ExperimentState = ExperimentState.CREATED
    prerequisites: List[str] = field(default_factory=list)
    expected_signals: List[str] = field(default_factory=list)
    evidence_requirements: List[str] = field(default_factory=list)
    input_parameters: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[ExperimentResult] = None
    evidence_ids: List[str] = field(default_factory=list)
    coverage_delta: Dict[str, Any] = field(default_factory=dict)
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 2
    parent_experiment_id: Optional[str] = None
    feedback: Dict[str, Any] = field(default_factory=dict)

    def transition(self, new_state: ExperimentState) -> bool:
        allowed = VALID_EXPERIMENT_TRANSITIONS.get(self.state, set())
        if new_state not in allowed:
            return False
        self.state = new_state
        if new_state == ExperimentState.RUNNING:
            self.started_at = datetime.utcnow()
        elif new_state in (ExperimentState.CONFIRMED, ExperimentState.REJECTED,
                           ExperimentState.INCONCLUSIVE, ExperimentState.ERROR):
            self.completed_at = datetime.utcnow()
        return True

    def validate_prerequisite_format(self) -> bool:
        for prereq in self.prerequisites:
            try:
                uuid.UUID(prereq)
            except ValueError:
                return False
        return True

    def is_duplicate_of(self, other: SecurityExperiment) -> bool:
        return (
            self.hypothesis_id == other.hypothesis_id
            and self.endpoint_id == other.endpoint_id
            and self.capability == other.capability
            and self.identity_id == other.identity_id
            and self.input_parameters == other.input_parameters
        )

    def can_retry(self) -> bool:
        return (self.state == ExperimentState.ERROR
                and self.retry_count < self.max_retries)

    def mark_retry(self) -> bool:
        if not self.can_retry():
            return False
        self.retry_count += 1
        self.state = ExperimentState.READY
        self.error_code = None
        self.error_message = None
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "hypothesis_id": self.hypothesis_id,
            "endpoint_id": self.endpoint_id,
            "test_id": self.test_id,
            "capability": self.capability,
            "identity_id": self.identity_id,
            "payload_ids": self.payload_ids,
            "state": self.state.value,
            "priority": self.priority,
            "retry_count": self.retry_count,
            "evidence_ids": self.evidence_ids,
            "error_code": self.error_code,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
