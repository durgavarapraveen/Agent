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


@dataclass
class SecurityExperiment:
    hypothesis_id: str
    endpoint_id: str
    capability: str
    identity_id: str = ""
    experiment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    priority: float = 0.5
    state: ExperimentState = ExperimentState.CREATED
    prerequisites: List[str] = field(default_factory=list)
    expected_signals: List[str] = field(default_factory=list)
    evidence_requirements: List[str] = field(default_factory=list)
    input_parameters: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    evidence_ids: List[str] = field(default_factory=list)
    coverage_delta: Dict[str, Any] = field(default_factory=dict)
    error_code: Optional[str] = None
    error_message: Optional[str] = None

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
