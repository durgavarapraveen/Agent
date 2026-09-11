from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from core.domain.experiment import SecurityExperiment

logger = logging.getLogger(__name__)


class ExecutionStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    AUTHORIZATION_ERROR = "authorization_error"
    SCHEMA_ERROR = "schema_error"


@dataclass
class ExecutionResult:
    status: ExecutionStatus
    evidence: Dict[str, Any] = field(default_factory=dict)
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ExecutorBase(abc.ABC):

    def __init__(self, timeout_seconds: int = 30) -> None:
        self.timeout_seconds = timeout_seconds

    @abc.abstractmethod
    def validate_inputs(self, inputs: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        ...

    @abc.abstractmethod
    def validate_target(self, endpoint: Dict[str, Any], identity: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        ...

    @abc.abstractmethod
    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        ...

    def collect_evidence(self, raw_output: Any) -> Dict[str, Any]:
        if isinstance(raw_output, dict):
            return raw_output
        return {"raw": str(raw_output)}

    def cleanup(self) -> None:
        pass
