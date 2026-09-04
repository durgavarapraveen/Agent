from core.domain.base import DomainModel
from pydantic import Field
from enum import Enum
from typing import Dict

class TestState(str, Enum):
    NOT_TESTED = "NOT_TESTED"
    READY = "READY"
    RUNNING = "RUNNING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"

class CoverageState(DomainModel):
    # Mapping of test_id (e.g., sql_injection, xss) to TestState
    coverage_map: Dict[str, TestState] = Field(default_factory=dict)
    
    # Nested mapping of endpoint_id -> test_id -> TestState
    endpoint_coverage_map: Dict[str, Dict[str, TestState]] = Field(default_factory=dict)
