from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum

class TestStatus(str, Enum):
    TESTED = "tested"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    NOT_TESTED = "not_tested"

class Payload(BaseModel):
    value: str
    expected_behavior: str
    oracle_hints: Dict[str, Any] = Field(default_factory=dict)

class InjectionTest(BaseModel):
    test_id: str
    name: str
    test_type: str
    endpoint_id: str
    parameter_name: str
    status: TestStatus = TestStatus.NOT_TESTED

class InjectionResult(BaseModel):
    test_id: str
    status: TestStatus
    evidence: str
    oracle_used: Optional[str] = None
    timestamp: float = 0.0

class InjectionTestMatrix(BaseModel):
    endpoints: int = 0
    eligible_parameters: int = 0
    tests_by_type: Dict[str, List[InjectionTest]] = Field(default_factory=dict)
    status_by_type: Dict[str, Dict[str, int]] = Field(default_factory=dict)
