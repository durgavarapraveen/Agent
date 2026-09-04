from core.domain.base import DomainModel
from core.domain.coverage import TestState
from core.domain.evidence import SecurityEvidence
from pydantic import Field
from typing import List, Dict, Optional
from datetime import datetime

class TestRunState(DomainModel):
    status: TestState = Field(default=TestState.NOT_TESTED)
    evidence_collected: List[SecurityEvidence] = Field(default_factory=list)
    last_executed: Optional[datetime] = Field(default=None)
    failure_reason: Optional[str] = Field(default=None)
    tool_used: Optional[str] = Field(default=None)
    endpoints_scanned: List[str] = Field(default_factory=list)

class CoverageStateV2(DomainModel):
    # Mapping of test_id -> TestRunState
    coverage_map: Dict[str, TestRunState] = Field(default_factory=dict)
    
    # Nested mapping of endpoint_id -> test_id -> TestRunState
    endpoint_coverage_map: Dict[str, Dict[str, TestRunState]] = Field(default_factory=dict)
