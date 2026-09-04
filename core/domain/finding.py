from core.domain.base import DomainModel
from pydantic import Field
from enum import Enum
from typing import List, Optional

class FindingState(str, Enum):
    CANDIDATE = "CANDIDATE"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    MITIGATED = "MITIGATED"

class SecurityFinding(DomainModel):
    title: str = Field(...)
    description: str = Field(...)
    severity: str = Field(default="INFO")
    finding_state: FindingState = Field(default=FindingState.CANDIDATE)
    evidence_ids: List[str] = Field(default_factory=list)
    endpoint_id: Optional[str] = Field(default=None)
