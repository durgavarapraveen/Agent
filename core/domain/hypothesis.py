from core.domain.base import DomainModel
from pydantic import Field
from typing import List, Optional

class SecurityHypothesis(DomainModel):
    title: str = Field(...)
    rationale: str = Field(...)
    expected_signals: List[str] = Field(default_factory=list)
    test_id: str = Field(...)
    endpoint_id: Optional[str] = Field(default=None)
    identity_ids: List[str] = Field(default_factory=list)
    status: str = Field(default="PROPOSED")
