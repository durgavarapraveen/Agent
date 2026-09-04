from core.domain.base import DomainModel
from pydantic import Field
from typing import Dict, Optional

class SecurityEvidence(DomainModel):
    experiment_id: str = Field(...)
    evidence_type: str = Field(...)
    request_id: Optional[str] = Field(default=None)
    raw_data: str = Field(default="")
    extracted_indicators: Dict[str, str] = Field(default_factory=dict)
