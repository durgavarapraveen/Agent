from core.domain.base import DomainModel
from pydantic import Field
from typing import Dict, Optional

class SecurityExperiment(DomainModel):
    hypothesis_id: str = Field(...)
    test_strategy: str = Field(...)
    target_endpoint_id: Optional[str] = Field(default=None)
    payload_data: Dict[str, str] = Field(default_factory=dict)
    status: str = Field(default="PENDING")
    result_summary: str = Field(default="")
