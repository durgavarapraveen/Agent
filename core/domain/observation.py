from core.domain.base import DomainModel
from pydantic import Field
from typing import Dict, List

class SecurityObservation(DomainModel):
    description: str = Field(...)
    observation_type: str = Field(...)
    metadata: Dict[str, str] = Field(default_factory=dict)
    related_asset_ids: List[str] = Field(default_factory=list)
