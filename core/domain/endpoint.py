from core.domain.base import DomainModel
from core.domain.parameter import Parameter
from core.domain.identity import Identity
from pydantic import Field, validator
from typing import List, Dict, Optional
from enum import Enum


class DiscoveryState(str, Enum):
    DISCOVERED = "discovered"
    INFERRED = "inferred"
    HYPOTHESIS = "hypothesis"
    CONFIRMED = "confirmed"


class SchemaNode(DomainModel):
    """Recursive model to define expected response shapes."""
    type_name: str = Field(...)
    properties: Dict[str, 'SchemaNode'] = Field(default_factory=dict)
    is_array: bool = Field(default=False)

SchemaNode.update_forward_refs()


class Endpoint(DomainModel):
    endpoint_id: str = Field(...)
    url: str = Field(...)
    path: str = Field(...)
    method_set: List[str] = Field(...)
    parameters: List[Parameter] = Field(default_factory=list)
    response_schema: Dict[str, SchemaNode] = Field(default_factory=dict)

    # Extended fields (Phase 7)
    asset_id: str = Field(default="")
    application_id: str = Field(default="")
    scheme: str = Field(default="https")
    host: str = Field(default="")
    port: int = Field(default=443)
    content_type: str = Field(default="")
    auth_required: bool = Field(default=False)
    auth_state: str = Field(default="unknown")
    auth_contexts: List[Identity] = Field(default_factory=list)
    discovery_state: DiscoveryState = Field(default=DiscoveryState.DISCOVERED)
    evidence_ids: List[str] = Field(default_factory=list)
    first_seen: Optional[str] = Field(default=None)
    last_seen: Optional[str] = Field(default=None)
    discovered_endpoints: int = Field(default=1)
    is_spa_catch_all: bool = Field(default=False)

    @validator('method_set')
    def validate_methods(cls, v):
        if not v:
            raise ValueError("Endpoint method_set must not be empty")
        return [m.upper() for m in v]

    def normalized_key(self) -> str:
        """Dedup key: scheme + host + port + method + normalized_path"""
        methods = ",".join(sorted(self.method_set))
        return f"{self.scheme}://{self.host}:{self.port}/{methods}/{self.path}"
