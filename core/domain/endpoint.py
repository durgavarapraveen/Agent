from core.domain.base import DomainModel
from core.domain.parameter import Parameter
from core.domain.identity import Identity
from pydantic import Field, validator
from typing import List, Dict

class SchemaNode(DomainModel):
    """Recursive model to define expected response shapes without Dict[str, Any]."""
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
    
    # We use a SchemaNode tree rather than Dict[str, Any] to represent JSON schemas securely
    response_schema: Dict[str, SchemaNode] = Field(default_factory=dict)
    
    auth_required: bool = Field(default=False)
    auth_contexts: List[Identity] = Field(default_factory=list)
    discovered_endpoints: int = Field(default=1)
    
    @validator('method_set')
    def validate_methods(cls, v):
        if not v:
            raise ValueError("Endpoint method_set must not be empty")
        return [m.upper() for m in v]
