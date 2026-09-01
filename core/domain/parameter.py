from core.domain.base import DomainModel
from pydantic import Field
from enum import Enum

class ParameterType(str, Enum):
    QUERY = "query"
    PATH = "path"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"
    UNKNOWN = "unknown"

class Parameter(DomainModel):
    name: str = Field(...)
    parameter_type: ParameterType = Field(default=ParameterType.UNKNOWN)
    inferred_data_type: str = Field(default="string")
    is_required: bool = Field(default=False)
