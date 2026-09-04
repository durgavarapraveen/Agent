from core.domain.base import DomainModel
from pydantic import Field
from enum import Enum

class ParameterType(str, Enum):
    QUERY = "query"
    PATH = "path"
    BODY = "body"
    JSON = "json"
    FORM = "form"
    HEADER = "header"
    COOKIE = "cookie"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    INFERRED = "inferred"
    UNKNOWN = "unknown"

class Parameter(DomainModel):
    name: str = Field(...)
    parameter_type: ParameterType = Field(default=ParameterType.UNKNOWN)
    inferred_data_type: str = Field(default="string")
    is_required: bool = Field(default=False)
