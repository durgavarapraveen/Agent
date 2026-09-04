from core.domain.base import DomainModel
from pydantic import Field
from typing import Optional, List, Dict

class ResponseData(DomainModel):
    status_code: int = Field(...)
    headers: Dict[str, str] = Field(default_factory=dict)
    body: bytes = Field(default=b"")
    body_hash: str = Field(default="")

class CapturedRequest(DomainModel):
    request_id: str = Field(...)
    method: str = Field(...)
    url: str = Field(...)
    full_headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    body: Optional[bytes] = Field(default=None)
    parameters_used: List[str] = Field(default_factory=list)
    identity_id: str = Field(default="anonymous")
    session_id: str = Field(default="")
    response: ResponseData = Field(...)
