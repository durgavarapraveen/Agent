from core.domain.base import DomainModel
from pydantic import Field, validator
from datetime import datetime
from typing import Optional, Dict

class Session(DomainModel):
    session_id: str = Field(...)
    identity_id: str = Field(...)
    authentication_method: str = Field(...)
    cookies: Dict[str, str] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    tokens: Dict[str, str] = Field(default_factory=dict)
    last_activity: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = Field(default=None)
    valid: bool = Field(default=True)
    validation_method: str = Field(default="unknown")

    @validator('identity_id')
    def validate_identity_id(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Session identity_id must be a valid string")
        return v
