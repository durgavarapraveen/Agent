from core.domain.base import DomainModel
from pydantic import Field, validator
from enum import Enum
from datetime import datetime
from typing import Optional

class Role(str, Enum):
    STANDARD = "standard"
    ADMINISTRATOR = "administrator"
    GUEST = "guest"
    UNKNOWN = "unknown"

class AuthenticationState(str, Enum):
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
    AUTHENTICATED = "AUTHENTICATED"
    EXPIRED = "EXPIRED"
    INVALID = "INVALID"

class Identity(DomainModel):
    identity_id: str = Field(...)
    label: str = Field(...)
    username_reference: str = Field(...)
    role: Role = Field(default=Role.UNKNOWN)
    credential_source: str = Field(default="env_var")
    authentication_state: AuthenticationState = Field(default=AuthenticationState.NOT_AUTHENTICATED)
    last_authenticated: Optional[datetime] = Field(default=None)

    @validator('role', pre=True)
    def parse_role(cls, v):
        if isinstance(v, str):
            try:
                return Role(v.lower())
            except ValueError:
                return Role.UNKNOWN
        return v
