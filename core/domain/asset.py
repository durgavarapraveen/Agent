from core.domain.base import DomainModel
from typing import List, Optional
from pydantic import Field

class Technology(DomainModel):
    name: str = Field(...)
    version: str = Field(default="")
    category: str = Field(default="")

class Application(DomainModel):
    name: str = Field(...)
    description: str = Field(default="")
    technologies: List[Technology] = Field(default_factory=list)

class Host(DomainModel):
    hostname: str = Field(...)
    ip_address: str = Field(default="")
    applications: List[Application] = Field(default_factory=list)
    technologies: List[Technology] = Field(default_factory=list)
