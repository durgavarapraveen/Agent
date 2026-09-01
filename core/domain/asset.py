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

class Page(DomainModel):
    url: str = Field(...)
    title: str = Field(default="")
    
class Cookie(DomainModel):
    name: str = Field(...)
    domain: str = Field(default="")
    path: str = Field(default="/")
    secure: bool = Field(default=False)
    http_only: bool = Field(default=False)
    
class Token(DomainModel):
    name: str = Field(...)
    token_type: str = Field(default="jwt")
    
class File(DomainModel):
    filename: str = Field(...)
    extension: str = Field(default="")
    mime_type: str = Field(default="")
    
class DataObject(DomainModel):
    object_type: str = Field(...)
    object_id: str = Field(...)
    
class Workflow(DomainModel):
    name: str = Field(...)
    description: str = Field(default="")
    request_ids: List[str] = Field(default_factory=list)

