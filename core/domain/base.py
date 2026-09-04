from datetime import datetime
import uuid
from pydantic import BaseModel, Field
import json

class DomainModel(BaseModel):
    """Base class for all canonical domain models."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    source: str = Field(default="unknown")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    
    class Config:
        validate_assignment = True
        extra = "forbid"
        
    @classmethod
    def from_dict(cls, data: dict):
        return cls(**data)
        
    def to_dict(self) -> dict:
        # Avoid dumping raw datetime objects natively, pydantic can serialize them if using model_dump
        return self.model_dump(mode="json")
        
    def __str__(self) -> str:
        return f"<{self.__class__.__name__} id={self.id}>"
