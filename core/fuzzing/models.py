from core.domain.base import DomainModel
from core.domain.finding import SecurityFinding
from pydantic import Field
from enum import Enum
from typing import List

class ToolStatus(str, Enum):
    SUCCESS = "success"
    TIMEOUT = "timeout"
    ERROR = "error"

class ToolResult(DomainModel):
    tool_name: str = Field(...)
    status: ToolStatus = Field(...)
    findings: List[SecurityFinding] = Field(default_factory=list)
    evidence: str = Field(default="")
    execution_time_ms: float = Field(default=0.0)
