from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum
from core.domain.finding import SecurityFinding

class ExecutionStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"

class ToolAttempt(BaseModel):
    tool_name: str
    status: ExecutionStatus = ExecutionStatus.PENDING
    evidence: str = ""
    execution_time_ms: float = 0.0

class ExecutionResult(BaseModel):
    capability: str
    target: str
    status: ExecutionStatus = ExecutionStatus.PENDING
    attempts: List[ToolAttempt] = Field(default_factory=list)
    findings: List[SecurityFinding] = Field(default_factory=list)
