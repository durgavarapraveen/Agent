"""
Evidence and provenance system.
Preserve all raw data + structured observations.
"""

from pydantic import BaseModel, Field
from datetime import datetime
from uuid import uuid4
from typing import Any, Optional, Dict

class Evidence(BaseModel):
    """Raw evidence from tool execution"""
    evidence_id: str = Field(default_factory=lambda: str(uuid4())[:12])
    source: str  # tool name
    tool_name: Optional[str] = None
    agent_id: Optional[str] = None
    task_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    raw_output: str  # PRESERVE ORIGINAL
    parsed: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.5  # 0.0 to 1.0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }

class KnowledgeItem(BaseModel):
    """Structured observation (NOT normalized away)"""
    item_id: str = Field(default_factory=lambda: str(uuid4())[:12])
    entity_type: str  # "host", "port", "service", "endpoint", "technology", "credential"
    value: str
    target: str
    version: Optional[str] = None  # PRESERVE VERSION
    confidence: float = 0.8  # 0.0 to 1.0
    source: str  # which tool found this
    evidence_id: Optional[str] = None  # link back to evidence
    discovered_at: datetime = Field(default_factory=datetime.now)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }

class Finding(BaseModel):
    """Security finding (observation + evidence + interpretation)"""
    finding_id: str = Field(default_factory=lambda: str(uuid4())[:12])
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: float = 0.8
    status: str = "OBSERVED"  # OBSERVED, CANDIDATE, VALIDATING, CONFIRMED, REJECTED
    category: str  # e.g., "authentication", "injection", "exposure"
    cwe: Optional[str] = None
    cve: Optional[str] = None
    affected_asset: str
    affected_endpoint: Optional[str] = None
    evidence_ids: list[str] = Field(default_factory=list)  # References to Evidence
    knowledge_ids: list[str] = Field(default_factory=list)  # References to KnowledgeItems
    reproduction_summary: str = ""
    source_agent_id: Optional[str] = None
    remediation: str = ""
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    
    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }