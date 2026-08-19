from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import uuid4

class TaskStatus(Enum):
    PENDING = "PENDING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"

class FindingSeverity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class FindingStatus(Enum):
    OBSERVED = "OBSERVED"
    CANDIDATE = "CANDIDATE"
    VALIDATING = "VALIDATING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"

class AgentState(Enum):
    CREATED = "CREATED"
    INITIALIZED = "INITIALIZED"
    READY = "READY"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"

class AttackPathStatus(Enum):
    HYPOTHESIZED = "HYPOTHESIZED"
    PARTIALLY_VALIDATED = "PARTIALLY_VALIDATED"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"

@dataclass
class Evidence:
    evidence_id: str = field(default_factory=lambda: str(uuid4()))
    type: str = ""  # http_response, header, status_code, source_code, tool_output, etc
    content: Any = None
    tool_name: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    source_agent_id: Optional[str] = None
    
    def to_dict(self):
        return asdict(self)

@dataclass
class Finding:
    finding_id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.INFO
    confidence: float = 0.0  # 0.0 to 1.0
    status: FindingStatus = FindingStatus.OBSERVED
    category: str = ""  # e.g., "authentication", "authorization", "injection"
    cwe: Optional[str] = None
    cve: Optional[str] = None
    affected_asset: str = ""
    affected_endpoint: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    reproduction_summary: str = ""
    source_agent_id: str = ""
    related_findings: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    remediation: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self):
        d = asdict(self)
        d['severity'] = self.severity.value
        d['status'] = self.status.value
        d['evidence'] = [e.to_dict() if isinstance(e, Evidence) else e for e in self.evidence]
        d['created_at'] = self.created_at.isoformat()
        d['updated_at'] = self.updated_at.isoformat()
        return d

@dataclass
class Task:
    task_id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    description: str = ""
    objective: str = ""
    capability: str = ""  # e.g., "recon", "api_analysis", "authentication_analysis"
    priority: int = 5  # 1-10
    status: TaskStatus = TaskStatus.PENDING
    parent_task_id: Optional[str] = None
    created_by: str = ""
    assigned_agent_id: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    result: Optional[Dict[str, Any]] = None
    evidence: List[Evidence] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def to_dict(self):
        d = asdict(self)
        d['status'] = self.status.value
        d['evidence'] = [e.to_dict() if isinstance(e, Evidence) else e for e in self.evidence]
        d['created_at'] = self.created_at.isoformat()
        if self.started_at:
            d['started_at'] = self.started_at.isoformat()
        if self.completed_at:
            d['completed_at'] = self.completed_at.isoformat()
        return d

@dataclass
class TaskProposal:
    proposal_id: str = field(default_factory=lambda: str(uuid4()))
    capability: str = ""
    objective: str = ""
    reason: str = ""
    priority: int = 5
    proposed_by: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self):
        return asdict(self)

@dataclass
class AttackPath:
    path_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    steps: List[str] = field(default_factory=list)  # finding IDs
    status: AttackPathStatus = AttackPathStatus.HYPOTHESIZED
    confidence: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self):
        d = asdict(self)
        d['status'] = self.status.value
        d['evidence'] = [e.to_dict() if isinstance(e, Evidence) else e for e in self.evidence]
        d['created_at'] = self.created_at.isoformat()
        return d

@dataclass
class AgentInfo:
    agent_id: str = field(default_factory=lambda: str(uuid4()))
    parent_agent_id: Optional[str] = None
    task_id: str = ""
    role: str = ""
    capability: str = ""
    state: AgentState = AgentState.CREATED
    context: Dict[str, Any] = field(default_factory=dict)
    tools: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    execution_history: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def to_dict(self):
        d = asdict(self)
        d['state'] = self.state.value
        d['created_at'] = self.created_at.isoformat()
        if self.started_at:
            d['started_at'] = self.started_at.isoformat()
        if self.completed_at:
            d['completed_at'] = self.completed_at.isoformat()
        return d

@dataclass
class CentralAgentDecision:
    """Structured decision output from Central Agent."""
    decision_type: str  # CREATE_TASK, APPROVE_TASK, REJECT_TASK, REPLAN, CONTINUE, WAIT, COMPLETE, REQUEST_TOOL, REQUEST_VALIDATION
    reason: str = ""
    tasks: List[Task] = field(default_factory=list)
    approved_tasks: List[str] = field(default_factory=list)
    rejected_tasks: List[str] = field(default_factory=list)
    next_action: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        return asdict(self)

@dataclass
class AgentResult:
    """Standard result format returned by agents."""
    status: str = "completed"  # completed, failed, partial
    summary: str = ""
    discoveries: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    task_proposals: List[TaskProposal] = field(default_factory=list)
    knowledge_updates: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self):
        d = {
            'status': self.status,
            'summary': self.summary,
            'discoveries': self.discoveries,
            'findings': [f.to_dict() for f in self.findings],
            'evidence': [e.to_dict() for e in self.evidence],
            'artifacts': self.artifacts,
            'task_proposals': [p.to_dict() for p in self.task_proposals],
            'knowledge_updates': self.knowledge_updates,
            'recommendations': self.recommendations
        }
        return d
