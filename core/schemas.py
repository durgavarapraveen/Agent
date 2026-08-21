"""
Strict Pydantic schemas for all framework communication.
Single source of truth for schema definitions.
"""

from pydantic import BaseModel, Field, validator
from datetime import datetime
from typing import Optional, List, Dict, Any, Literal
from enum import Enum
from uuid import uuid4


class TaskStatus(str, Enum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    WAITING_DEPENDENCY = "WAITING_DEPENDENCY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"


class CapabilityType(str, Enum):
    DNS_ENUMERATION = "dns_enumeration"
    PORT_SCANNING = "port_scanning"
    TLS_ANALYSIS = "tls_analysis"
    TECHNOLOGY_FINGERPRINTING = "technology_fingerprinting"
    HTTP_ANALYSIS = "http_analysis"
    ENDPOINT_DISCOVERY = "endpoint_discovery"
    JAVASCRIPT_ANALYSIS = "javascript_analysis"
    WEB_CRAWLING = "web_crawling"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    AUTHENTICATION_TESTING = "authentication_testing"


class ErrorType(str, Enum):
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    COMMAND_SYNTAX_ERROR = "COMMAND_SYNTAX_ERROR"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    TIMEOUT = "TIMEOUT"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    NETWORK_ERROR = "NETWORK_ERROR"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    PARSE_ERROR = "PARSE_ERROR"
    POLICY_REJECTION = "POLICY_REJECTION"
    UNKNOWN = "UNKNOWN"


class BrainDecisionAction(str, Enum):
    SPAWN_AGENTS = "spawn_agents"
    RUN_TASK = "run_task"
    WAIT = "wait"
    REPLAN = "replan"
    COMPLETE = "complete"
    BLOCKED = "blocked"


class SuccessCriterionType(str, Enum):
    KNOWLEDGE_EXISTS = "knowledge_exists"
    KNOWLEDGE_COUNT = "knowledge_count"
    TOOL_SUCCESS = "tool_success"
    EVIDENCE_EXISTS = "evidence_exists"
    NO_ERRORS = "no_errors"


class ExecutionMetrics(BaseModel):
    """Track execution performance"""
    total_duration_seconds: float = 0.0
    task_count_total: int = 0
    task_count_completed: int = 0
    task_count_failed: int = 0
    task_count_blocked: int = 0
    agent_count_total: int = 0
    tool_count_total: int = 0
    tool_count_success: int = 0
    tool_count_failed: int = 0
    llm_call_count: int = 0
    llm_total_latency_seconds: float = 0.0
    knowledge_items_created: int = 0
    evidence_items_created: int = 0
    findings_created: int = 0
    retry_count: int = 0
    parallel_task_max: int = 0


class ErrorInfo(BaseModel):
    """Structured error information"""
    error_type: ErrorType
    message: str
    retryable: bool = False
    attempts: int = 0
    tool: Optional[str] = None
    command: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class Evidence(BaseModel):
    """Provenance information for observations"""
    evidence_id: str = Field(default_factory=lambda: str(uuid4()))
    source: str  # tool name: nmap, openssl, etc
    agent_id: Optional[str] = None
    task_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    raw_output: str
    tool_version: Optional[str] = None
    target: Optional[str] = None
    caveat: Optional[str] = None  # Reliability note


class ToolResult(BaseModel):
    """Standard result from tool execution"""
    tool: str
    capability: str
    status: Literal["success", "failed", "timeout"]
    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[int] = None
    duration_seconds: float = 0.0
    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: Optional[datetime] = None
    target: Optional[str] = None
    error: Optional[ErrorInfo] = None
    evidence_id: Optional[str] = None  # Reference to Evidence store
    data: Dict[str, Any] = Field(default_factory=dict)


class SuccessCriterion(BaseModel):
    """Typed success criteria for task completion"""
    criterion_type: SuccessCriterionType
    entity_type: Optional[str] = None
    operator: Optional[str] = None  # >, <, ==, >=, <=
    value: Optional[Any] = None
    minimum_successful_calls: Optional[int] = None
    capability: Optional[str] = None


class TaskSpec(BaseModel):
    """Complete task specification"""
    task_id: str = Field(default_factory=lambda: str(uuid4()))
    objective: str
    capability: CapabilityType
    inputs: Dict[str, Any] = Field(default_factory=dict)
    context_requirements: List[str] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)
    success_criteria: List[SuccessCriterion] = Field(default_factory=list)
    constraints: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 300
    max_steps: int = 10
    priority: int = Field(default=5, ge=1, le=10)
    parent_task_id: Optional[str] = None


class CapabilityRequest(BaseModel):
    """Request to resolve and execute a capability"""
    capability: CapabilityType
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    authorized_scope: List[str] = Field(default_factory=list)


class CapabilityResult(BaseModel):
    """Result of capability resolution and execution"""
    capability: CapabilityType
    resolved_tool: str
    tool_result: ToolResult
    observations: List[Dict[str, Any]] = Field(default_factory=list)


class KnowledgeItem(BaseModel):
    """Structured knowledge with full provenance"""
    knowledge_id: str = Field(default_factory=lambda: str(uuid4()))
    entity_type: str  # subdomain, host, port, service, endpoint, etc
    entity_value: str  # the actual value
    attributes: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source: str  # tool that discovered it
    evidence_id: str  # Reference to Evidence
    discovered_by: str  # agent_id
    discovered_at: datetime = Field(default_factory=datetime.now)
    version: Optional[str] = None
    related_knowledge: List[str] = Field(default_factory=list)  # knowledge_ids


class Finding(BaseModel):
    """Security finding with full evidence trail"""
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    status: Literal["OBSERVED", "CANDIDATE", "VALIDATING", "CONFIRMED", "REJECTED"]
    category: str  # authentication, injection, exposure, etc
    cwe: Optional[str] = None
    cve: Optional[str] = None
    affected_asset: str
    affected_endpoint: Optional[str] = None
    observations: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)  # References to Evidence
    source_agent_id: str
    validation_state: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class AgentResult(BaseModel):
    """Standard result from agent execution"""
    task_id: str
    agent_id: str
    status: Literal["completed", "failed", "partial", "timeout"]
    observations: List[Dict[str, Any]] = Field(default_factory=list)
    knowledge_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    next_recommendations: List[str] = Field(default_factory=list)
    errors: List[ErrorInfo] = Field(default_factory=list)
    execution_metrics: Optional[ExecutionMetrics] = None


class BrainDecision(BaseModel):
    """Canonical decision output from Central Brain"""
    action: BrainDecisionAction
    thought: Optional[str] = None
    tasks: List[TaskSpec] = Field(default_factory=list)
    wait_seconds: Optional[int] = None
    reason: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ExecutionState(BaseModel):
    """Complete execution state for Brain replanning"""
    target: str
    scope: Dict[str, Any]
    tasks_completed: List[TaskSpec] = Field(default_factory=list)
    tasks_running: List[TaskSpec] = Field(default_factory=list)
    tasks_failed: List[str] = Field(default_factory=list)  # task_ids
    tasks_blocked: List[str] = Field(default_factory=list)  # task_ids
    task_dependency_graph: Dict[str, List[str]] = Field(default_factory=dict)
    knowledge_summary: Dict[str, Any] = Field(default_factory=dict)
    evidence_summary: Dict[str, int] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    available_capabilities: List[CapabilityType] = Field(default_factory=list)
    objectives: List[str] = Field(default_factory=list)
    execution_metrics: Optional[ExecutionMetrics] = None