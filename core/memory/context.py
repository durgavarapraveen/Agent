from dataclasses import dataclass, field
from typing import Any, Optional, Dict
from datetime import datetime

@dataclass
class ExecutionContext:
    """Central context for execution - holds all shared state."""
    
    target: str  # URL, repository path, or "DEMO"
    objective: str
    mode: str  # "DEMO", "WEB", "SOURCE"
    
    # System components
    knowledge_store: Any = None
    llm_provider: Any = None
    tool_manager: Any = None
    mcp_manager: Any = None
    scope_manager: Any = None
    event_bus: Any = None
    event_logger: Any = None
    
    # Execution state
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    
    # Limits and config
    max_concurrent_agents: int = 4
    max_total_tasks: int = 100
    max_task_runtime: int = 300  # seconds
    max_agent_iterations: int = 10
    max_tool_calls: int = 500
    global_execution_timeout: int = 1800  # 30 minutes
    
    # Metadata
    assessor_name: str = "AutonomousSecurityAgent"
    version: str = "1.0.0"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_global_elapsed_seconds(self) -> float:
        """Get seconds elapsed since start."""
        return (datetime.now() - self.start_time).total_seconds()
    
    def is_timeout_exceeded(self) -> bool:
        """Check if global timeout exceeded."""
        return self.get_global_elapsed_seconds() > self.global_execution_timeout
    
    def mark_complete(self):
        """Mark execution as complete."""
        self.end_time = datetime.now()
    
    def get_duration_seconds(self) -> float:
        """Get total execution duration."""
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()
