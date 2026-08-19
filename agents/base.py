import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, Optional, List, TYPE_CHECKING
import logging

if TYPE_CHECKING:
    from core.context import ExecutionContext

from core.models import AgentState, AgentInfo, AgentResult, Task, TaskProposal
from core.events import EventType

logger = logging.getLogger(__name__)

class BaseAgent(ABC):
    """Base class for all agents."""
    
    def __init__(self, agent_id: str, role: str, capability: str, context: Any):
        self.agent_id = agent_id
        self.role = role
        self.capability = capability
        self.context = context
        
        self.state = AgentState.CREATED
        self.findings = []
        self.discoveries = []
        self.task_proposals = []
        self.execution_history = []
        
        self.task: Optional[Task] = None
        self.parent_agent_id: Optional[str] = None
        
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
    
    async def initialize(self):
        """Initialize the agent."""
        self.state = AgentState.INITIALIZED
        logger.info(f"Agent {self.agent_id} ({self.role}) initialized")
        
        await self.context.event_logger.log_event(
            EventType.AGENT_INITIALIZED,
            self.agent_id,
            {"role": self.role, "capability": self.capability}
        )
    
    async def execute_task(self, task: Task) -> AgentResult:
        """Execute a task."""
        self.task = task
        self.state = AgentState.RUNNING
        self.start_time = datetime.now()
        
        await self.context.event_logger.log_event(
            EventType.AGENT_STARTED,
            self.agent_id,
            {"task_id": task.task_id}
        )
        
        try:
            # Check timeout
            if self.context.is_timeout_exceeded():
                logger.warning(f"Agent {self.agent_id} - global timeout exceeded")
                self.state = AgentState.TIMEOUT
                return AgentResult(status="timeout")
            
            # Execute the actual work
            result = await self.perform_work()
            
            self.state = AgentState.COMPLETED
            self.end_time = datetime.now()
            
            # Store discoveries
            self.discoveries.extend(result.discoveries)
            self.findings.extend(result.findings)
            self.task_proposals.extend(result.task_proposals)
            
            await self.context.event_logger.log_event(
                EventType.AGENT_COMPLETED,
                self.agent_id,
                {
                    "findings_count": len(result.findings),
                    "discoveries_count": len(result.discoveries),
                    "proposals_count": len(result.task_proposals)
                }
            )
            
            return result
        
        except asyncio.TimeoutError:
            logger.error(f"Agent {self.agent_id} timed out")
            self.state = AgentState.TIMEOUT
            return AgentResult(status="timeout")
        
        except Exception as e:
            logger.error(f"Agent {self.agent_id} failed: {e}", exc_info=True)
            self.state = AgentState.FAILED
            
            await self.context.event_logger.log_event(
                EventType.AGENT_FAILED,
                self.agent_id,
                {"error": str(e)}
            )
            
            return AgentResult(status="failed", summary=f"Error: {e}")
        
        finally:
            self.end_time = datetime.now()
    
    @abstractmethod
    async def perform_work(self) -> AgentResult:
        """Perform the actual agent work - must be implemented by subclasses."""
        pass
    
    def propose_task(self, capability: str, objective: str, reason: str, priority: int = 5) -> TaskProposal:
        """Propose a new task."""
        proposal = TaskProposal(
            capability=capability,
            objective=objective,
            reason=reason,
            priority=priority,
            proposed_by=self.agent_id
        )
        self.task_proposals.append(proposal)
        return proposal
    
    def get_info(self) -> AgentInfo:
        """Get agent information."""
        return AgentInfo(
            agent_id=self.agent_id,
            parent_agent_id=self.parent_agent_id,
            task_id=self.task.task_id if self.task else "",
            role=self.role,
            capability=self.capability,
            state=self.state,
            findings=[f.finding_id for f in self.findings],
            artifacts=[]
        )
    
    async def log_execution_event(self, event_type: EventType, data: Dict[str, Any]):
        """Log an execution event."""
        await self.context.event_logger.log_event(event_type, self.agent_id, data)
    
    def get_runtime_seconds(self) -> float:
        """Get runtime in seconds."""
        start = self.start_time or datetime.now()
        end = self.end_time or datetime.now()
        return (end - start).total_seconds()
