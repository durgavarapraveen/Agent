from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Callable, List, Dict
from enum import Enum
import asyncio

class EventType(Enum):
    # Agent events
    AGENT_CREATED = "agent_created"
    AGENT_INITIALIZED = "agent_initialized"
    AGENT_STARTED = "agent_started"
    AGENT_COMPLETED = "agent_completed"
    AGENT_FAILED = "agent_failed"
    AGENT_STATE_CHANGED = "agent_state_changed"
    
    # Task events
    TASK_CREATED = "task_created"
    TASK_QUEUED = "task_queued"
    TASK_STARTED = "task_started"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    TASK_BLOCKED = "task_blocked"
    
    # Tool events
    TOOL_CALLED = "tool_called"
    TOOL_COMPLETED = "tool_completed"
    TOOL_FAILED = "tool_failed"
    
    # Knowledge events
    KNOWLEDGE_ADDED = "knowledge_added"
    KNOWLEDGE_UPDATED = "knowledge_updated"
    KNOWLEDGE_DELETED = "knowledge_deleted"
    
    # Finding events
    FINDING_CREATED = "finding_created"
    FINDING_CONFIRMED = "finding_confirmed"
    FINDING_REJECTED = "finding_rejected"
    FINDING_STATUS_CHANGED = "finding_status_changed"
    
    # Task proposal events
    TASK_PROPOSED = "task_proposed"
    TASK_APPROVED = "task_approved"
    TASK_REJECTED = "task_rejected"
    
    # Orchestration events
    REPLAN_STARTED = "replan_started"
    REPLAN_COMPLETED = "replan_completed"
    VALIDATION_STARTED = "validation_started"
    VALIDATION_COMPLETED = "validation_completed"
    ASSESSMENT_COMPLETE = "assessment_complete"

@dataclass
class Event:
    event_type: EventType
    timestamp: datetime
    source: str  # agent_id, task_id, etc
    data: Dict[str, Any]
    
    def to_dict(self):
        d = asdict(self)
        d['event_type'] = self.event_type.value
        d['timestamp'] = self.timestamp.isoformat()
        return d

class EventBus:
    """Central event bus for system-wide events."""
    
    def __init__(self):
        self.subscribers: Dict[EventType, List[Callable]] = {}
        self.event_history: List[Event] = []
        self._lock = asyncio.Lock()
    
    async def subscribe(self, event_type: EventType, callback: Callable):
        """Subscribe to events of a specific type."""
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(callback)
    
    async def publish(self, event: Event):
        """Publish an event to all subscribers."""
        async with self._lock:
            self.event_history.append(event)
        
        if event.event_type in self.subscribers:
            tasks = []
            for callback in self.subscribers[event.event_type]:
                if asyncio.iscoroutinefunction(callback):
                    tasks.append(callback(event))
                else:
                    callback(event)
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    
    async def get_events_by_type(self, event_type: EventType) -> List[Event]:
        """Retrieve events of a specific type."""
        return [e for e in self.event_history if e.event_type == event_type]
    
    async def get_events_by_source(self, source: str) -> List[Event]:
        """Retrieve events from a specific source."""
        return [e for e in self.event_history if e.source == source]
    
    async def get_execution_timeline(self) -> List[Dict[str, Any]]:
        """Get a formatted execution timeline."""
        return [e.to_dict() for e in self.event_history]

class EventLogger:
    """Logs events in a structured way."""
    
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self.log_entries = []
    
    async def log_event(self, event_type: EventType, source: str, data: Dict[str, Any]):
        """Log an event through the event bus."""
        event = Event(
            event_type=event_type,
            timestamp=datetime.now(),
            source=source,
            data=data
        )
        await self.event_bus.publish(event)
        self.log_entries.append(event)
    
    def get_logs(self) -> List[Dict[str, Any]]:
        """Get all logs."""
        return [e.to_dict() for e in self.log_entries]
