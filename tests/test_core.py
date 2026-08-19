import pytest
import asyncio
from datetime import datetime

from core.models import Task, Finding, Evidence, AgentInfo, AgentResult, AgentState
from core.events import EventBus, EventType, Event
from core.context import ExecutionContext
from core.exceptions import ScopeViolationException

@pytest.fixture
def event_bus():
    return EventBus()

@pytest.fixture
def execution_context():
    return ExecutionContext(
        target="https://example.com",
        objective="Test assessment",
        mode="DEMO"
    )

class TestModels:
    def test_task_creation(self):
        task = Task(
            title="Test Task",
            description="A test task",
            objective="Test",
            capability="test_capability",
            priority=5
        )
        assert task.task_id
        assert task.status.value == "PENDING"
        assert task.priority == 5
    
    def test_finding_creation(self):
        finding = Finding(
            title="Test Finding",
            description="A test finding",
            severity=finding.__class__.FindingSeverity.HIGH,
            confidence=0.9,
            category="test"
        )
        assert finding.finding_id
        assert finding.status.value == "OBSERVED"
        assert finding.confidence == 0.9
    
    def test_evidence_to_dict(self):
        evidence = Evidence(
            type="http_response",
            content={"status": 200}
        )
        d = evidence.to_dict()
        assert "evidence_id" in d
        assert d["type"] == "http_response"
    
    def test_agent_info(self):
        agent_info = AgentInfo(
            role="Test Agent",
            capability="test_capability",
            state=AgentState.RUNNING
        )
        assert agent_info.agent_id
        assert agent_info.state.value == "RUNNING"

class TestEventBus:
    @pytest.mark.asyncio
    async def test_event_publish_and_subscribe(self, event_bus):
        received_events = []
        
        async def handler(event):
            received_events.append(event)
        
        await event_bus.subscribe(EventType.AGENT_CREATED, handler)
        
        event = Event(
            event_type=EventType.AGENT_CREATED,
            timestamp=datetime.now(),
            source="test_agent",
            data={"name": "test"}
        )
        
        await event_bus.publish(event)
        
        assert len(received_events) == 1
        assert received_events[0].source == "test_agent"
    
    @pytest.mark.asyncio
    async def test_event_history(self, event_bus):
        event1 = Event(
            event_type=EventType.AGENT_CREATED,
            timestamp=datetime.now(),
            source="agent1",
            data={}
        )
        event2 = Event(
            event_type=EventType.TASK_CREATED,
            timestamp=datetime.now(),
            source="task1",
            data={}
        )
        
        await event_bus.publish(event1)
        await event_bus.publish(event2)
        
        agent_events = await event_bus.get_events_by_type(EventType.AGENT_CREATED)
        assert len(agent_events) == 1
        
        agent1_events = await event_bus.get_events_by_source("agent1")
        assert len(agent1_events) == 1

class TestExecutionContext:
    def test_context_creation(self, execution_context):
        assert execution_context.target == "https://example.com"
        assert execution_context.mode == "DEMO"
        assert execution_context.start_time
    
    def test_context_timeout_check(self, execution_context):
        execution_context.global_execution_timeout = 1
        import time
        time.sleep(1.1)
        assert execution_context.is_timeout_exceeded()
    
    def test_context_completion(self, execution_context):
        assert execution_context.end_time is None
        execution_context.mark_complete()
        assert execution_context.end_time is not None
