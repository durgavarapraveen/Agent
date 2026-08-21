"""
Tests for refactored architecture.
Run: pytest test_architecture.py -v
"""

import pytest
from datetime import datetime
from core.schemas import (
    TaskSpec, TaskStatus, CapabilityType, BrainDecision, BrainDecisionAction,
    ToolResult, ErrorInfo, ErrorType, Evidence, KnowledgeItem, SuccessCriterion,
    SuccessCriterionType
)
from core.task_manager import TaskManager, Task, TaskStateTransitionError
from orchestrator.scheduler import Scheduler
from core.tool_definitions import CapabilityRegistry
from core.error_classifier import ErrorClassifier
from core.result_normalizers import NormalizerFactory, DNSResultNormalizer
from core.policy_validator import PolicyValidator, ScopeValidator
from core.stores import EvidenceStore, KnowledgeStore, FindingStore
from core.context_resolver import ContextResolver


class TestTaskStateTransitions:
    """Test task state machine"""
    
    def test_valid_transition_created_to_queued(self):
        spec = TaskSpec(objective="test", capability=CapabilityType.DNS_ENUMERATION)
        task = Task(spec)
        assert task.status == TaskStatus.CREATED
        task.transition_to(TaskStatus.QUEUED)
        assert task.status == TaskStatus.QUEUED
    
    def test_invalid_transition(self):
        spec = TaskSpec(objective="test", capability=CapabilityType.DNS_ENUMERATION)
        task = Task(spec)
        with pytest.raises(TaskStateTransitionError):
            task.transition_to(TaskStatus.COMPLETED)
    
    def test_task_completion_sets_time(self):
        spec = TaskSpec(objective="test", capability=CapabilityType.DNS_ENUMERATION)
        task = Task(spec)
        assert task.started_at is None
        task.transition_to(TaskStatus.QUEUED)
        task.transition_to(TaskStatus.RUNNING)
        assert task.started_at is not None
        task.transition_to(TaskStatus.COMPLETED)
        assert task.completed_at is not None


class TestTaskManager:
    """Test task management and deduplication"""
    
    def test_create_task(self):
        tm = TaskManager()
        spec = TaskSpec(objective="test", capability=CapabilityType.DNS_ENUMERATION)
        task = tm.create_task(spec)
        assert task.spec.task_id in tm.tasks
    
    def test_task_deduplication(self):
        tm = TaskManager()
        spec1 = TaskSpec(
            objective="Enumerate DNS",
            capability=CapabilityType.DNS_ENUMERATION,
            inputs={"domain": "example.com"}
        )
        spec2 = TaskSpec(
            objective="Enumerate DNS",
            capability=CapabilityType.DNS_ENUMERATION,
            inputs={"domain": "example.com"}
        )
        
        tm.create_task(spec1)
        tm.register_task_signature(spec1, spec1.task_id)
        
        should_create, reason = tm.should_create_task(spec2)
        assert not should_create
        assert "Duplicate" in reason
    
    def test_dependency_graph(self):
        tm = TaskManager()
        spec1 = TaskSpec(objective="task1", capability=CapabilityType.DNS_ENUMERATION)
        spec2 = TaskSpec(
            objective="task2",
            capability=CapabilityType.PORT_SCANNING,
            dependencies=[spec1.task_id]
        )
        
        tm.create_task(spec1)
        tm.create_task(spec2)
        
        graph = tm.get_dependency_graph()
        assert spec1.task_id in graph
        assert spec2.task_id in graph
        assert spec1.task_id in graph[spec2.task_id]


class TestScheduler:
    """Test dependency-aware scheduling"""
    
    def test_independent_tasks_in_parallel(self):
        tm = TaskManager()
        scheduler = Scheduler(tm)
        
        specs = [
            TaskSpec(objective="task1", capability=CapabilityType.DNS_ENUMERATION),
            TaskSpec(objective="task2", capability=CapabilityType.PORT_SCANNING),
        ]
        
        scheduler.schedule_tasks(specs)
        
        # Both should be queued immediately (no dependencies)
        assert len(scheduler.parallel_groups) == 1
        assert len(scheduler.parallel_groups[0]) == 2
    
    def test_dependent_task_waits(self):
        tm = TaskManager()
        scheduler = Scheduler(tm)
        
        spec1 = TaskSpec(objective="task1", capability=CapabilityType.DNS_ENUMERATION)
        spec2 = TaskSpec(
            objective="task2",
            capability=CapabilityType.PORT_SCANNING,
            dependencies=[spec1.task_id]
        )
        
        scheduler.schedule_tasks([spec1, spec2])
        
        task2 = tm.get_task(spec2.task_id)
        assert task2.status == TaskStatus.WAITING_DEPENDENCY
    
    def test_dependency_satisfaction_unlocks_task(self):
        tm = TaskManager()
        scheduler = Scheduler(tm)
        
        spec1 = TaskSpec(objective="task1", capability=CapabilityType.DNS_ENUMERATION)
        spec2 = TaskSpec(
            objective="task2",
            capability=CapabilityType.PORT_SCANNING,
            dependencies=[spec1.task_id]
        )
        
        scheduler.schedule_tasks([spec1, spec2])
        
        # Complete task1
        tm.complete_task(spec1.task_id)
        
        # Process dependencies
        scheduler.process_dependencies()
        
        # Task2 should now be queued
        task2 = tm.get_task(spec2.task_id)
        assert task2.status == TaskStatus.QUEUED


class TestToolRegistry:
    """Test tool and capability management"""
    
    def test_tool_registration(self):
        registry = CapabilityRegistry()
        tools = registry.get_all_available_tools()
        assert len(tools) > 0
    
    def test_capability_resolution(self):
        registry = CapabilityRegistry()
        tool = registry.resolve_capability(CapabilityType.DNS_ENUMERATION)
        assert tool is not None
        assert tool.capability == CapabilityType.DNS_ENUMERATION
    
    def test_alternative_tool_resolution(self):
        registry = CapabilityRegistry()
        tool = registry.resolve_tool_alternative("nmap")
        # Should find port_scanning capability alternatives


class TestErrorClassification:
    """Test error classification and retry policy"""
    
    def test_timeout_error(self):
        classifier = ErrorClassifier()
        error = classifier.classify_error("nmap", 124, "", "Timeout")
        assert error.error_type == ErrorType.TIMEOUT
        assert error.retryable is True
    
    def test_tool_not_found(self):
        classifier = ErrorClassifier()
        error = classifier.classify_error("missing_tool", 127, "", "command not found")
        assert error.error_type == ErrorType.TOOL_UNAVAILABLE
        assert error.retryable is False
    
    def test_package_installation_blocked(self):
        classifier = ErrorClassifier()
        error = classifier.classify_error(
            "bash", 0, "", "",
            command="apt-get install nginx"
        )
        assert error.error_type == ErrorType.POLICY_REJECTION
        assert error.retryable is False


class TestPolicyValidator:
    """Test policy enforcement"""
    
    def test_scope_validation(self):
        validator = PolicyValidator(["example.com"])
        authorized, reason = validator.validate_scope("example.com")
        assert authorized is True
        
        authorized, reason = validator.validate_scope("evil.com")
        assert authorized is False
    
    def test_command_blocking(self):
        validator = PolicyValidator(["example.com"])
        valid, error = validator.validate_command("apt-get install nginx")
        assert valid is False
        assert error.error_type == ErrorType.POLICY_REJECTION
    
    def test_safe_command_allowed(self):
        validator = PolicyValidator(["example.com"])
        valid, error = validator.validate_command("nmap -p 80 example.com")
        assert valid is True


class TestScopeValidator:
    """Test scope filtering"""
    
    def test_authorized_target_filtering(self):
        validator = ScopeValidator(["example.com"])
        targets = ["example.com", "evil.com", "sub.example.com"]
        authorized = validator.get_discovered_targets(targets)
        assert "example.com" in authorized
        assert "evil.com" not in authorized


class TestResultNormalization:
    """Test result normalization"""
    
    def test_dns_result_normalization(self):
        result = ToolResult(
            tool="dns_lookup_python",
            capability="dns_enumeration",
            status="success",
            stdout="192.168.1.1\n10.0.0.1",
            target="example.com"
        )
        
        normalizer = NormalizerFactory.get_normalizer(result)
        evidence = normalizer.create_evidence()
        knowledge = normalizer.normalize()
        
        assert evidence is not None
        assert len(knowledge) >= 2
        assert all(k.entity_type == "host" for k in knowledge)


class TestStores:
    """Test evidence and knowledge stores"""
    
    def test_evidence_storage(self):
        store = EvidenceStore()
        evidence = Evidence(
            source="nmap",
            raw_output="22/tcp open",
            confidence=0.95
        )
        eid = store.store(evidence)
        assert store.get(eid) == evidence
    
    def test_knowledge_storage_and_dedup(self):
        store = KnowledgeStore()
        
        item1 = KnowledgeItem(
            entity_type="host",
            entity_value="192.168.1.1",
            confidence=0.95,
            source="nmap",
            evidence_id="e1",
            discovered_by="agent1"
        )
        
        kid1 = store.store(item1)
        assert kid1 in store.knowledge
        
        # Same entity - should not create duplicate
        assert store.entity_exists("host", "192.168.1.1")
    
    def test_knowledge_retrieval(self):
        store = KnowledgeStore()
        item = KnowledgeItem(
            entity_type="port",
            entity_value="80",
            confidence=0.95,
            source="nmap",
            evidence_id="e1",
            discovered_by="agent1"
        )
        store.store(item)
        
        retrieved = store.get_by_type("port")
        assert len(retrieved) == 1


class TestContextResolver:
    """Test context resolution"""
    
    def test_host_resolution(self):
        ks = KnowledgeStore()
        item = KnowledgeItem(
            entity_type="host",
            entity_value="192.168.1.1",
            confidence=0.95,
            source="dns",
            evidence_id="e1",
            discovered_by="agent1"
        )
        ks.store(item)
        
        resolver = ContextResolver(ks)
        hosts = resolver.resolve_hosts(["*"])
        assert len(hosts) == 1


class TestCentralBrain:
    """Test central brain decision-making"""
    
    def test_brain_creates_structured_decision(self):
        from central_brain_v2 import CentralBrainV2
        brain = CentralBrainV2("example.com")
        state = brain.get_execution_state()
        
        decision = brain.make_decision(state)
        assert isinstance(decision, BrainDecision)
        assert decision.action in [e for e in BrainDecisionAction]


class TestBrainDecisionSchema:
    """Test BrainDecision schema validation"""
    
    def test_valid_decision(self):
        decision = BrainDecision(
            action=BrainDecisionAction.SPAWN_AGENTS,
            tasks=[],
        )
        assert decision.action == BrainDecisionAction.SPAWN_AGENTS
    
    def test_decision_serialization(self):
        decision = BrainDecision(
            action=BrainDecisionAction.COMPLETE,
            reason="Test complete"
        )
        d = decision.model_dump()  # CHANGE FROM .dict()
        assert d["action"] == "complete"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
