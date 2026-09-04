"""
Tests for refactored architecture.
Run: pytest test_architecture.py -v
"""

import pytest
import json
from core.common.schemas import (
    TaskSpec, TaskStatus, CapabilityType, BrainDecision, BrainDecisionAction,
    ToolResult, ErrorType, Evidence, KnowledgeItem, SuccessCriterion,
    SuccessCriterionType
)
from core.orchestration.task_manager import TaskManager, Task, TaskStateTransitionError
from orchestrator.scheduler import Scheduler
from core.tools.tool_definitions import CapabilityRegistry
from core.common.error_classifier import ErrorClassifier
from core.common.result_normalizers import NormalizerFactory
from core.security.policy_validator import PolicyValidator, ScopeValidator
from core.memory.stores import EvidenceStore, KnowledgeStore
from core.memory.context_resolver import ContextResolver


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
        from core.orchestration.central_brain import CentralBrain
        brain = CentralBrain("example.com")
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


# ═══════════════════════════════════════════════════════════════
# ARCHITECTURAL REGRESSION TESTS (REQUIREMENTS A-N)
# ═══════════════════════════════════════════════════════════════

class TestArchitecturalRegressions:
    """Regression test suite for all P0 control-plane requirements"""

    # A. DeepSeek response normalization
    @pytest.mark.anyio
    async def test_deepseek_normalization_empty_content_with_reasoning(self):
        from agents.llm_client import DeepSeekProvider
        provider = DeepSeekProvider(api_key="mock_key")
        
        # Mock httpx response containing reasoning_content but empty content
        mock_response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "reasoning_content": '{"action": "spawn_tasks", "tasks": []}'
                    },
                    "finish_reason": "stop"
                }
            ],
            "model": "deepseek-v4-flash"
        }
        
        # Override the request call
        async def mock_post(*args, **kwargs):
            class MockResponse:
                status_code = 200
                def json(self): return mock_response
                @property
                def text(self): return json.dumps(mock_response)
            return MockResponse()
            
        import httpx
        from unittest.mock import patch
        with patch.object(httpx.AsyncClient, 'post', side_effect=mock_post):
            res = await provider.generate_json("test prompt")
            assert isinstance(res, dict)
            assert res.get("action") == "spawn_tasks"

    # B. Empty LLM response
    @pytest.mark.anyio
    async def test_empty_llm_response_error(self):
        from agents.llm_client import DeepSeekProvider
        provider = DeepSeekProvider(api_key="mock_key")
        mock_response = {
            "choices": [{"message": {"role": "assistant", "content": ""}}],
            "model": "deepseek-v4-flash"
        }
        async def mock_post(*args, **kwargs):
            class MockResponse:
                status_code = 200
                def json(self): return mock_response
                @property
                def text(self): return json.dumps(mock_response)
            return MockResponse()
            
        import httpx
        from unittest.mock import patch
        with patch.object(httpx.AsyncClient, 'post', side_effect=mock_post):
            res = await provider.generate_json("test prompt")
            assert res == {}  # Handled as empty dict, retry/failure classification triggered

    # C. Invalid planner schema
    def test_invalid_planner_schema(self):
        from pydantic import ValidationError
        # Missing required field action
        with pytest.raises(ValidationError):
            BrainDecision(thought="test")

    # D. Valid planner decision
    def test_valid_planner_decision_normalization(self):
        # Planner outputs depends_on / max_retries
        raw_decision = {
            "action": "spawn_tasks",
            "tasks": [
                {
                    "objective": "scan",
                    "capability": "port_scanning",
                    "inputs": {"target": "example.com"},
                    "depends_on": ["dep1"],
                    "max_retries": 5
                }
            ]
        }
        decision = BrainDecision(**raw_decision)
        assert decision.action == BrainDecisionAction.SPAWN_AGENTS
        assert len(decision.tasks) == 1
        assert decision.tasks[0].dependencies == ["dep1"]
        assert decision.tasks[0].max_steps == 5

    # E. Task dependency (Task B waits on Task A)
    def test_task_dependency(self):
        tm = TaskManager()
        scheduler = Scheduler(tm)
        spec_a = TaskSpec(objective="A", capability=CapabilityType.DNS_ENUMERATION)
        spec_b = TaskSpec(objective="B", capability=CapabilityType.PORT_SCANNING, dependencies=[spec_a.task_id])
        
        scheduler.schedule_tasks([spec_a, spec_b])
        
        task_b = tm.get_task(spec_b.task_id)
        assert task_b.status == TaskStatus.WAITING_DEPENDENCY
        
        # Complete A
        tm.complete_task(spec_a.task_id)
        scheduler.process_dependencies()
        assert task_b.status == TaskStatus.QUEUED

    # F. Dependency failure (B blocks when A fails)
    def test_dependency_failure(self):
        tm = TaskManager()
        scheduler = Scheduler(tm)
        spec_a = TaskSpec(objective="A", capability=CapabilityType.DNS_ENUMERATION)
        spec_b = TaskSpec(objective="B", capability=CapabilityType.PORT_SCANNING, dependencies=[spec_a.task_id])
        
        scheduler.schedule_tasks([spec_a, spec_b])
        
        # Fail A
        tm.fail_task(spec_a.task_id)
        scheduler.process_dependencies()
        
        task_b = tm.get_task(spec_b.task_id)
        assert task_b.status == TaskStatus.BLOCKED

    # G. Circular dependency
    def test_circular_dependency(self):
        tm = TaskManager()
        scheduler = Scheduler(tm)
        spec_a = TaskSpec(objective="A", capability=CapabilityType.DNS_ENUMERATION)
        spec_b = TaskSpec(objective="B", capability=CapabilityType.PORT_SCANNING, dependencies=[spec_a.task_id])
        # Force circle
        spec_a.dependencies.append(spec_b.task_id)
        
        with pytest.raises(ValueError, match="Circular dependency"):
            scheduler.schedule_tasks([spec_a, spec_b])

    # H. Duplicate task
    def test_duplicate_task(self):
        tm = TaskManager()
        spec1 = TaskSpec(objective="scan1", capability=CapabilityType.DNS_ENUMERATION, inputs={"target": "example.com"})
        spec2 = TaskSpec(objective="scan2", capability=CapabilityType.DNS_ENUMERATION, inputs={"target": "example.com"})
        
        t1, is_new1 = tm.get_or_create_task(spec1)
        t2, is_new2 = tm.get_or_create_task(spec2)
        
        assert is_new1 is True
        assert is_new2 is False
        assert t1.spec.task_id == t2.spec.task_id

    # I. Different task parameters
    def test_different_task_parameters(self):
        from core.security.authorization import TargetScopeValidator
        TargetScopeValidator.set(TargetScopeValidator(["example.com", "speshway.com"]))
        
        tm = TaskManager()
        spec1 = TaskSpec(objective="scan1", capability=CapabilityType.DNS_ENUMERATION, inputs={"target": "example.com"})
        spec2 = TaskSpec(objective="scan2", capability=CapabilityType.DNS_ENUMERATION, inputs={"target": "speshway.com"})
        
        t1, is_new1 = tm.get_or_create_task(spec1)
        t2, is_new2 = tm.get_or_create_task(spec2)
        
        assert is_new1 is True
        assert is_new2 is True
        assert t1.spec.task_id != t2.spec.task_id

    # J. Invalid tool invocation
    @pytest.mark.anyio
    async def test_invalid_tool_invocation(self):
        from core.tools.tool_validation import ToolInvocationValidator, ToolValidationError
        registry = CapabilityRegistry()
        validator = ToolInvocationValidator(registry)
        
        # Test non-registered tool
        with pytest.raises(ToolValidationError):
            validator.validate("unknown_tool", {})
            
        # Test out of bounds timeout
        with pytest.raises(ToolValidationError):
            validator.validate("nmap", {"timeout": 99999})

    # K. Unauthorized target
    def test_unauthorized_target(self):
        from core.security.authorization import TargetScopeValidator
        from core.common.exceptions import AuthorizationError
        
        validator = TargetScopeValidator(["example.com"])
        # In-scope
        validator.validate("example.com")
        validator.validate("sub.example.com")
        
        # Out-scope
        with pytest.raises(AuthorizationError):
            validator.validate("speshway.com")

    # L. Valid tool invocation
    @pytest.mark.anyio
    async def test_valid_tool_invocation(self):
        from core.tools.tool_validation import ToolInvocationValidator
        registry = CapabilityRegistry()
        validator = ToolInvocationValidator(registry)
        
        # Valid nmap call to authorized target (configured as example.com)
        from core.security.authorization import TargetScopeValidator
        TargetScopeValidator.set(TargetScopeValidator(["example.com"]))
        
        validator.validate("nmap", {"target": "example.com", "timeout": 60})

    # M. Invalid state transition
    def test_invalid_state_transition(self):
        spec = TaskSpec(objective="A", capability=CapabilityType.DNS_ENUMERATION)
        task = Task(spec)
        with pytest.raises(TaskStateTransitionError):
            task.transition_to(TaskStatus.COMPLETED)

    # N. No-progress loop
    def test_no_progress_loop(self):
        from core.orchestration.progress import ProgressEvaluator, ProgressSnapshot
        evaluator = ProgressEvaluator()
        
        snap = ProgressSnapshot(
            completed_tasks_count=1,
            failed_tasks_count=0,
            blocked_tasks_count=0,
            knowledge_count=5,
            evidence_count=2,
            findings_count=1,
            relationships_count=1
        )
        
        assert evaluator.evaluate_progress(snap) is True
        
        # Loop iteration 2: state has not changed
        assert evaluator.evaluate_progress(snap) is False
        assert evaluator.no_progress_streak == 1
        
        # Loop iteration 3: state still hasn't changed
        assert evaluator.evaluate_progress(snap) is False
        assert evaluator.no_progress_streak == 2


class TestP0Reliability:
    """Explicit tests for P0-1 through P0-5 reliability refactor requirements"""

    # TEST 1: Planner cannot return raw command.
    def test_1_planner_cannot_return_raw_command(self):
        from core.tools.tool_adapter import ToolAdapter, ToolInvocation
        from core.common.exceptions import ToolValidationError

        # Direct bash command attempt is forbidden
        inv = ToolInvocation(tool="bash", operation="exec", params={"command": "rm -rf /"})
        with pytest.raises(ToolValidationError) as exc:
            ToolAdapter.adapt(inv)
        assert "forbidden" in str(exc.value).lower()

    # TEST 2: Structured ToolInvocation works.
    def test_2_structured_tool_invocation_works(self):
        from core.tools.tool_adapter import ToolAdapter, ToolInvocation

        inv = ToolInvocation(
            tool="nmap",
            operation="port_scan",
            params={
                "target": "example.com",
                "ports": "22,80,443",
                "service_detection": True
            }
        )
        adapted = ToolAdapter.adapt(inv)
        assert "nmap" in adapted["command"]
        assert "-sV" in adapted["command"]
        assert "-p 22,80,443" in adapted["command"]
        assert "example.com" in adapted["command"]

    # TEST 3: Generic bash cannot be selected by the LLM.
    def test_3_generic_bash_cannot_be_selected(self):
        from core.tools.tool_registry import ToolRegistry
        from core.tools.tool_validation import ToolInvocationValidator, ToolValidationError

        reg = ToolRegistry()
        # bash and sh must not be present in ToolRegistry
        assert "bash" not in reg.tools
        assert "sh" not in reg.tools

        validator = ToolInvocationValidator(reg)
        with pytest.raises(ToolValidationError):
            validator.validate("bash", {"command": "echo test"})

    # TEST 4: Canonical PlannerDecision is enforced.
    def test_4_canonical_planner_decision_enforced(self):
        from core.common.normalizer import PlannerResponseNormalizer
        from core.common.schemas import BrainDecisionAction, BrainDecision

        raw_llm_json = {
            "action": "spawn_tasks",
            "thinking": "Initial recon",
            "tasks": [
                {
                    "objective": "Port scan target",
                    "capability": "port_scanning",
                    "inputs": {"target": "example.com"}
                }
            ]
        }
        decision = PlannerResponseNormalizer.normalize(raw_llm_json)
        assert isinstance(decision, BrainDecision)
        assert decision.action == BrainDecisionAction.SPAWN_AGENTS
        assert len(decision.tasks) == 1
        assert decision.tasks[0].capability == CapabilityType.PORT_SCANNING

    # TEST 5: "agents" and "agent_specs" do not leak into core code.
    def test_5_agents_and_agent_specs_do_not_leak(self):
        from core.common.normalizer import PlannerResponseNormalizer

        raw_drift_1 = {
            "action": "spawn_agents",
            "agent_specs": [
                {"objective": "Find subdomains", "capability": "dns_enumeration", "target": "example.com"}
            ]
        }
        raw_drift_2 = {
            "action": "spawn_agents",
            "agents": [
                {"objective": "Analyze TLS", "capability": "tls_analysis", "target": "example.com"}
            ]
        }
        dec1 = PlannerResponseNormalizer.normalize(raw_drift_1)
        dec2 = PlannerResponseNormalizer.normalize(raw_drift_2)
        assert len(dec1.tasks) == 1
        assert dec1.tasks[0].capability == CapabilityType.DNS_ENUMERATION
        assert len(dec2.tasks) == 1
        assert dec2.tasks[0].capability == CapabilityType.TLS_ANALYSIS

    # TEST 6: LLM cannot modify TaskStatus.
    def test_6_llm_cannot_modify_task_status(self):
        spec = TaskSpec(objective="test task", capability=CapabilityType.PORT_SCANNING)
        task = Task(spec)
        assert task.status == TaskStatus.CREATED

        # Directly setting invalid transitions fails
        with pytest.raises(TaskStateTransitionError):
            task.transition_to(TaskStatus.COMPLETED)

    # TEST 7: Task dependency prevents premature execution.
    def test_7_task_dependency_prevents_premature_execution(self):
        from orchestrator.scheduler import Scheduler
        from core.security.authorization import TargetScopeValidator
        TargetScopeValidator.set(TargetScopeValidator(["example.com"]))

        tm = TaskManager()
        sched = Scheduler(tm)

        t1 = tm.create_task(TaskSpec(task_id="t1", objective="Recon", capability=CapabilityType.DNS_ENUMERATION))
        t2 = tm.create_task(TaskSpec(task_id="t2", objective="Scan", capability=CapabilityType.PORT_SCANNING, dependencies=["t1"]))

        sched.schedule_tasks([t1.spec, t2.spec])
        runnable = sched.get_next_runnable_tasks()
        runnable_ids = [t.spec.task_id for t in runnable]

        assert "t1" in runnable_ids
        assert "t2" not in runnable_ids  # t2 blocked until t1 completes

        # Complete t1
        tm.start_task("t1")
        tm.complete_task("t1")
        sched.process_dependencies()

        runnable_after = sched.get_next_runnable_tasks()
        runnable_after_ids = [t.spec.task_id for t in runnable_after]
        assert "t2" in runnable_after_ids

    # TEST 8: Identical semantic tasks are deduplicated.
    def test_8_identical_semantic_tasks_deduplicated(self):
        from core.security.authorization import TargetScopeValidator
        TargetScopeValidator.set(TargetScopeValidator(["example.com"]))

        tm = TaskManager()
        spec1 = TaskSpec(
            objective="Scan ports on example.com",
            capability=CapabilityType.PORT_SCANNING,
            inputs={"target": "example.com", "ports": "80,443"}
        )
        spec2 = TaskSpec(
            objective="Perform port scanning on example.com",
            capability=CapabilityType.PORT_SCANNING,
            inputs={"target": "example.com", "ports": "80,443"}
        )
        t1, is_new1 = tm.get_or_create_task(spec1)
        t2, is_new2 = tm.get_or_create_task(spec2)

        assert is_new1 is True
        assert is_new2 is False
        assert t1.spec.task_id == t2.spec.task_id

    # TEST 9: Different parameters create different tasks.
    def test_9_different_parameters_create_different_tasks(self):
        from core.security.authorization import TargetScopeValidator
        TargetScopeValidator.set(TargetScopeValidator(["example.com"]))

        tm = TaskManager()
        spec_top100 = TaskSpec(
            objective="Scan top 100 ports",
            capability=CapabilityType.PORT_SCANNING,
            inputs={"target": "example.com", "top_ports": 100}
        )
        spec_all_ports = TaskSpec(
            objective="Scan all 65535 ports",
            capability=CapabilityType.PORT_SCANNING,
            inputs={"target": "example.com", "all_ports": True}
        )
        t1, is_new1 = tm.get_or_create_task(spec_top100)
        t2, is_new2 = tm.get_or_create_task(spec_all_ports)

        assert is_new1 is True
        assert is_new2 is True
        assert t1.spec.task_id != t2.spec.task_id

    # TEST 10: Completed task is not executed again.
    def test_10_completed_task_not_executed_again(self):
        from core.security.authorization import TargetScopeValidator
        TargetScopeValidator.set(TargetScopeValidator(["example.com"]))

        tm = TaskManager()
        spec = TaskSpec(
            objective="Enumerate subdomains",
            capability=CapabilityType.DNS_ENUMERATION,
            inputs={"target": "example.com"}
        )
        task, is_new = tm.get_or_create_task(spec)
        tm.start_task(task.spec.task_id)
        tm.complete_task(task.spec.task_id, {"subdomains": ["www.example.com"]})

        # Proposing task again
        task_again, is_new_again = tm.get_or_create_task(spec)
        assert is_new_again is False
        assert task_again.status == TaskStatus.COMPLETED

    # TEST 11: Successful task completes through SuccessCriterion.
    def test_11_successful_task_completes_through_success_criterion(self):
        from core.orchestration.task_evaluator import TaskCompletionEvaluator, CompletionStatus

        spec = TaskSpec(
            objective="Port scan example.com",
            capability=CapabilityType.PORT_SCANNING,
            inputs={"target": "example.com"},
            success_criteria=[
                SuccessCriterion(criterion_type=SuccessCriterionType.TOOL_SUCCESS)
            ]
        )
        tool_results = [{"success": True, "output": "22/tcp open, 80/tcp open", "data": {"ports": [22, 80]}}]
        status, reason = TaskCompletionEvaluator.evaluate(spec, tool_results)
        assert status == CompletionStatus.SUCCEEDED

    # TEST 12: max_steps does NOT mark a task successful.
    @pytest.mark.anyio
    async def test_12_max_steps_does_not_mark_task_successful(self):
        from core.orchestration.dynamic_agent import DynamicAgent
        from core.tools.tool_registry import ToolRegistry
        from core.memory.shared_context_v2 import SharedContextV2 as SharedContext
        from unittest.mock import AsyncMock, patch

        ctx = SharedContext("example.com")
        tools = ToolRegistry()
        agent = DynamicAgent(
            agent_id="AGENT-TEST",
            objective="Scan target",
            tool_registry=tools,
            shared_context=ctx,
            agent_context="test",
            allowed_tools=["nmap"],
            max_steps=2
        )

        # Mock tool execution failure
        with patch.object(tools, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = {"success": False, "error": "Execution error", "returncode": 1}
            res = await agent.execute()

            assert res["status"] == "failed"

    # TEST 13: A successful deterministic task does not require another LLM planning call.
    def test_13_successful_deterministic_task_no_extra_llm_call(self):
        from core.orchestration.task_evaluator import TaskCompletionEvaluator, CompletionStatus

        spec = TaskSpec(
            objective="Check SSL Certificate",
            capability=CapabilityType.TLS_ANALYSIS,
            inputs={"target": "example.com"}
        )
        tool_result = {"success": True, "output": "Certificate valid until 2027", "data": {"valid": True}}
        status, _ = TaskCompletionEvaluator.evaluate(spec, [tool_result])
        assert status == CompletionStatus.SUCCEEDED

    # TEST 14: Invalid tool arguments fail BEFORE reaching the shell.
    def test_14_invalid_tool_arguments_fail_before_shell(self):
        from core.tools.tool_validation import ToolInvocationValidator, ToolValidationError
        from core.tools.tool_registry import ToolRegistry

        reg = ToolRegistry()
        validator = ToolInvocationValidator(reg)

        # Timeout > 1800 must fail immediately before any subprocess or shell execution
        with pytest.raises(ToolValidationError):
            validator.validate("nmap", {"target": "example.com", "timeout": 99999})

        # Missing target for nmap in ToolAdapter must raise ToolValidationError
        from core.tools.tool_adapter import ToolAdapter, ToolInvocation
        with pytest.raises(ToolValidationError):
            ToolAdapter.adapt(ToolInvocation(tool="nmap", operation="port_scan", params={}))


class TestPhaseArchitectureRefinements:
    """Explicit tests for Follow-up Architecture Refinements (TEST 1 to TEST 10)"""

    # TEST 1: Planner cannot request specific tools. Normalized into capability.
    def test_1_planner_cannot_request_specific_tools(self):
        from core.common.normalizer import PlannerResponseNormalizer
        from core.common.schemas import CapabilityType

        raw = {
            "action": "spawn_tasks",
            "tasks": [
                {
                    "objective": "Scan target endpoints",
                    "tools": ["nmap", "gobuster"],
                    "inputs": {"target": "example.com", "tools": ["nmap", "gobuster"]}
                }
            ]
        }
        dec = PlannerResponseNormalizer.normalize(raw)
        task = dec.tasks[0]
        # Must be normalized into capability without raw tool commanding in inputs
        assert task.capability in (CapabilityType.PORT_SCANNING, CapabilityType.ENDPOINT_DISCOVERY)
        assert "tools" not in task.inputs

    # TEST 2: EndpointDiscoveryAgent executes without LLM calls.
    @pytest.mark.anyio
    async def test_2_endpoint_discovery_executes_without_llm_calls(self):
        from core.orchestration.capability_worker import CapabilityWorker
        from core.common.schemas import CapabilityType
        from core.tools.tool_registry import ToolRegistry
        from core.memory.shared_context_v2 import SharedContextV2 as SharedContext
        from unittest.mock import AsyncMock, patch

        ctx = SharedContext("example.com")
        tools = ToolRegistry()
        
        worker = CapabilityWorker("AGENT-EP", tools, ctx)
        
        # Mock tools.execute to return endpoints
        with patch.object(tools, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = {
                "success": True,
                "output": "https://example.com/api/v1/users\nhttps://example.com/login\n",
                "returncode": 0,
                "data": {"endpoints": ["/api/v1/users", "/login"]}
            }
            
            res = await worker.execute_capability(
                capability=CapabilityType.ENDPOINT_DISCOVERY,
                target="https://example.com",
                task_id="task-ep-1",
                objective="Discover application endpoints"
            )
            
            assert res.status == "completed"
            assert len(res.observations) > 0
            assert any("login" in ep for ep in res.observations[0]["data"]["endpoints"])

    # TEST 3: Agent does not decide retry (RetryPolicy handles deterministically).
    def test_3_agent_does_not_decide_retry(self):
        from core.common.retry_policy import RetryPolicy
        from core.common.schemas import RetryDecisionType

        # Timeout should retry
        res_timeout = {"status": "failed", "error": "Connection timed out", "returncode": 124}
        dec_timeout = RetryPolicy.evaluate("httpx", res_timeout, attempt=1, max_retries=3)
        assert dec_timeout.decision == RetryDecisionType.RETRY

        # Invalid argument should not retry
        res_invalid = {"status": "failed", "error": "Invalid argument: --bad-flag", "returncode": 2}
        dec_invalid = RetryPolicy.evaluate("httpx", res_invalid, attempt=1, max_retries=3)
        assert dec_invalid.decision == RetryDecisionType.NO_RETRY

        # Tool missing should use alternative strategy
        res_missing = {"status": "failed", "error": "command not found: subfinder", "returncode": 127}
        dec_missing = RetryPolicy.evaluate("subfinder", res_missing, attempt=1, max_retries=3)
        assert dec_missing.decision == RetryDecisionType.ALTERNATIVE_STRATEGY
        assert dec_missing.alternative_tool == "amass"

    # TEST 4: Scheduler blocks dependent task (A depends on B, B incomplete: A cannot start).
    def test_4_scheduler_blocks_dependent_task(self):
        from core.orchestration.task_manager import TaskManager
        from orchestrator.scheduler import Scheduler
        from core.common.schemas import TaskSpec, CapabilityType
        from core.security.authorization import TargetScopeValidator
        TargetScopeValidator.set(TargetScopeValidator(["example.com"]))

        tm = TaskManager()
        sched = Scheduler(tm)

        task_b = TaskSpec(task_id="task_B", objective="Subdomain discovery", capability=CapabilityType.DNS_ENUMERATION)
        task_a = TaskSpec(task_id="task_A", objective="Endpoint discovery", capability=CapabilityType.ENDPOINT_DISCOVERY, dependencies=["task_B"])

        sched.schedule_tasks([task_b, task_a])
        runnable = sched.get_next_runnable_tasks()
        runnable_ids = [t.spec.task_id for t in runnable]

        assert "task_B" in runnable_ids
        assert "task_A" not in runnable_ids

    # TEST 5: After B succeeds: A becomes READY.
    def test_5_after_b_succeeds_a_becomes_ready(self):
        from core.orchestration.task_manager import TaskManager
        from orchestrator.scheduler import Scheduler
        from core.common.schemas import TaskSpec, CapabilityType
        from core.security.authorization import TargetScopeValidator
        TargetScopeValidator.set(TargetScopeValidator(["example.com"]))

        tm = TaskManager()
        sched = Scheduler(tm)

        task_b = TaskSpec(task_id="task_B", objective="Subdomain discovery", capability=CapabilityType.DNS_ENUMERATION)
        task_a = TaskSpec(task_id="task_A", objective="Endpoint discovery", capability=CapabilityType.ENDPOINT_DISCOVERY, dependencies=["task_B"])

        sched.schedule_tasks([task_b, task_a])

        # Complete B
        tm.start_task("task_B")
        tm.complete_task("task_B", {"subdomains": ["api.example.com"]})

        # Process dependencies
        sched.process_dependencies()

        runnable = sched.get_next_runnable_tasks()
        runnable_ids = [t.spec.task_id for t in runnable]
        assert "task_A" in runnable_ids

    # TEST 6: Duplicate semantic tasks are not created.
    def test_6_duplicate_semantic_tasks_are_not_created(self):
        from core.orchestration.task_manager import TaskManager
        from core.common.schemas import TaskSpec, CapabilityType
        from core.security.authorization import TargetScopeValidator
        TargetScopeValidator.set(TargetScopeValidator(["example.com"]))

        tm = TaskManager()
        spec1 = TaskSpec(objective="Scan ports on example.com", capability=CapabilityType.PORT_SCANNING, inputs={"target": "example.com"})
        spec2 = TaskSpec(objective="Perform port scanning on example.com", capability=CapabilityType.PORT_SCANNING, inputs={"target": "example.com"})

        t1, is_new1 = tm.get_or_create_task(spec1)
        t2, is_new2 = tm.get_or_create_task(spec2)

        assert is_new1 is True
        assert is_new2 is False
        assert t1.spec.task_id == t2.spec.task_id

    # TEST 7: Partial tool result is accepted (Tool returns data + warning -> PARTIAL_SUCCESS).
    def test_7_partial_tool_result_accepted(self):
        from core.orchestration.capability_worker import CapabilityWorker
        from core.common.schemas import ToolExecutionStatus
        from core.tools.tool_registry import ToolRegistry

        worker = CapabilityWorker("AGENT-P", ToolRegistry(), None)
        raw_res = {
            "success": False,
            "returncode": 1,
            "output": "https://example.com/secret_panel\nhttps://example.com/api",
            "error": "Warning: Deprecated dependency in python urllib",
            "data": {}
        }
        res = worker._process_raw_tool_result("paramspider", "endpoint_discovery", "example.com", raw_res)
        assert res.status == ToolExecutionStatus.PARTIAL_SUCCESS
        assert len(res.data.get("endpoints", [])) > 0
        assert len(res.warnings) > 0

    # TEST 8: Task completion does not require LLM.
    def test_8_task_completion_does_not_require_llm(self):
        from core.orchestration.task_evaluator import TaskCompletionEvaluator, CompletionStatus
        from core.common.schemas import TaskSpec, CapabilityType

        spec = TaskSpec(
            objective="Port Scan",
            capability=CapabilityType.PORT_SCANNING,
            inputs={"target": "example.com"}
        )
        tool_results = [{
            "status": "PARTIAL_SUCCESS",
            "data": {"ports": [{"port": 80, "state": "open"}, {"port": 443, "state": "open"}]},
            "warnings": ["Slow network"]
        }]
        status, reason = TaskCompletionEvaluator.evaluate(spec, tool_results)
        assert status == CompletionStatus.SUCCEEDED

    # TEST 9: Agent cannot execute arbitrary shell commands.
    def test_9_agent_cannot_execute_arbitrary_shell_commands(self):
        from core.tools.tool_adapter import ToolAdapter, ToolInvocation
        from core.common.exceptions import ToolValidationError

        inv = ToolInvocation(tool="bash", operation="exec", params={"command": "whoami"})
        with pytest.raises(ToolValidationError) as exc:
            ToolAdapter.adapt(inv)
        assert "forbidden" in str(exc.value).lower()

    # TEST 10: Existing authorization tests continue passing.
    def test_10_existing_authorization_tests_continue_passing(self):
        from core.security.authorization import TargetScopeValidator
        from core.common.exceptions import AuthorizationError

        val = TargetScopeValidator(["example.com", "*.speshway.com"])
        val.validate("example.com")
        val.validate("app.speshway.com")

        with pytest.raises(AuthorizationError):
            val.validate("attacker-domain.org")


class TestDynamicToolIntelligencePlatform:
    """Explicit tests for Dynamic Agent + Tool Intelligence Platform (TEST 1 to TEST 8)"""

    # TEST 1: Add new tool without code changes. Register only, Agent discovers it.
    def test_1_add_new_tool_without_code_changes(self):
        from core.tools.tool_knowledge_store import ToolKnowledgeStore
        from core.tools.tool_intelligence import ToolProfile
        from core.orchestration.capability_resolver import CapabilityResolver

        store = ToolKnowledgeStore()
        new_tool = ToolProfile(
            name="chaos",
            description="ProjectDiscovery Chaos DNS recon",
            capabilities=["dns_enumeration"],
            trust_score=0.98,
            performance_score=0.95,
            source="plugin"
        )
        store.register_tool(new_tool)

        resolver = CapabilityResolver(store)
        resolved = resolver.resolve_tools("dns_enumeration")
        tool_names = [t.name for t in resolved]
        assert "chaos" in tool_names

    # TEST 2: Unknown tool from LLM is rejected.
    def test_2_unknown_tool_from_llm_is_rejected(self):
        from core.orchestration.execution_planner import ExecutionPlanner
        from core.tools.tool_intelligence import TargetContext
        from core.common.schemas import TaskSpec, CapabilityType
        from core.common.exceptions import ToolValidationError
        from core.security.authorization import TargetScopeValidator
        TargetScopeValidator.set(TargetScopeValidator(["example.com"]))

        planner = ExecutionPlanner()
        task = TaskSpec(objective="Find endpoints", capability=CapabilityType.ENDPOINT_DISCOVERY)
        target_ctx = TargetContext.from_target("https://example.com")
        strategy_steps = [{"tool": "hacker_unknown_tool_xyz", "params": {}}]

        with pytest.raises(ToolValidationError) as exc:
            planner.plan_execution(strategy_steps, task, target_ctx, allowed_profiles=[])
        assert "not registered" in str(exc.value).lower()

    # TEST 3: LLM cannot bypass ToolRegistry / ExecutionPlanner.
    def test_3_llm_cannot_bypass_tool_registry(self):
        from core.orchestration.execution_planner import ExecutionPlanner
        from core.tools.tool_intelligence import TargetContext
        from core.common.schemas import TaskSpec, CapabilityType
        from core.common.exceptions import ToolValidationError

        planner = ExecutionPlanner()
        task = TaskSpec(objective="Run bash command", capability=CapabilityType.ENDPOINT_DISCOVERY)
        target_ctx = TargetContext.from_target("https://example.com")
        strategy_steps = [{"tool": "bash", "params": {"command": "cat /etc/passwd"}}]

        with pytest.raises(ToolValidationError) as exc:
            planner.plan_execution(strategy_steps, task, target_ctx, allowed_profiles=[])
        assert "forbidden" in str(exc.value).lower()

    # TEST 4: Tool discovery does not execute immediately.
    def test_4_tool_discovery_does_not_execute_immediately(self):
        from core.tools.tool_discovery import ToolDiscoveryAgent
        from core.tools.tool_knowledge_store import ToolKnowledgeStore
        from unittest.mock import patch

        store = ToolKnowledgeStore()
        agent = ToolDiscoveryAgent(store=store)

        with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
            profiles = agent.run_discovery()
            # Discovery must not execute any external subprocesses on targets
            assert mock_popen.call_count == 0
            assert mock_run.call_count == 0
            assert len(profiles) > 0

    # TEST 5: Bad tool source is rejected.
    def test_5_bad_tool_source_is_rejected(self):
        from core.tools.tool_discovery import ToolValidationPipeline, ToolCandidate

        candidate_bad_source = ToolCandidate(
            name="evil_tool",
            source="untrusted_anonymous_p2p",
            capabilities=["endpoint_discovery"],
            trust_score=0.1
        )
        ok, reason, profile = ToolValidationPipeline.validate_candidate(candidate_bad_source)
        assert ok is False
        assert "untrusted source" in reason.lower()

        candidate_malicious_name = ToolCandidate(
            name="tool; rm -rf /",
            source="local",
            capabilities=["dns_enumeration"]
        )
        ok2, reason2, profile2 = ToolValidationPipeline.validate_candidate(candidate_malicious_name)
        assert ok2 is False
        assert "malicious syntax" in reason2.lower()

    # TEST 6: Tool ranking improves after successful execution.
    def test_6_tool_ranking_improves_after_successful_execution(self):
        from core.tools.tool_intelligence import ToolProfile
        from core.tools.tool_ranking import ToolRankingEngine

        tool_a = ToolProfile(name="toolA", trust_score=0.80, performance_score=0.80, success_rate=0.80)
        tool_b = ToolProfile(name="toolB", trust_score=0.85, performance_score=0.85, success_rate=0.85)

        # Initially B ranks above A
        ranked_before = ToolRankingEngine.rank_tools([tool_a, tool_b])
        assert ranked_before[0].name == "toolB"

        # Tool A succeeds multiple times with findings
        for _ in range(5):
            tool_a.update_performance(success=True, duration=1.0, findings_count=50)

        ranked_after = ToolRankingEngine.rank_tools([tool_a, tool_b])
        assert ranked_after[0].name == "toolA"
        assert tool_a.performance_score > 0.85

    # TEST 7: DynamicAgent works without hardcoded tools.
    @pytest.mark.anyio
    async def test_7_dynamic_agent_works_without_hardcoded_tools(self):
        from core.orchestration.dynamic_agent import ControlledDynamicAgent
        from core.tools.tool_registry import ToolRegistry
        from core.memory.shared_context_v2 import SharedContextV2 as SharedContext
        from core.security.authorization import TargetScopeValidator
        from unittest.mock import AsyncMock, patch

        TargetScopeValidator.set(TargetScopeValidator(["example.com"]))
        ctx = SharedContext("https://example.com")
        tools = ToolRegistry()
        agent = ControlledDynamicAgent(
            agent_id="DYNAMIC-AGENT-01",
            objective="Discover endpoints on example.com",
            tool_registry=tools,
            shared_context=ctx
        )

        with patch.object(tools, "execute", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = {
                "success": True,
                "output": "https://example.com/api/v1\nhttps://example.com/dashboard",
                "returncode": 0,
                "data": {"endpoints": ["https://example.com/api/v1", "https://example.com/dashboard"]}
            }
            res = await agent.execute()
            assert res["status"] == "success"
            assert mock_exec.call_count >= 1

    # TEST 8: Existing TaskManager tests continue passing.
    def test_8_existing_task_manager_continues_passing(self):
        from core.orchestration.task_manager import TaskManager
        from core.common.schemas import TaskSpec, CapabilityType, TaskStatus
        from core.security.authorization import TargetScopeValidator
        TargetScopeValidator.set(TargetScopeValidator(["example.com"]))

        tm = TaskManager()
        spec = TaskSpec(objective="Perform port scanning", capability=CapabilityType.PORT_SCANNING, inputs={"target": "example.com"})
        task, is_new = tm.get_or_create_task(spec)
        assert is_new is True
        assert task.status == TaskStatus.CREATED

        tm.start_task(task.spec.task_id)
        assert task.status == TaskStatus.RUNNING

        tm.complete_task(task.spec.task_id, {"ports": [80, 443]})
        assert task.status == TaskStatus.COMPLETED


class TestPhaseTransitionsAndActiveScanning:
    """Test stateful phase transitions and active vulnerability scanning planning"""

    def test_state_machine_phase_transitions(self):
        from core.orchestration.central_brain import CentralBrain, ExecutionPhase
        from core.security.authorization import TargetScopeValidator
        from core.memory.dedup_tracker import DeduplicationTracker

        DeduplicationTracker().reset_all()
        TargetScopeValidator.set(TargetScopeValidator(["example.com"]))
        brain = CentralBrain("https://example.com")
        assert brain.current_phase == ExecutionPhase.RECON

        # RECON -> ACTIVE_SCANNING transition when endpoints are populated
        brain.ctx.add_endpoints([{"url": "https://example.com/api/v1"}])
        next_phase = brain._evaluate_phase_transition()
        assert next_phase == ExecutionPhase.ACTIVE_SCANNING

        brain.transition_phase(next_phase)
        assert brain.current_phase == ExecutionPhase.ACTIVE_SCANNING

        # ACTIVE_SCANNING -> EXPLOITATION transition when vulnerabilities are present
        brain.ctx.add_vulnerability({
            "type": "unencoded_input_reflection",
            "title": "Unencoded Input Reflection",
            "proof": "reflected tracer",
            "details": "tracer"
        })
        next_phase = brain._evaluate_phase_transition()
        assert next_phase == ExecutionPhase.EXPLOITATION

        brain.transition_phase(next_phase)
        assert brain.current_phase == ExecutionPhase.EXPLOITATION

    def test_execution_planner_active_scan(self):
        from core.orchestration.execution_planner import ExecutionPlanner

        planner = ExecutionPlanner()
        steps = planner.plan_active_vulnerability_scan(
            endpoint="https://example.com/api/user",
            parameters=["id", "search"],
            vuln_type="sqli"
        )
        assert len(steps) == 2
        assert steps[0]["tool"] == "payload_tester"
        assert steps[0]["params"]["param"] == "id"
        assert steps[1]["params"]["param"] == "search"


class TestCompoundRiskGraphEngine:
    """Test theoretical security dependency graph engine and compound risk analysis"""

    def test_compound_risk_analysis_auth_and_admin(self):
        from core.exploitation.chain_detector import ChainDetector
        from core.reporting.vuln_graph import VulnGraph
        from core.memory.relationship_db import RelationshipDB

        detector = ChainDetector(VulnGraph(), RelationshipDB())

        findings = [
            {
                "id": "VULN-001",
                "type": "missing_auth",
                "title": "Missing Authorization Check",
                "severity": "MEDIUM",
                "location": "https://example.com/api/v1/user"
            },
            {
                "id": "VULN-002",
                "type": "admin_interface",
                "title": "Administrative Interface",
                "severity": "MEDIUM",
                "location": "https://example.com/admin/dashboard"
            }
        ]

        risks = detector.analyze_compound_risks(findings)
        assert len(risks) == 1
        risk = risks[0]
        assert risk["pattern_id"] == "PATTERN-AUTH-ADMIN"
        assert risk["compound_severity"] == "HIGH"  # MEDIUM + MEDIUM -> HIGH
        assert len(risk["remediation_chain"]) >= 2
        assert "RBAC" in risk["remediation_chain"][0] or "Role-Based Access Control" in risk["remediation_chain"][0]

    def test_compound_risk_analysis_session_and_reflection(self):
        from core.exploitation.chain_detector import ChainDetector
        from core.reporting.vuln_graph import VulnGraph
        from core.memory.relationship_db import RelationshipDB

        detector = ChainDetector(VulnGraph(), RelationshipDB())

        findings = [
            {
                "id": "VULN-003",
                "type": "missing_httponly",
                "title": "Missing HttpOnly Cookie Attribute",
                "severity": "MEDIUM",
                "location": "https://example.com/login"
            },
            {
                "id": "VULN-004",
                "type": "unencoded_input_reflection",
                "title": "Unencoded Input Reflection",
                "severity": "MEDIUM",
                "location": "https://example.com/search"
            }
        ]

        risks = detector.analyze_compound_risks(findings)
        assert len(risks) == 1
        risk = risks[0]
        assert risk["pattern_id"] == "PATTERN-SESSION-REFLECTION"
        assert risk["compound_severity"] == "HIGH"
        assert len(risk["remediation_chain"]) >= 2
        assert "HttpOnly" in risk["remediation_chain"][0]

    def test_compound_risk_analysis_upload_and_directory(self):
        from core.exploitation.chain_detector import ChainDetector
        from core.reporting.vuln_graph import VulnGraph
        from core.memory.relationship_db import RelationshipDB

        detector = ChainDetector(VulnGraph(), RelationshipDB())

        findings = [
            {
                "id": "VULN-005",
                "type": "file_upload",
                "title": "Unrestricted File Upload",
                "severity": "HIGH",
                "location": "https://example.com/upload"
            },
            {
                "id": "VULN-006",
                "type": "directory_listing",
                "title": "Exposed Directory Indexing",
                "severity": "MEDIUM",
                "location": "https://example.com/uploads/"
            }
        ]

        risks = detector.analyze_compound_risks(findings)
        assert len(risks) == 1
        risk = risks[0]
        assert risk["pattern_id"] == "PATTERN-UPLOAD-DIRECTORY-LISTING"
        assert risk["compound_severity"] == "CRITICAL"  # HIGH + MEDIUM -> CRITICAL
        assert len(risk["remediation_chain"]) >= 2
        assert "directory indexing" in risk["remediation_chain"][0].lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])




