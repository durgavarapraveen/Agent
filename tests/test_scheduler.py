import pytest
from core.common.schemas import TaskSpec, CapabilityType, TaskStatus
from core.orchestration.task_manager import TaskManager
from orchestrator.scheduler import Scheduler

@pytest.fixture
def task_manager():
    return TaskManager()

@pytest.fixture
def scheduler(task_manager):
    return Scheduler(task_manager)

class TestTaskScheduler:
    def test_schedule_single_task(self, scheduler, task_manager):
        spec = TaskSpec(
            objective="Scan ports",
            capability=CapabilityType.PORT_SCANNING,
            inputs={"target": "example.com"}
        )
        tasks = scheduler.schedule_tasks([spec])
        assert len(tasks) == 1
        assert spec.task_id in tasks
        assert tasks[spec.task_id].status == TaskStatus.QUEUED

    def test_schedule_batch_tasks(self, scheduler, task_manager):
        specs = [
            TaskSpec(
                objective=f"Scan port {i}",
                capability=CapabilityType.PORT_SCANNING,
                inputs={"port": i}
            )
            for i in range(5)
        ]
        tasks = scheduler.schedule_tasks(specs)
        assert len(tasks) == 5
        queued = task_manager.get_tasks_by_status(TaskStatus.QUEUED)
        assert len(queued) == 5

    def test_task_dependency_ordering(self, scheduler, task_manager):
        spec1 = TaskSpec(
            objective="DNS enum",
            capability=CapabilityType.DNS_ENUMERATION,
            inputs={"domain": "example.com"}
        )
        spec2 = TaskSpec(
            objective="Port scan",
            capability=CapabilityType.PORT_SCANNING,
            inputs={"target": "example.com"},
            dependencies=[spec1.task_id]
        )
        
        tasks = scheduler.schedule_tasks([spec1, spec2])
        assert tasks[spec1.task_id].status == TaskStatus.QUEUED
        assert tasks[spec2.task_id].status == TaskStatus.WAITING_DEPENDENCY

    def test_process_dependencies_unblocks_task(self, scheduler, task_manager):
        spec1 = TaskSpec(
            objective="DNS enum",
            capability=CapabilityType.DNS_ENUMERATION,
            inputs={"domain": "example.com"}
        )
        spec2 = TaskSpec(
            objective="Port scan",
            capability=CapabilityType.PORT_SCANNING,
            inputs={"target": "example.com"},
            dependencies=[spec1.task_id]
        )
        
        tasks = scheduler.schedule_tasks([spec1, spec2])
        task1 = tasks[spec1.task_id]
        task2 = tasks[spec2.task_id]

        # Simulate completion of task 1
        task_manager.start_task(task1.spec.task_id)
        task_manager.complete_task(task1.spec.task_id, {"status": "success"})

        # Process dependencies
        scheduler.process_dependencies()

        assert task2.status == TaskStatus.QUEUED

    def test_different_targets_not_deduplicated(self, scheduler, task_manager):
        from core.security.authorization import TargetScopeValidator
        TargetScopeValidator.set(TargetScopeValidator(["example.com", "sub.example.com"]))
        
        spec1 = TaskSpec(
            objective="Analyze SSL/TLS configuration for https://example.com",
            capability=CapabilityType.TLS_ANALYSIS,
            inputs={"target": "example.com"}
        )
        spec2 = TaskSpec(
            objective="Analyze SSL/TLS configuration for https://sub.example.com",
            capability=CapabilityType.TLS_ANALYSIS,
            inputs={"target": "sub.example.com"}
        )
        
        task1, is_new1 = task_manager.get_or_create_task(spec1)
        task_manager.queue_task(task1.spec.task_id)
        task_manager.start_task(task1.spec.task_id)
        task_manager.complete_task(task1.spec.task_id, {"status": "success"})

        task2, is_new2 = task_manager.get_or_create_task(spec2)
        assert is_new2 is True
        assert task1.spec.task_id != task2.spec.task_id


