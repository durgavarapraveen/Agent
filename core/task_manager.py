"""
Task state machine and deterministic task management.
Framework owns task lifecycle, not LLM.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Set
from core.schemas import TaskSpec, TaskStatus, SuccessCriterion

logger = logging.getLogger(__name__)


class TaskStateTransitionError(Exception):
    """Invalid state transition attempted"""
    pass


class Task:
    """Task wrapper with state machine"""
    
    VALID_TRANSITIONS = {
        TaskStatus.CREATED: [TaskStatus.QUEUED, TaskStatus.WAITING_DEPENDENCY],
        TaskStatus.QUEUED: [TaskStatus.RUNNING, TaskStatus.WAITING_DEPENDENCY, TaskStatus.COMPLETED, TaskStatus.FAILED],
        TaskStatus.WAITING_DEPENDENCY: [TaskStatus.QUEUED, TaskStatus.RUNNING, TaskStatus.BLOCKED],
        TaskStatus.RUNNING: [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.TIMEOUT],
        TaskStatus.COMPLETED: [],
        TaskStatus.FAILED: [],
        TaskStatus.BLOCKED: [TaskStatus.CANCELLED],
        TaskStatus.CANCELLED: [],
        TaskStatus.TIMEOUT: [],
    }
    
    def __init__(self, spec: TaskSpec):
        self.spec = spec
        self.status = TaskStatus.CREATED
        self.created_at = datetime.now()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error: Optional[str] = None
        self.result: Optional[Dict] = None
        self.retry_count = 0
        self.max_retries = 3
        
    def transition_to(self, new_status: TaskStatus) -> bool:
        """Deterministic state transition"""
        if new_status not in self.VALID_TRANSITIONS.get(self.status, []):
            raise TaskStateTransitionError(
                f"Cannot transition from {self.status.value} to {new_status.value}"
            )
        
        old_status = self.status
        self.status = new_status
        
        if new_status == TaskStatus.RUNNING:
            self.started_at = datetime.now()
        elif new_status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.TIMEOUT]:
            self.completed_at = datetime.now()
        
        logger.info(f"[Task {self.spec.task_id}] {old_status.value} -> {new_status.value}")
        return True
    
    def is_completed(self) -> bool:
        return self.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.TIMEOUT, TaskStatus.CANCELLED]
    
    def is_running(self) -> bool:
        return self.status == TaskStatus.RUNNING
    
    def is_waiting_dependency(self) -> bool:
        return self.status == TaskStatus.WAITING_DEPENDENCY
    
    def to_dict(self) -> Dict:
        return {
            "task_id": self.spec.task_id,
            "objective": self.spec.objective,
            "capability": self.spec.capability.value,
            "status": self.status.value,
            "dependencies": self.spec.dependencies,
            "success_criteria": [c.dict() for c in self.spec.success_criteria],
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "retry_count": self.retry_count,
            "error": self.error,
        }


class TaskManager:
    """Centralized task lifecycle management"""
    
    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self.task_signatures: Dict[str, str] = {}  # signature -> task_id
        
    def create_task(self, spec: TaskSpec) -> Task:
        """Create new task"""
        task = Task(spec)
        self.tasks[spec.task_id] = task
        logger.info(f"[TaskManager] Created task {spec.task_id}: {spec.objective}")
        return task
    
    def queue_task(self, task_id: str) -> Task:
        """Queue task for execution"""
        task = self.get_task(task_id)
        task.transition_to(TaskStatus.QUEUED)
        return task
    
    def start_task(self, task_id: str) -> Task:
        """Mark task as running"""
        task = self.get_task(task_id)
        task.transition_to(TaskStatus.RUNNING)
        return task
    
    def complete_task(self, task_id: str, result: Dict = None) -> Task:
        """Mark task as completed"""
        task = self.get_task(task_id)
        task.transition_to(TaskStatus.COMPLETED)
        if result:
            task.result = result
        return task
    
    def fail_task(self, task_id: str, error: str = "") -> Task:
        """Mark task as failed"""
        task = self.get_task(task_id)
        task.error = error
        task.transition_to(TaskStatus.FAILED)
        return task
    
    def timeout_task(self, task_id: str) -> Task:
        """Mark task as timed out"""
        task = self.get_task(task_id)
        task.transition_to(TaskStatus.TIMEOUT)
        return task
    
    def block_task(self, task_id: str, reason: str = "") -> Task:
        """Mark task as blocked"""
        task = self.get_task(task_id)
        task.error = reason
        task.transition_to(TaskStatus.BLOCKED)
        return task
    
    def wait_on_dependency(self, task_id: str) -> Task:
        """Mark task as waiting on dependency"""
        task = self.get_task(task_id)
        task.transition_to(TaskStatus.WAITING_DEPENDENCY)
        return task
    
    def get_task(self, task_id: str) -> Task:
        """Retrieve task by ID"""
        if task_id not in self.tasks:
            raise KeyError(f"Task {task_id} not found")
        return self.tasks[task_id]
    
    def get_all_tasks(self) -> List[Task]:
        """Get all tasks"""
        return list(self.tasks.values())
    
    def get_tasks_by_status(self, status: TaskStatus) -> List[Task]:
        """Get tasks filtered by status"""
        return [t for t in self.tasks.values() if t.status == status]
    
    def generate_task_signature(self, spec: TaskSpec) -> str:
        """Generate deterministic signature for deduplication"""
        import hashlib
        sig_parts = [
            spec.capability.value,
            spec.objective,
            str(sorted(spec.inputs.items())),
        ]
        sig_str = "|".join(sig_parts)
        return hashlib.sha256(sig_str.encode()).hexdigest()[:16]
    
    def find_duplicate_task(self, spec: TaskSpec) -> Optional[Task]:
        """
        Check if equivalent task exists (completed or running).
        Returns None if no duplicate, otherwise returns the existing task.
        """
        sig = self.generate_task_signature(spec)
        
        if sig in self.task_signatures:
            existing_id = self.task_signatures[sig]
            existing_task = self.tasks.get(existing_id)
            if existing_task and not existing_task.is_completed():
                logger.info(f"[TaskManager] Found running equivalent: {existing_id}")
                return existing_task
            if existing_task and existing_task.status == TaskStatus.COMPLETED:
                logger.info(f"[TaskManager] Found completed equivalent: {existing_id}")
                return existing_task
        
        return None
    
    def register_task_signature(self, spec: TaskSpec, task_id: str) -> None:
        """Register task signature for deduplication"""
        sig = self.generate_task_signature(spec)
        self.task_signatures[sig] = task_id
    
    def should_create_task(self, spec: TaskSpec) -> tuple[bool, Optional[str]]:
        """
        Determine if task should be created.
        Returns (should_create, reason_if_no)
        """
        duplicate = self.find_duplicate_task(spec)
        if duplicate:
            return (False, f"Duplicate of task {duplicate.spec.task_id}")
        return (True, None)
    
    def get_dependency_graph(self) -> Dict[str, List[str]]:
        """Build dependency graph for all tasks"""
        graph = {}
        for task in self.tasks.values():
            graph[task.spec.task_id] = task.spec.dependencies
        return graph
    
    def get_blocked_by(self, task_id: str) -> List[str]:
        """Get IDs of tasks that wait for this task"""
        task = self.get_task(task_id)
        return [
            t.spec.task_id for t in self.tasks.values()
            if task_id in t.spec.dependencies
        ]
    
    def check_dependencies_satisfied(self, task_id: str) -> bool:
        """Check if all dependencies of task are completed"""
        task = self.get_task(task_id)
        for dep_id in task.spec.dependencies:
            if dep_id not in self.tasks:
                logger.warning(f"Dependency {dep_id} not found for {task_id}")
                return False
            dep_task = self.tasks[dep_id]
            if dep_task.status != TaskStatus.COMPLETED:
                return False
        return True
    
    def check_dependencies_failed(self, task_id: str) -> bool:
        """Check if any dependency failed"""
        task = self.get_task(task_id)
        for dep_id in task.spec.dependencies:
            if dep_id in self.tasks:
                dep_task = self.tasks[dep_id]
                if dep_task.status == TaskStatus.FAILED:
                    return True
        return False
    
    def to_dict(self) -> Dict:
        """Serialize all tasks"""
        return {
            task_id: task.to_dict()
            for task_id, task in self.tasks.items()
        }