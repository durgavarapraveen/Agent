"""
Task state machine and deterministic task management.
Framework owns task lifecycle, not LLM.
"""

import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from core.schemas import TaskSpec, TaskStatus, SuccessCriterion
from core.exceptions import AutonomousPentestException

logger = logging.getLogger(__name__)


class TaskStateTransitionError(AutonomousPentestException):
    """Invalid state transition attempted"""
    pass


class Task:
    """Task wrapper with state machine"""
    
    VALID_TRANSITIONS = {
        TaskStatus.CREATED: [TaskStatus.QUEUED, TaskStatus.RUNNING, TaskStatus.WAITING_DEPENDENCY, TaskStatus.BLOCKED],
        TaskStatus.QUEUED: [TaskStatus.RUNNING, TaskStatus.WAITING_DEPENDENCY, TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.BLOCKED, TaskStatus.CANCELLED],
        TaskStatus.WAITING_DEPENDENCY: [TaskStatus.QUEUED, TaskStatus.RUNNING, TaskStatus.BLOCKED, TaskStatus.CANCELLED],
        TaskStatus.RUNNING: [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.TIMEOUT, TaskStatus.CANCELLED],
        TaskStatus.COMPLETED: [],
        TaskStatus.FAILED: [TaskStatus.QUEUED],  # For explicit deterministic retries
        TaskStatus.BLOCKED: [TaskStatus.CANCELLED, TaskStatus.QUEUED],
        TaskStatus.CANCELLED: [],
        TaskStatus.TIMEOUT: [TaskStatus.QUEUED],
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
        self.max_retries = spec.max_retries or 3
        
    def transition_to(self, new_status: TaskStatus) -> bool:
        """Deterministic state transition"""
        if new_status == self.status:
            return True

        if new_status not in self.VALID_TRANSITIONS.get(self.status, []):
            raise TaskStateTransitionError(
                f"Cannot transition task '{self.spec.task_id}' from {self.status.value} to {new_status.value}"
            )
        
        old_status = self.status
        self.status = new_status
        
        if new_status == TaskStatus.RUNNING:
            self.started_at = datetime.now()
            logger.info(f"TASK_STARTED: task_id={self.spec.task_id} capability={self.spec.capability.value}")
        elif new_status == TaskStatus.COMPLETED:
            self.completed_at = datetime.now()
            logger.info(f"TASK_SUCCEEDED: task_id={self.spec.task_id}")
        elif new_status == TaskStatus.FAILED:
            self.completed_at = datetime.now()
            logger.warning(f"TASK_FAILED: task_id={self.spec.task_id} error={self.error}")
        elif new_status == TaskStatus.BLOCKED:
            logger.warning(f"TASK_BLOCKED: task_id={self.spec.task_id} reason={self.error}")
        elif new_status == TaskStatus.WAITING_DEPENDENCY:
            logger.info(f"TASK_WAITING_DEPENDENCY: task_id={self.spec.task_id} waiting on={self.spec.dependencies}")
        elif new_status == TaskStatus.QUEUED:
            logger.info(f"TASK_READY: task_id={self.spec.task_id}")
        
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
    """Centralized task lifecycle and deduplication management"""
    
    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self.task_signatures: Dict[str, str] = {}  # signature -> task_id
        
    def create_task(self, spec: TaskSpec) -> Task:
        """Create new task"""
        import uuid
        if not spec.task_id:
            spec.task_id = str(uuid.uuid4())

        # Validate scope targets at task creation time
        from core.authorization import TargetScopeValidator
        target = spec.inputs.get("target") or spec.inputs.get("url") or spec.inputs.get("domain") or spec.inputs.get("host")
        if target:
            TargetScopeValidator.get().validate(target)
            
        task = Task(spec)
        self.tasks[spec.task_id] = task
        logger.info(f"TASK_CREATED: task_id={spec.task_id} capability={spec.capability.value} objective={spec.objective}")
        return task
    
    def get_or_create_task(self, spec: TaskSpec) -> Tuple[Task, bool]:
        """
        Deduplicates task creation by matching normalized task fingerprints.
        Returns (task, is_new)

        force_reexecute=True on the spec bypasses deduplication entirely and
        always creates a new task (useful for explicit retries / re-scan).
        """
        # Honour explicit re-execution flag — skip dedup entirely.
        if getattr(spec, 'force_reexecute', False):
            task = self.create_task(spec)
            self.register_task_signature(spec, spec.task_id)
            logger.info(f"TASK_FORCE_REEXECUTE: created fresh task={spec.task_id} capability={spec.capability.value}")
            return task, True

        duplicate = self.find_duplicate_task(spec)
        if duplicate:
            # If task is already RUNNING, COMPLETED, or BLOCKED, reuse it
            target = str(spec.inputs.get("target") or spec.inputs.get("url") or spec.inputs.get("domain") or spec.inputs.get("host") or spec.objective or "").strip()
            logger.info(f"TASK_DEDUPLICATED: Reusing existing task={duplicate.spec.task_id} (status={duplicate.status.value}) for proposed capability={spec.capability.value} target='{target}'")
            return duplicate, False
            
        task = self.create_task(spec)
        self.register_task_signature(spec, spec.task_id)
        return task, True

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
        """Generate deterministic signature based on normalized capability, target, parameters, and tools.
        
        Signature formula: hash(capability + target_url_or_ip + parameters + dynamic_tools)
        This ensures that tasks on subdomains or distinct targets (e.g. sub.speshway.com vs speshway.com)
        are NOT incorrectly deduplicated.
        """
        import re
        import hashlib
        
        # Extract and normalize target from inputs or objective
        target = spec.inputs.get("target") or spec.inputs.get("url") or spec.inputs.get("domain") or spec.inputs.get("host")
        if isinstance(target, list) and target:
            target = str(target[0])
            
        if not target:
            # Fallback: extract domain/host/URL from spec.objective via regex
            urls = re.findall(r'https?://[^\s/]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', spec.objective)
            if urls:
                target = urls[0]
            else:
                target = spec.objective  # Ensure distinct objectives don't share empty target

        if isinstance(target, str):
            target = target.strip().lower()
            if "://" in target:
                target = target.split("://", 1)[1]
            if "/" in target:
                target = target.split("/", 1)[0]
        else:
            target = str(target)

        # Normalize inputs & parameters
        norm_inputs = {}
        for k, v in spec.inputs.items():
            if k not in ("target", "url", "domain", "host", "task_id", "timestamp"):
                norm_inputs[k] = v

        inputs_str = json.dumps(norm_inputs, sort_keys=True)
        tools_str = ",".join(sorted(spec.inputs.get("tools", [])))
        
        sig_parts = [
            spec.capability.value,
            target,
            inputs_str,
            tools_str,
        ]
        sig_str = "|".join(sig_parts)
        return hashlib.sha256(sig_str.encode()).hexdigest()[:16]
    
    def find_duplicate_task(self, spec: TaskSpec) -> Optional[Task]:
        """Check if equivalent task exists"""
        sig = self.generate_task_signature(spec)
        if sig in self.task_signatures:
            existing_id = self.task_signatures[sig]
            existing_task = self.tasks.get(existing_id)
            if existing_task:
                return existing_task
        return None
    
    def register_task_signature(self, spec: TaskSpec, task_id: str) -> None:
        """Register task signature for deduplication"""
        sig = self.generate_task_signature(spec)
        self.task_signatures[sig] = task_id
    
    def should_create_task(self, spec: TaskSpec) -> Tuple[bool, Optional[str]]:
        """Determine if task should be created"""
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
                if dep_task.status in (TaskStatus.FAILED, TaskStatus.BLOCKED, TaskStatus.CANCELLED):
                    return True
        return False
    
    def to_dict(self) -> Dict:
        """Serialize all tasks"""
        return {
            task_id: task.to_dict()
            for task_id, task in self.tasks.items()
        }