"""
Dependency-aware task scheduler.
Deterministic scheduling logic owned by framework, not LLM.
"""

import logging
from typing import Dict, List
from core.common.schemas import TaskStatus, TaskSpec
from core.orchestration.task_manager import TaskManager, Task

logger = logging.getLogger(__name__)


class Scheduler:
    """Deterministic task scheduler with dependency awareness"""
    
    def __init__(self, task_manager: TaskManager):
        self.task_manager = task_manager
        self.execution_order: List[str] = []  # task_id order
        self.parallel_groups: List[List[str]] = []  # Groups of parallel-executable tasks


    def detect_circular_dependencies(self, proposed_specs: List[TaskSpec]) -> bool:
        """Helper to detect cycles in the task dependency DAG using DFS"""
        graph = {}
        for task in self.task_manager.tasks.values():
            graph[task.spec.task_id] = list(task.spec.dependencies)
        for spec in proposed_specs:
            graph[spec.task_id] = list(spec.dependencies)
            
        visited = {}  # 0=unvisited, 1=visiting, 2=visited
        
        def dfs(node):
            visited[node] = 1  # visiting
            for neighbor in graph.get(node, []):
                state = visited.get(neighbor, 0)
                if state == 1:
                    return True
                if state == 0:
                    if dfs(neighbor):
                        return True
            visited[node] = 2  # visited
            return False
            
        for node in graph:
            if visited.get(node, 0) == 0:
                if dfs(node):
                    return True
        return False

    def schedule_tasks(self, task_specs: List[TaskSpec]) -> Dict[str, Task]:
        """
        Create and schedule multiple tasks.
        Independent tasks run in parallel.
        Dependent tasks queue and wait.
        """
        # Validate dependency IDs
        proposed_ids = {spec.task_id for spec in task_specs}
        for spec in task_specs:
            for dep_id in spec.dependencies:
                if dep_id not in self.task_manager.tasks and dep_id not in proposed_ids:
                    logger.error(f"[Scheduler] DEPENDENCY_FAILURE: Dependency {dep_id} not found for {spec.task_id}")
                    raise ValueError(f"Dependency {dep_id} not found in existing tasks or proposed batch")

        # Detect circular dependencies
        if self.detect_circular_dependencies(task_specs):
            logger.error("[Scheduler] DEPENDENCY_FAILURE: Circular dependency detected in scheduling request")
            raise ValueError("Circular dependency detected")

        created_tasks = {}
        
        for spec in task_specs:
            # Check for duplicates and reuse or create
            task, is_new = self.task_manager.get_or_create_task(spec)
            
            # Queue the task
            if spec.dependencies:
                # Has dependencies - wait
                if task.status == TaskStatus.CREATED:
                    self.task_manager.wait_on_dependency(task.spec.task_id)
            else:
                # No dependencies - ready to run
                if task.status == TaskStatus.CREATED:
                    self.task_manager.queue_task(task.spec.task_id)
            
            created_tasks[spec.task_id] = task
        
        # Build execution plan
        self._build_execution_plan()
        
        return created_tasks
    
    def _build_execution_plan(self) -> None:
        """Build deterministic execution plan respecting dependencies"""
        self.execution_order = []
        self.parallel_groups = []
        
        remaining = set(self.task_manager.tasks.keys())
        completed = set()
        
        while remaining:
            # Find all tasks whose dependencies are all either completed or not in remaining
            ready = []
            for task_id in remaining:
                task = self.task_manager.get_task(task_id)
                # Check if all dependencies are either completed or scheduled before
                deps_satisfied = all(
                    dep_id in completed or dep_id not in self.task_manager.tasks
                    for dep_id in task.spec.dependencies
                )
                if deps_satisfied:
                    ready.append(task_id)
            
            if not ready:
                # Circular dependency or unsatisfied external dependencies
                logger.error(f"[Scheduler] Circular/unsatisfied dependencies: {remaining}")
                break
            
            # Group independent tasks (can run in parallel)
            parallel_group = self._find_independent_group(ready)
            self.parallel_groups.append(parallel_group)
            self.execution_order.extend(parallel_group)
            completed.update(parallel_group)
            remaining -= set(parallel_group)
        
        logger.info(f"[Scheduler] Execution plan: {len(self.parallel_groups)} stages")
    
    def _find_independent_group(self, candidates: List[str]) -> List[str]:
        """Find maximal set of tasks with no interdependencies"""
        if not candidates:
            return []
        
        group = [candidates[0]]
        
        for task_id in candidates[1:]:
            # Check if task_id has dependency on anything in group
            task = self.task_manager.get_task(task_id)
            if not any(dep in group for dep in task.spec.dependencies):
                # Also check if any task in group depends on this task
                if not any(
                    task_id in self.task_manager.get_task(g).spec.dependencies
                    for g in group
                ):
                    group.append(task_id)
        
        return group
    
    def process_dependencies(self) -> None:
        """
        After a task completes, unblock waiting tasks.
        Propagates cascading block/failures.
        """
        updated = True
        while updated:
            updated = False
            for task in self.task_manager.get_tasks_by_status(TaskStatus.WAITING_DEPENDENCY):
                task_id = task.spec.task_id
                
                # Check if all dependencies are completed successfully
                if self.task_manager.check_dependencies_satisfied(task_id):
                    self.task_manager.queue_task(task_id)
                    logger.info(f"[Scheduler] Dependencies satisfied for {task_id}, queuing")
                    updated = True
                
                # Check if any dependency has failed, timed out, or blocked
                elif self.task_manager.check_dependencies_failed(task_id):
                    # Check failure state of dependencies
                    failed_deps = []
                    for dep_id in task.spec.dependencies:
                        if dep_id in self.task_manager.tasks:
                            dep = self.task_manager.get_task(dep_id)
                            if dep.status in (TaskStatus.FAILED, TaskStatus.TIMEOUT, TaskStatus.CANCELLED, TaskStatus.BLOCKED):
                                failed_deps.append(f"{dep_id} ({dep.status.value})")
                                
                    self.task_manager.block_task(task_id, f"DEPENDENCY_FAILURE: Dependencies failed: {failed_deps}")
                    logger.warning(f"[Scheduler] Blocking task {task_id} - failed dependencies: {failed_deps}")
                    updated = True
    
    def get_next_runnable_tasks(self) -> List[Task]:
        """Get tasks ready to run"""
        runnable = []
        for task in self.task_manager.get_tasks_by_status(TaskStatus.QUEUED):
            if self.task_manager.check_dependencies_satisfied(task.spec.task_id):
                runnable.append(task)
        return runnable
    
    def get_execution_summary(self) -> Dict:
        """Summary of execution plan"""
        return {
            "total_stages": len(self.parallel_groups),
            "parallel_groups": self.parallel_groups,
            "execution_order": self.execution_order,
            "total_tasks": len(self.task_manager.tasks),
            "tasks_by_status": {
                status.value: len(self.task_manager.get_tasks_by_status(status))
                for status in TaskStatus
            }
        }
    
    def to_dict(self) -> Dict:
        """Serialize scheduler state"""
        return {
            "execution_plan": self.get_execution_summary(),
            "tasks": self.task_manager.to_dict(),
        }


# Compatibility alias
TaskScheduler = Scheduler