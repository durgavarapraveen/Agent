import asyncio
from typing import List, Dict, Optional
from datetime import datetime
import logging

from core.models import Task, TaskStatus
from core.events import EventType

logger = logging.getLogger(__name__)

class TaskScheduler:
    """Schedules and manages task execution."""
    
    def __init__(self, max_concurrent: int = 4):
        self.max_concurrent = max_concurrent
        self.task_queue: List[Task] = []
        self.running_tasks: Dict[str, Task] = {}
        self.completed_tasks: List[Task] = []
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.task_executors = {}  # task_id -> executing coroutine
    
    async def submit_task(self, task: Task) -> bool:
        """Submit a task for execution."""
        task.status = TaskStatus.QUEUED
        self.task_queue.append(task)
        logger.debug(f"Task queued: {task.task_id} ({task.capability})")
        return True
    
    async def submit_batch(self, tasks: List[Task]) -> int:
        """Submit multiple tasks."""
        count = 0
        for task in tasks:
            if await self.submit_task(task):
                count += 1
        return count
    
    def _check_dependencies(self, task: Task) -> bool:
        """Check if a task's dependencies are met."""
        for dep_id in task.dependencies:
            # Check if dependency is in completed
            if not any(t.task_id == dep_id for t in self.completed_tasks):
                return False
        return True
    
    def get_ready_tasks(self) -> List[Task]:
        """Get tasks ready for execution."""
        ready = []
        for task in self.task_queue:
            if task.status == TaskStatus.QUEUED and self._check_dependencies(task):
                ready.append(task)
        return ready
    
    async def schedule_work(self, executor_func, max_tasks: int = None) -> List:
        """Schedule available tasks for execution."""
        tasks_to_run = self.get_ready_tasks()
        
        if max_tasks:
            tasks_to_run = tasks_to_run[:max_tasks]
        
        if not tasks_to_run:
            return []
        
        execution_tasks = []
        for task in tasks_to_run:
            execution_tasks.append(self._execute_task(task, executor_func))
        
        results = await asyncio.gather(*execution_tasks, return_exceptions=True)
        return results
    
    async def _execute_task(self, task: Task, executor_func):
        """Execute a single task with concurrency control."""
        async with self.semaphore:
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now()
            
            # Move from queue to running
            self.task_queue.remove(task)
            self.running_tasks[task.task_id] = task
            
            try:
                result = await executor_func(task)
                task.status = TaskStatus.COMPLETED
                task.result = result
            except asyncio.TimeoutError:
                logger.error(f"Task timeout: {task.task_id}")
                task.status = TaskStatus.FAILED
            except Exception as e:
                logger.error(f"Task execution failed {task.task_id}: {e}")
                task.status = TaskStatus.FAILED
            finally:
                task.completed_at = datetime.now()
                self.running_tasks.pop(task.task_id, None)
                self.completed_tasks.append(task)
    
    def get_queued_count(self) -> int:
        """Get number of queued tasks."""
        return len([t for t in self.task_queue if t.status == TaskStatus.QUEUED])
    
    def get_running_count(self) -> int:
        """Get number of running tasks."""
        return len(self.running_tasks)
    
    def get_completed_count(self) -> int:
        """Get number of completed tasks."""
        return len(self.completed_tasks)
    
    def get_status_summary(self) -> Dict[str, int]:
        """Get task status summary."""
        return {
            "queued": self.get_queued_count(),
            "running": self.get_running_count(),
            "completed": self.get_completed_count(),
            "total": len(self.task_queue) + len(self.running_tasks) + len(self.completed_tasks)
        }
    
    async def wait_for_completion(self, task_id: str, timeout: int = 300) -> bool:
        """Wait for a task to complete."""
        start = datetime.now()
        while True:
            # Check if completed
            if any(t.task_id == task_id for t in self.completed_tasks):
                return True
            
            # Check timeout
            elapsed = (datetime.now() - start).total_seconds()
            if elapsed > timeout:
                logger.warning(f"Timeout waiting for task: {task_id}")
                return False
            
            await asyncio.sleep(0.5)
