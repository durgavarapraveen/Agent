import pytest
import asyncio
from core.models import Task, TaskStatus
from orchestrator.scheduler import TaskScheduler

@pytest.fixture
def scheduler():
    return TaskScheduler(max_concurrent=2)

class TestTaskScheduler:
    @pytest.mark.asyncio
    async def test_submit_task(self, scheduler):
        task = Task(
            title="Test",
            description="Test task",
            objective="Test",
            capability="test",
            priority=5
        )
        
        result = await scheduler.submit_task(task)
        assert result is True
        assert scheduler.get_queued_count() == 1
    
    @pytest.mark.asyncio
    async def test_submit_batch(self, scheduler):
        tasks = [
            Task(
                title=f"Test {i}",
                description="Test",
                objective="Test",
                capability="test",
                priority=5
            )
            for i in range(5)
        ]
        
        count = await scheduler.submit_batch(tasks)
        assert count == 5
        assert scheduler.get_queued_count() == 5
    
    @pytest.mark.asyncio
    async def test_task_dependency_check(self, scheduler):
        task1 = Task(title="1", description="", objective="", capability="test", priority=5)
        task2 = Task(title="2", description="", objective="", capability="test", priority=5)
        task2.dependencies = [task1.task_id]
        
        await scheduler.submit_task(task1)
        await scheduler.submit_task(task2)
        
        ready = scheduler.get_ready_tasks()
        assert len(ready) == 1
        assert ready[0].task_id == task1.task_id
    
    @pytest.mark.asyncio
    async def test_max_concurrent_limit(self, scheduler):
        scheduler.max_concurrent = 2
        
        async def dummy_executor(task):
            await asyncio.sleep(0.1)
            return {"status": "success"}
        
        tasks = [
            Task(title=f"T{i}", description="", objective="", capability="test", priority=5)
            for i in range(5)
        ]
        
        for task in tasks:
            await scheduler.submit_task(task)
        
        results = await scheduler.schedule_work(dummy_executor, max_tasks=2)
        
        assert len(results) == 2
        assert scheduler.get_completed_count() == 2
