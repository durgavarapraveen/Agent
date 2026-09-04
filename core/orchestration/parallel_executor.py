"""
Parallel Execution Engine (Phase 16).

Executes independent task groups concurrently with:
- Configurable concurrency limits
- Target health awareness (backs off when target degrades)
- Per-task timeout enforcement
- Result aggregation
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)


class TaskResult:
    __slots__ = ("task_id", "success", "result", "error", "duration_ms")

    def __init__(self, task_id: str, success: bool, result: Any = None,
                 error: str = "", duration_ms: float = 0.0):
        self.task_id = task_id
        self.success = success
        self.result = result
        self.error = error
        self.duration_ms = duration_ms


class ParallelExecutor:

    def __init__(self, max_concurrency: int = 5,
                 task_timeout: float = 120.0,
                 health_manager=None):
        self._max_concurrency = max_concurrency
        self._task_timeout = task_timeout
        self._health = health_manager
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._results: Dict[str, TaskResult] = {}
        self._running_count = 0

    @property
    def effective_concurrency(self) -> int:
        if self._health:
            return min(self._max_concurrency, self._health.concurrency)
        return self._max_concurrency

    async def execute_group(
        self,
        tasks: List[Dict[str, Any]],
        executor_fn: Callable[[Dict[str, Any]], Coroutine],
    ) -> List[TaskResult]:
        concurrency = self.effective_concurrency
        if concurrency <= 0:
            logger.warning("PARALLEL_EXEC concurrency=0 (target paused), skipping group")
            return [TaskResult(t.get("task_id", "?"), False, error="TARGET_PAUSED")
                    for t in tasks]

        self._semaphore = asyncio.Semaphore(concurrency)
        logger.info(f"PARALLEL_EXEC starting group={len(tasks)} concurrency={concurrency}")

        coros = [self._run_one(t, executor_fn) for t in tasks]
        results = await asyncio.gather(*coros, return_exceptions=True)

        final = []
        for i, r in enumerate(results):
            tid = tasks[i].get("task_id", str(i))
            if isinstance(r, Exception):
                final.append(TaskResult(tid, False, error=str(r)))
            else:
                final.append(r)

        succeeded = sum(1 for r in final if r.success)
        failed = len(final) - succeeded
        logger.info(f"PARALLEL_EXEC done succeeded={succeeded} failed={failed}")
        return final

    async def execute_stages(
        self,
        stages: List[List[Dict[str, Any]]],
        executor_fn: Callable[[Dict[str, Any]], Coroutine],
    ) -> List[List[TaskResult]]:
        all_results = []
        for i, stage in enumerate(stages):
            logger.info(f"PARALLEL_EXEC stage={i+1}/{len(stages)} tasks={len(stage)}")
            results = await self.execute_group(stage, executor_fn)
            all_results.append(results)

            failed = [r for r in results if not r.success]
            if failed:
                logger.warning(f"PARALLEL_EXEC stage={i+1} failures={len(failed)}")
        return all_results

    async def _run_one(
        self,
        task: Dict[str, Any],
        executor_fn: Callable[[Dict[str, Any]], Coroutine],
    ) -> TaskResult:
        tid = task.get("task_id", "unknown")
        await self._semaphore.acquire()
        self._running_count += 1
        start = time.monotonic()
        try:
            result = await asyncio.wait_for(
                executor_fn(task), timeout=self._task_timeout
            )
            elapsed = (time.monotonic() - start) * 1000
            return TaskResult(tid, True, result=result, duration_ms=elapsed)
        except asyncio.TimeoutError:
            elapsed = (time.monotonic() - start) * 1000
            logger.warning(f"PARALLEL_EXEC timeout task={tid} after {elapsed:.0f}ms")
            return TaskResult(tid, False, error="TIMEOUT", duration_ms=elapsed)
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            logger.error(f"PARALLEL_EXEC error task={tid}: {e}")
            return TaskResult(tid, False, error=str(e), duration_ms=elapsed)
        finally:
            self._running_count -= 1
            self._semaphore.release()
