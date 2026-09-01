"""
Phase 8 Module 8.1: Parallel Task Orchestrator (core/orchestrator_v2.py)

Daemonized ThreadPoolExecutor for concurrent tasks, priority queueing,
aiohttp async HTTP request batching with semaphore concurrency capping,
structured JSON logging, and cross-platform resource limit enforcement.
"""

import asyncio
import concurrent.futures
import json
import logging
import queue
import time
from enum import IntEnum
from typing import Dict, List, Any, Callable

import aiohttp

logger = logging.getLogger(__name__)


class TaskPriority(IntEnum):
    """Task Priority Levels (lower integer = higher priority)."""
    URGENT = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3


class PriorityTask:
    """Wrapper for PriorityQueue items to enable comparison."""
    def __init__(self, priority: TaskPriority, task_id: str, func: Callable, args: tuple = (), kwargs: dict = None):
        self.priority = priority
        self.task_id = task_id
        self.func = func
        self.args = args
        self.kwargs = kwargs or {}

    def __lt__(self, other):
        return self.priority < other.priority


class ParallelOrchestrator:
    """Daemonized ThreadPool & AsyncIO Task Orchestrator."""

    def __init__(self, max_workers: int = 3, max_http_concurrency: int = 50):
        self.max_workers = max_workers
        self.max_http_concurrency = max_http_concurrency
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="AntiGravityWorker"
        )
        self.priority_queue = queue.PriorityQueue()
        self.active_futures: Dict[str, concurrent.futures.Future] = {}
        self.apply_resource_limits()

    def apply_resource_limits(self):
        """Enforce per-process resource limits (POSIX setrlimit / Windows fallback)."""
        try:
            import resource
            # Cap maximum open files to 1024 if allowed
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            resource.setrlimit(resource.RLIMIT_NOFILE, (min(1024, hard), hard))
            logger.info("[OrchestratorV2] POSIX resource limits applied successfully.")
        except (ImportError, AttributeError, ValueError):
            # Windows fallback log
            logger.debug("[OrchestratorV2] Non-POSIX OS detected; standard resource limits active.")

    def submit_priority_task(
        self,
        task_id: str,
        priority: TaskPriority,
        func: Callable,
        *args,
        **kwargs
    ) -> concurrent.futures.Future:
        """Submit a task to the priority queue and dispatch to thread pool."""
        item = PriorityTask(priority=priority, task_id=task_id, func=func, args=args, kwargs=kwargs)
        self.priority_queue.put(item)
        
        # Pop from queue and submit to executor
        next_item: PriorityTask = self.priority_queue.get()
        future = self.executor.submit(next_item.func, *next_item.args, **next_item.kwargs)
        self.active_futures[next_item.task_id] = future

        self.log_structured_event(
            level="INFO",
            event="TASK_SUBMITTED",
            details={
                "task_id": next_item.task_id,
                "priority": next_item.priority.name,
                "max_workers": self.max_workers
            }
        )
        return future

    async def _async_http_fetch(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        url: str,
        method: str = "GET",
        headers: Dict[str, str] = None,
        timeout_sec: float = 5.0
    ) -> Dict[str, Any]:
        """Fetch single HTTP request with semaphore concurrency limit."""
        async with semaphore:
            try:
                timeout = aiohttp.ClientTimeout(total=timeout_sec)
                async with session.request(method, url, headers=headers, timeout=timeout) as response:
                    text = await response.text()
                    return {
                        "url": url,
                        "status": response.status,
                        "headers": dict(response.headers),
                        "content_length": len(text),
                        "success": True
                    }
            except Exception as e:
                return {
                    "url": url,
                    "status": 0,
                    "error": str(e),
                    "success": False
                }

    async def _batch_http_async_loop(
        self,
        urls: List[str],
        headers: Dict[str, str] = None,
        timeout_sec: float = 5.0
    ) -> List[Dict[str, Any]]:
        """Asynchronous batch HTTP request runner using aiohttp & semaphore."""
        semaphore = asyncio.Semaphore(self.max_http_concurrency)
        connector = aiohttp.TCPConnector(limit=self.max_http_concurrency)

        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                self._async_http_fetch(session, semaphore, url, headers=headers, timeout_sec=timeout_sec)
                for url in urls
            ]
            return await asyncio.gather(*tasks)

    def execute_batch_http_async(
        self,
        urls: List[str],
        headers: Dict[str, str] = None,
        timeout_sec: float = 5.0
    ) -> List[Dict[str, Any]]:
        """Synchronous wrapper to run batch HTTP requests safely."""
        try:
            return asyncio.run(self._batch_http_async_loop(urls, headers, timeout_sec))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self._batch_http_async_loop(urls, headers, timeout_sec))
            finally:
                loop.close()

    def log_structured_event(self, level: str, event: str, details: Dict[str, Any]):
        """Emit structured JSON log for SIEM/log aggregation tools."""
        log_entry = {
            "timestamp": time.time(),
            "iso_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level": level,
            "event": event,
            "details": details
        }
        logger.info(json.dumps(log_entry))

    def shutdown(self, wait: bool = False):
        """Shutdown ThreadPoolExecutor and release resources."""
        self.executor.shutdown(wait=wait)
        self.log_structured_event("INFO", "ORCHESTRATOR_SHUTDOWN", {"wait": wait})
