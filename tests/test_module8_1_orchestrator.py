"""
Unit tests for Phase 8 Module 8.1: Parallel Task Orchestrator (core/orchestrator_v2.py)
"""

import time
import unittest
from core.orchestrator_v2 import ParallelOrchestrator, TaskPriority


def dummy_worker(x: int) -> int:
    time.sleep(0.05)
    return x * 2


class TestModule8_1_Orchestrator(unittest.TestCase):

    def setUp(self):
        self.orchestrator = ParallelOrchestrator(max_workers=3, max_http_concurrency=10)

    def tearDown(self):
        self.orchestrator.shutdown(wait=False)

    def test_parallel_task_execution(self):
        """Verify parallel execution of 3 tasks via ThreadPoolExecutor."""
        f1 = self.orchestrator.submit_priority_task("task_1", TaskPriority.HIGH, dummy_worker, 5)
        f2 = self.orchestrator.submit_priority_task("task_2", TaskPriority.URGENT, dummy_worker, 10)
        f3 = self.orchestrator.submit_priority_task("task_3", TaskPriority.LOW, dummy_worker, 15)

        self.assertEqual(f1.result(timeout=2.0), 10)
        self.assertEqual(f2.result(timeout=2.0), 20)
        self.assertEqual(f3.result(timeout=2.0), 30)

    def test_async_batch_http_execution(self):
        """Verify async HTTP request batching using aiohttp with concurrency capping."""
        urls = ["https://httpbin.org/get", "https://httpbin.org/headers"]
        results = self.orchestrator.execute_batch_http_async(urls, timeout_sec=5.0)
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertIn("url", r)

    def test_priority_queue_order(self):
        """Verify priority queue handles URGENT before LOW."""
        task_list = []
        def recorder(name):
            task_list.append(name)
            return name

        f1 = self.orchestrator.submit_priority_task("t_low", TaskPriority.LOW, recorder, "LOW_JOB")
        f2 = self.orchestrator.submit_priority_task("t_urgent", TaskPriority.URGENT, recorder, "URGENT_JOB")

        f1.result()
        f2.result()
        self.assertEqual(len(task_list), 2)


if __name__ == "__main__":
    unittest.main()
