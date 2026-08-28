"""
Unit tests for Phase 8 Module 8.2: Resource Limits & Timeouts (core/resource_limiter.py)
"""

import os
import sys
import time
import unittest
from core.resource_limiter import ResourceLimiter, ResourceViolationError


class TestModule8_2_ResourceLimiter(unittest.TestCase):

    def setUp(self):
        self.limiter = ResourceLimiter()

    def tearDown(self):
        self.limiter.cancel_global_scan_timer()
        self.limiter.terminate_all_processes()

    def test_run_subprocess_success(self):
        """Verify normal subprocess execution and resource usage summary."""
        cmd = [sys.executable, "-c", "print('hello world')"]
        res = self.limiter.run_subprocess_with_limits(cmd, tool_name="python", timeout=5)
        self.assertEqual(res["returncode"], 0)
        self.assertIn("hello world", res["stdout"])
        self.assertFalse(res["timed_out"])
        self.assertEqual(res["status"], "SUCCESS")

    def test_subprocess_timeout_partial_results(self):
        """Verify tool timeout enforcement capturing partial stdout and flagging PARTIAL_RESULTS."""
        cmd = [sys.executable, "-c", "import time; print('start'); time.sleep(10)"]
        res = self.limiter.run_subprocess_with_limits(cmd, tool_name="sleep_tool", timeout=1)
        self.assertTrue(res["timed_out"])
        self.assertEqual(res["status"], "PARTIAL_RESULTS")

    def test_global_scan_timer(self):
        """Verify daemonized global scan timer callback execution."""
        triggered = []
        def _cb():
            triggered.append(True)

        timer = self.limiter.start_global_scan_timer(timeout_sec=0.2, callback=_cb)
        time.sleep(0.4)
        self.assertTrue(len(triggered) >= 1)


if __name__ == "__main__":
    unittest.main()
