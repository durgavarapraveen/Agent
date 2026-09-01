"""
Unit tests for Phase 8 Module 8.3: Failure Recovery Engine (core/recovery_engine.py)
"""

import os
import shutil
import tempfile
import unittest
from core.common.recovery_engine import RecoveryEngine


class TestModule8_3_RecoveryEngine(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.checkpoints_dir = os.path.join(self.test_dir, "checkpoints")
        self.audit_log = os.path.join(self.test_dir, "audit.log")
        self.engine = RecoveryEngine(checkpoints_dir=self.checkpoints_dir, audit_log_path=self.audit_log)

    def tearDown(self):
        self.engine.stop_periodic_checkpoint_timer()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_and_resume_checkpoint(self):
        """Verify saving AES-256-GCM encrypted checkpoint and resuming state."""
        scan_id = "test_scan_001"
        state = {
            "completed_modules": ["Module1", "Module2"],
            "partial_findings": [{"cve": "CVE-2026-001"}],
            "current_target": "10.0.0.1",
            "remaining_tasks": ["Module3", "Module4"]
        }

        chk_path = self.engine.save_checkpoint(scan_id, state)
        self.assertTrue(os.path.exists(chk_path))

        resumed_state = self.engine.resume_from_checkpoint(scan_id)
        self.assertIsNotNone(resumed_state)
        self.assertEqual(resumed_state["scan_id"], scan_id)
        self.assertEqual(resumed_state["completed_modules"], ["Module1", "Module2"])

    def test_graceful_degradation_llm(self):
        """Verify LLM fallback rule-based decision tree."""
        decision = self.engine.fallback_llm_decision({"type": "SQLI_VULN", "target": "10.0.0.5"})
        self.assertTrue(decision["fallback_used"])
        self.assertEqual(decision["recommended_action"], "run_sqlmap_validation")

    def test_db_fallback_buffer_and_flush(self):
        """Verify in-memory finding buffering and flushing when DB is restored."""
        self.engine.buffer_finding_in_memory({"id": 1, "finding": "Test Finding"})
        self.assertEqual(len(self.engine.memory_finding_buffer), 1)

        def dummy_db_save(item):
            return True

        flushed = self.engine.flush_memory_buffer(dummy_db_save)
        self.assertEqual(flushed, 1)
        self.assertEqual(len(self.engine.memory_finding_buffer), 0)


if __name__ == "__main__":
    unittest.main()
