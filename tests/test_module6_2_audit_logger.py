"""
Unit tests for Phase 6 Module 6.2: Immutable Audit Logger (core/audit_logger.py)
"""

import json
import os
import unittest
from core.security.audit_logger import AuditLogger


class TestModule6_2_AuditLogger(unittest.TestCase):

    def setUp(self):
        self.log_path = "data/test_audit.log"
        if os.path.exists(self.log_path):
            os.remove(self.log_path)
        self.logger = AuditLogger(log_path=self.log_path)

    def tearDown(self):
        import gc
        del self.logger
        gc.collect()
        if os.path.exists(self.log_path):
            try:
                os.remove(self.log_path)
            except Exception:
                pass

    def test_hash_chained_logging_and_integrity_verification(self):
        """Verify append-only SHA-256 hash chaining and integrity verification."""
        e1 = self.logger.log_event("SCAN_START", "10.0.0.1", "Nmap scan initiated", user="alice@company.com")
        e2 = self.logger.log_event("FINDING_DETECTED", "10.0.0.1", "SQLi detected by nuclei", user="nuclei")

        self.assertEqual(e1["entry_id"], 1)
        self.assertEqual(e2["entry_id"], 2)
        self.assertEqual(e2["previous_hash"], e1["current_hash"])

        valid, tampered_id = self.logger.verify_audit_integrity()
        self.assertTrue(valid)
        self.assertIsNone(tampered_id)

    def test_tamper_detection(self):
        """Verify verify_audit_integrity detects modified audit log entries."""
        self.logger.log_event("SCAN_START", "10.0.0.1", "Initial scan")
        self.logger.log_event("REPORT_EXPORT", "10.0.0.1", "PDF exported")

        # Simulate tampering on line 1
        lines = open(self.log_path, "r", encoding="utf-8").read().strip().split("\n")
        e1 = json.loads(lines[0])
        e1["details"] = "TAMPERED_DETAILS"
        lines[0] = json.dumps(e1)
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        valid, tampered_id = self.logger.verify_audit_integrity()
        self.assertFalse(valid)
        self.assertEqual(tampered_id, 1)

    def test_forensic_query_and_pii_masking(self):
        """Verify forensic query filtering and PII masking."""
        self.logger.log_event("SCAN_START", "10.0.0.1", "Target scan", user="alice@company.com")
        self.logger.log_event("REPORT_EXPORT", "10.0.0.2", "Export report", user="bob@company.com")

        # Query host history
        history = self.logger.query_audit_log(target_ip="10.0.0.1", mask_pii=True)
        self.assertEqual(len(history), 1)
        self.assertIn("a***e@company.com", history[0]["user"])
        self.assertIn("10.0.*.*", history[0]["target"])

    def test_gdpr_anonymization_with_chain_integrity(self):
        """Verify GDPR anonymization redacts fields and preserves hash chain integrity."""
        self.logger.log_event("SCAN_START", "10.0.0.1", "Scan 1")
        self.logger.log_event("SCAN_START", "10.0.0.2", "Scan 2")

        # Anonymize 10.0.0.1
        res = self.logger.anonymize_audit_entries("10.0.0.1")
        self.assertTrue(res)

        # Integrity check after anonymization
        valid, tampered_id = self.logger.verify_audit_integrity()
        self.assertTrue(valid)

        # Verify target is [REDACTED]
        entries = self.logger.query_audit_log(target_ip="10.0.0.1", mask_pii=False)
        self.assertEqual(len(entries), 0)


if __name__ == "__main__":
    unittest.main()
