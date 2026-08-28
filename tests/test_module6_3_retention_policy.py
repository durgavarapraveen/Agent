"""
Unit tests for Phase 6 Module 6.3: Data Retention Policy (core/retention_policy.py)
"""

import os
import shutil
import unittest
from datetime import datetime, timedelta
from core.retention_policy import RetentionPolicy


class TestModule6_3_RetentionPolicy(unittest.TestCase):

    def setUp(self):
        self.reports_dir = "reports/test_retention"
        self.archives_dir = "archives/test_retention"
        self.audit_log = "data/test_retention_audit.log"

        for p in [self.reports_dir, self.archives_dir]:
            if os.path.exists(p):
                shutil.rmtree(p, ignore_errors=True)
        if os.path.exists(self.audit_log):
            os.remove(self.audit_log)

        self.policy = RetentionPolicy(
            reports_dir=self.reports_dir,
            archives_dir=self.archives_dir,
            audit_log_path=self.audit_log
        )

    def tearDown(self):
        import gc
        del self.policy
        gc.collect()

        for p in [self.reports_dir, self.archives_dir]:
            if os.path.exists(p):
                shutil.rmtree(p, ignore_errors=True)
        if os.path.exists(self.audit_log):
            try:
                os.remove(self.audit_log)
            except Exception:
                pass

    def test_archive_and_auto_cleanup(self):
        """Verify 90-day scan folder auto-archiving and cleanup."""
        old_scan = os.path.join(self.reports_dir, "scan_old_100days")
        os.makedirs(old_scan, exist_ok=True)
        with open(os.path.join(old_scan, "report_summary.txt"), "w") as f:
            f.write("Old scan report data")

        # Set modification time to 100 days ago
        old_time = (datetime.now() - timedelta(days=100)).timestamp()
        os.utime(old_scan, (old_time, old_time))

        res = self.policy.run_auto_cleanup()
        self.assertTrue(res["deleted_scans"] >= 1)
        self.assertFalse(os.path.exists(old_scan))

        # Check encrypted archive created
        enc_archives = list(os.listdir(self.archives_dir))
        self.assertTrue(len(enc_archives) >= 1)
        self.assertTrue(enc_archives[0].endswith(".enc.zip"))

    def test_gdpr_cascade_deletion(self):
        """Verify GDPR customer cascade delete across reports and audit entries."""
        cust_email = "testuser@gdpr.test"
        scan_folder = os.path.join(self.reports_dir, "scan_gdpr_test")
        os.makedirs(scan_folder, exist_ok=True)
        with open(os.path.join(scan_folder, "report_summary.txt"), "w") as f:
            f.write(f"Report summary for customer {cust_email}")

        # Add audit log entry for user
        self.policy.audit_logger.log_event("SCAN_START", "10.0.0.1", f"Scan for {cust_email}")

        del_res = self.policy.delete_customer_data(cust_email)
        self.assertEqual(del_res["status"], "success")
        self.assertFalse(os.path.exists(scan_folder))

        # Verify hash chain integrity after GDPR deletion
        valid, _ = self.policy.audit_logger.verify_audit_integrity()
        self.assertTrue(valid)

    def test_generate_gdpr_deletion_report(self):
        """Verify monthly deletion proof CSV report generation."""
        csv_path = "data/test_gdpr_deletion_report.csv"
        try:
            res_file = self.policy.generate_gdpr_deletion_report(output_csv=csv_path)
            self.assertTrue(os.path.exists(res_file))
            with open(res_file, "r") as f:
                content = f.read()
                self.assertIn("chain_integrity_verified", content)
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)


if __name__ == "__main__":
    unittest.main()
