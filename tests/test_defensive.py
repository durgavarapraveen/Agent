"""
Unit tests for the Defensive Architecture & Risk Assessment Suite (defensive/).
"""

import os
import tempfile
import unittest

from core.defensive.network_audit import NetworkAuditor
from core.defensive.credential_hardening import CredentialHardeningAuditor, SecretScanner
from core.defensive.persistence_monitor import PersistenceMonitor
from core.defensive.manager import DefensiveRiskAssessor


class TestDefensiveSuite(unittest.TestCase):

    def test_network_auditor_pivot_risks(self):
        auditor = NetworkAuditor(target_host="127.0.0.1")
        findings = auditor.audit_pivot_risks()
        self.assertIsInstance(findings, list)

    def test_secret_scanner_detects_entropy_and_patterns(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = os.path.join(tmp_dir, "config.py")
            with open(test_file, "w", encoding="utf-8") as f:
                f.write('AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"\n')
                f.write('AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n')

            scanner = SecretScanner(root_dir=tmp_dir)
            findings = scanner.scan_directory()

            self.assertGreaterEqual(len(findings), 1)
            types = [f["secret_type"] for f in findings]
            self.assertTrue(any("AWS" in t for t in types))

    def test_credential_hardening_shadow_permissions(self):
        auditor = CredentialHardeningAuditor()
        res = auditor.audit_shadow_permissions("/nonexistent/path/shadow")
        self.assertEqual(res["status"], "not_applicable")

    def test_persistence_monitor_rule_generation(self):
        monitor = PersistenceMonitor()
        sigma = monitor.generate_sigma_rules()
        auditd = monitor.generate_auditd_rules()

        self.assertIn("EventID: 4698", sigma)
        self.assertIn("cron_persistence", auditd)

    def test_defensive_risk_assessor(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            assessor = DefensiveRiskAssessor(root_dir=tmp_dir)
            result = assessor.run_full_assessment()

            self.assertIn("network_exposure", result)
            self.assertIn("credential_protection", result)
            self.assertIn("persistence_monitoring", result)
            self.assertIn("generated_rules", result["persistence_monitoring"])


if __name__ == "__main__":
    unittest.main()
