"""
Unit tests for Module 1.2: Privilege Escalation Detector (core/privesc_detector.py).
"""

import os
import tempfile
import unittest

from core.privesc_detector import PrivescDetector


class TestModule12PrivescDetector(unittest.TestCase):

    def setUp(self):
        self.detector = PrivescDetector()

    def test_windows_uac_bypass_audit(self):
        findings = self.detector.audit_windows_uac_bypass()
        self.assertIsInstance(findings, list)

    def test_windows_dll_hijacking_audit(self):
        findings = self.detector.audit_dll_hijacking()
        self.assertIsInstance(findings, list)

    def test_windows_unquoted_service_paths_audit(self):
        findings = self.detector.audit_unquoted_service_paths()
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].technique, "unquoted_service_path")
        self.assertIn("Manual PoC:", findings[0].escalation_path)

    def test_windows_weak_registry_permissions_audit(self):
        findings = self.detector.audit_weak_registry_permissions()
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].technique, "weak_registry_permissions")

    def test_gtfobins_suid_cross_reference(self):
        suid_binaries = ["/usr/bin/find", "/usr/bin/vim", "/usr/bin/python3"]
        findings = self.detector.cross_reference_gtfobins(suid_binaries, json_db_path="gtfobins.json")
        self.assertEqual(len(findings), 3)
        for f in findings:
            self.assertIn("Manual PoC:", f.escalation_path)

    def test_linux_cron_job_abuse_audit(self):
        findings = self.detector.audit_writable_root_cron_jobs()
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0].technique, "cron_abuse")

    def test_linux_kernel_version_csv_audit(self):
        findings = self.detector.audit_kernel_version_csv("Linux 2.6.32-21-generic", csv_path="kernel_exploits.csv")
        self.assertGreaterEqual(len(findings), 1)
        self.assertIn("DirtyCow", findings[0].detail)

    def test_theoretical_attack_chain_planner(self):
        # Populate mock findings
        self.detector.findings = self.detector.audit_writable_root_cron_jobs() + self.detector.audit_unquoted_service_paths()
        chains = self.detector.generate_theoretical_attack_chains()
        self.assertGreaterEqual(len(chains), 1)
        self.assertIn("remediation_note", chains[0])


if __name__ == "__main__":
    unittest.main()
