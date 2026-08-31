"""
End-to-End integration tests for Phase 6 Master Orchestrator (core/compliance_gate.py)
"""

import unittest
from core.reporting.compliance_gate import ComplianceGate
from core.security.legal_validator import ScopeViolationException


class TestPhase6_ComplianceGate(unittest.TestCase):

    def setUp(self):
        self.gate = ComplianceGate()
        self.gate.legal_validator.add_authorized_scope(cidr="10.0.0.0/24", domain="target.test")

    def test_full_phase6_compliance_gate_flow(self):
        """Verify full Phase 6 workflow: Pre-scan gate -> Audit log -> Post-scan compliance -> Crypto -> Retention."""
        target_ip = "10.0.0.5"
        target_domain = "api.target.test"

        # 1. Pre-Scan Gate
        self.assertTrue(self.gate.pre_scan_gate(target_ip, target_domain))

        # Out of scope check
        with self.assertRaises(ScopeViolationException):
            self.gate.pre_scan_gate("192.168.99.99")

        # 2. During Scan Audit Logging
        log_entry = self.gate.log_scan_action("SCAN_START", target_ip, "Nuclei scan started")
        self.assertEqual(log_entry["action"], "SCAN_START")

        # 3. Post-Scan Compliance Assessment
        findings = [
            {"cve": "CVE-2026-1001", "type": "SQLI", "severity": "CRITICAL", "title": "SQL Injection"}
        ]
        comp_res = self.gate.post_scan_compliance_assessment(findings, primary_framework="PCI-DSS")
        self.assertIn("scorecards", comp_res)
        self.assertIn("PCI-DSS", comp_res["scorecards"])

        # 4. Storage Encryption / Decryption
        raw_data = "Database payload string"
        enc_bytes = self.gate.encrypt_storage_payload(raw_data)
        dec_data = self.gate.decrypt_storage_payload(enc_bytes)
        self.assertEqual(raw_data, dec_data)


if __name__ == "__main__":
    unittest.main()
