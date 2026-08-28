"""
Unit tests for Phase 6 Module 6.5: Framework-Specific Compliance Mapper (core/compliance_mapper.py)
"""

import unittest
from core.compliance_mapper import ComplianceMapper


class TestModule6_5_ComplianceMapper(unittest.TestCase):

    def setUp(self):
        self.mapper = ComplianceMapper()
        self.vulnerabilities = [
            {"cve": "CVE-2026-1001", "type": "SQLI", "severity": "CRITICAL", "title": "SQL Injection in Search"},
            {"cve": "CVE-2026-1002", "type": "XSS", "severity": "HIGH", "title": "Reflected XSS in Login"}
        ]

    def test_single_finding_mapping(self):
        """Verify single finding mapping to PCI-DSS, HIPAA, and ISO 27001."""
        pci_map = self.mapper.map_finding(self.vulnerabilities[0], "PCI-DSS")
        self.assertIn("Requirement 6.6", pci_map["control_id"])

        hipaa_map = self.mapper.map_finding(self.vulnerabilities[1], "HIPAA")
        self.assertIn("164.312", hipaa_map["control_id"])

    def test_compliance_gap_detection_and_scorecard(self):
        """Verify automated gap detection statements and compliance scorecards."""
        gaps = self.mapper.detect_compliance_gaps(self.vulnerabilities)
        self.assertTrue(len(gaps) >= 2)
        self.assertIn("violates", gaps[0])

        scorecards = self.mapper.generate_scorecard(self.vulnerabilities)
        self.assertIn("PCI-DSS", scorecards)
        self.assertIn("compliance_percentage", scorecards["PCI-DSS"])

    def test_framework_prioritization_and_audit_evidence(self):
        """Verify primary framework action plan and boilerplate audit evidence statements."""
        plan = self.mapper.prioritize_for_framework(self.vulnerabilities, primary_framework="PCI-DSS")
        self.assertTrue(len(plan) >= 2)

        evidence = self.mapper.collect_audit_evidence(self.vulnerabilities)
        self.assertTrue(len(evidence) >= 1)
        self.assertIn("was tested on", evidence[0])


if __name__ == "__main__":
    unittest.main()
