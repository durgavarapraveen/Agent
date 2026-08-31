"""
Unit tests for Phase 5 Module 5.3: Remediation Engine (core/remediation_engine.py)
"""

import unittest
from core.reporting.remediation_engine import RemediationEngine


class TestModule5_3_RemediationEngine(unittest.TestCase):

    def setUp(self):
        self.engine = RemediationEngine()

    def test_remediation_text_lookup_and_fallback(self):
        """Verify CVE remediation map lookup and fallback rules."""
        cve_finding = {"cve": "CVE-2023-12345", "type": "RCE"}
        text = self.engine.get_remediation_text(cve_finding)
        self.assertIn("Update Apache HTTP Server", text)

        sqli_finding = {"type": "SQLI", "severity": "HIGH"}
        text_sqli = self.engine.get_remediation_text(sqli_finding)
        self.assertIn("parameterized queries", text_sqli)

    def test_patch_effort_estimation(self):
        """Verify patch effort hours lookup, heuristics, and total report aggregation."""
        cve_finding = {"cve": "CVE-2023-21768"}
        hours = self.engine.estimate_patch_effort(cve_finding)
        self.assertEqual(hours, 40)

        header_finding = {"type": "HEADER", "severity": "LOW"}
        hours_header = self.engine.estimate_patch_effort(header_finding)
        self.assertEqual(hours_header, 1)

        total_hours = self.engine.calculate_total_remediation_hours([cve_finding, header_finding])
        self.assertEqual(total_hours, 41)

    def test_industry_playbook_overrides(self):
        """Verify industry playbook override rules for Healthcare, Finance, and E-commerce."""
        health_finding = {"type": "SQLI"}
        health_text = self.engine.get_remediation_text(health_finding, industry="healthcare")
        self.assertIn("HIPAA", health_text)

        fin_finding = {"type": "XSS"}
        fin_text = self.engine.get_remediation_text(fin_finding, industry="finance")
        self.assertIn("PCI-DSS", fin_text)

    def test_workaround_suggestions_when_patch_unavailable(self):
        """Verify zero-day / unpatched workaround suggestions with warning flags."""
        unpatched_finding = {
            "cve": "CVE-2021-44228",
            "patch_available": False,
            "details": "Zero-day log4j vulnerability"
        }
        workaround = self.engine.check_workaround(unpatched_finding)
        self.assertIsNotNone(workaround)
        self.assertIn("WARNING: No vendor patch available", workaround["warning"])


if __name__ == "__main__":
    unittest.main()
