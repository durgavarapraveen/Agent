"""
Unit tests for Phase 5 Module 5.5: Custom Report Builder (core/report_builder.py)
"""

import json
import unittest
from core.reporting.report_builder import CustomReportBuilder


class TestModule5_5_ReportBuilder(unittest.TestCase):

    def setUp(self):
        self.builder = CustomReportBuilder()
        self.findings = [
            {
                "cve": "CVE-2026-1001",
                "title": "Unauthenticated RCE in /api/v1/user@domain.com",
                "severity": "CRITICAL",
                "risk_score": 9.5,
                "remediation": "Update package to version 2.4.49",
                "estimated_hours": 16,
                "type": "RCE"
            },
            {
                "cve": "CVE-2026-1002",
                "title": "SQL Injection in Search Endpoint",
                "severity": "HIGH",
                "risk_score": 7.2,
                "remediation": "Use parameterized queries",
                "estimated_hours": 8,
                "type": "SQLI"
            }
        ]

    def test_compliance_mapping_generator(self):
        """Verify compliance control mapping for PCI-DSS and HIPAA."""
        comp = self.builder.build_compliance_mapping(self.findings)
        self.assertIn("PCI-DSS", comp)
        self.assertIn("HIPAA", comp)
        self.assertIn("Requirement 6.5.1", comp["PCI-DSS"][1]["control"])

    def test_json_export_format(self):
        """Verify machine-readable JSON export with sensitive data masking."""
        raw_json = self.builder.export_json("scan-test", "target.test", self.findings, mask_sensitive=True)
        data = json.loads(raw_json)
        self.assertEqual(data["scan_id"], "scan-test")
        self.assertEqual(len(data["findings"]), 2)
        self.assertIn("u***r@domain.com", data["findings"][0]["title"])

    def test_markdown_export_format(self):
        """Verify version-control friendly Markdown export."""
        roadmap = ["1. Fix CVE-2026-1001 (9.5/10) - Update package"]
        md_text = self.builder.export_markdown("scan-test", "target.test", self.findings, roadmap=roadmap)
        self.assertIn("# Security Assessment Report", md_text)
        self.assertIn("| CRITICAL | CVE-2026-1001 |", md_text)
        self.assertIn("PCI-DSS Control Violations", md_text)

    def test_html_interactive_export(self):
        """Verify single self-contained HTML export with DataTables.js and Chart.js."""
        html_text = self.builder.export_html_interactive("scan-test", "target.test", self.findings)
        self.assertIn("<!doctype html>", html_text)
        self.assertIn("jquery.dataTables.min.js", html_text)
        self.assertIn("chart.js", html_text)
        self.assertIn("CVE-2026-1001", html_text)


if __name__ == "__main__":
    unittest.main()
