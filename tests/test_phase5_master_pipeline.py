"""
End-to-End integration tests for Phase 5 Master Orchestrator (core/reporting_engine.py)
"""

import os
import shutil
import unittest
from core.reporting_engine import ReportingEngine


class TestPhase5_MasterPipeline(unittest.TestCase):

    def setUp(self):
        self.output_dir = "reports/test_phase5_bundle"
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir, ignore_errors=True)
        self.engine = ReportingEngine(output_dir=self.output_dir)

    def tearDown(self):
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir, ignore_errors=True)

    def test_full_phase5_pipeline_execution(self):
        """Verify full Phase 5 pipeline: Aggregate -> Analyze -> Render -> Export."""
        target = "https://example-corp.test/user@domain.com?key=AKIA1234567890EXAMPLE"
        findings = [
            {
                "cve": "CVE-2023-12345",
                "title": "Unauthenticated RCE in Apache HTTP Server with password=SecretAdmin123!",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "public_exploit_available": True,
                "easy_to_chain": True,
                "no_authentication_required": True,
                "type": "RCE"
            },
            {
                "cve": "CVE-2022-1234",
                "title": "SQL Injection in Payment Search",
                "severity": "HIGH",
                "cvss": 7.5,
                "public_exploit_available": False,
                "type": "SQLI"
            }
        ]

        result = self.engine.generate_report_bundle(
            target=target,
            vulnerabilities=findings,
            scan_id="test_scan_001",
            industry="healthcare",
            mask_sensitive=True
        )

        self.assertTrue(os.path.exists(result["html"]))
        self.assertTrue(os.path.exists(result["json"]))
        self.assertTrue(os.path.exists(result["markdown"]))
        self.assertTrue(os.path.exists(result["summary"]))

        # Verify summary text content
        with open(result["summary"], "r", encoding="utf-8") as f:
            summary_txt = f.read()
            self.assertIn("ANTIGRAVITY REPORTING ENGINE — PHASE 5 SUMMARY", summary_txt)
            self.assertIn("Total Findings: 2", summary_txt)
            self.assertIn("Total Estimated Patch Effort:", summary_txt)


if __name__ == "__main__":
    unittest.main()
