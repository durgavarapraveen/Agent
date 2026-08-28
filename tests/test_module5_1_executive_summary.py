"""
Unit tests for Phase 5 Module 5.1: Executive Summary Generator (core/reporting.py)
"""

import os
import unittest
from types import SimpleNamespace
from core.reporting import (
    MANDATORY_DISCLAIMER,
    mask_sensitive_data,
    EncryptedTrendStore,
    compare_industry_benchmark,
    generate_severity_chart,
    generate_key_metrics_table,
    ExecutiveSummaryGenerator
)


class TestModule5_1_ExecutiveSummary(unittest.TestCase):

    def test_mask_sensitive_data(self):
        """Verify masking of AWS keys, email PII, passwords, and bearer tokens."""
        raw_text = "Found AKIA1234567890EXAMPLE and admin@company.com with password=SuperSecret123! and Bearer token123xyz"
        masked = mask_sensitive_data(raw_text, enabled=True)

        self.assertNotIn("AKIA1234567890EXAMPLE", masked)
        self.assertIn("AKIA************EXAMPLE", masked)
        self.assertNotIn("admin@company.com", masked)
        self.assertIn("a***n@company.com", masked)
        self.assertNotIn("SuperSecret123!", masked)
        self.assertIn("password=[MASKED]", masked)
        self.assertNotIn("token123xyz", masked)

        # Disabling masking
        unmasked = mask_sensitive_data(raw_text, enabled=False)
        self.assertEqual(unmasked, raw_text)

    def test_encrypted_trend_store(self):
        """Verify encrypted SQLite persistence of scan history."""
        db_path = "data/test_historical_trends.sqlite"
        if os.path.exists(db_path):
            os.remove(db_path)

        store = EncryptedTrendStore(db_path=db_path)
        store.record_scan("target.test", {"CRITICAL": 3, "HIGH": 5}, 3, 8.5)
        store.record_scan("target.test", {"CRITICAL": 5, "HIGH": 7}, 5, 9.2)

        history = store.get_target_history("target.test")
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["critical_count"], 3)
        self.assertEqual(history[1]["critical_count"], 5)

        avg_crit = store.get_average_critical("target.test")
        self.assertEqual(avg_crit, 4.0)

        if os.path.exists(db_path):
            os.remove(db_path)

    def test_industry_benchmark_comparison(self):
        """Verify finding comparisons against industry benchmark CSV."""
        counts = {"CRITICAL": 5, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
        result = compare_industry_benchmark(counts, industry="finance")

        self.assertIn("finance industry average", result)
        self.assertIn("Your critical findings (5) are at or below", result)

        counts_high = {"CRITICAL": 15, "HIGH": 50, "MEDIUM": 10, "LOW": 5}
        result_exceed = compare_industry_benchmark(counts_high, industry="finance")
        self.assertIn("exceed the finance industry average", result_exceed)

    def test_severity_chart_generation(self):
        """Verify Matplotlib horizontal bar chart generation and base64 PNG encoding."""
        counts = {"CRITICAL": 4, "HIGH": 8, "MEDIUM": 12, "LOW": 6, "INFO": 2}
        chart_data = generate_severity_chart(counts, previous_critical_avg=2.0)

        self.assertEqual(chart_data["trend_indicator"], "▲")
        self.assertTrue(len(chart_data["base64_png"]) > 50)

    def test_key_metrics_table(self):
        """Verify MTTR, % public exploit, and % reproducible Markdown table."""
        vulns = [
            {"severity": "CRITICAL", "has_exploit": True, "status": "CONFIRMED"},
            {"severity": "HIGH", "has_exploit": False, "status": "CONFIRMED"},
            {"severity": "MEDIUM", "has_exploit": True, "status": "UNVERIFIED"},
            {"severity": "LOW", "has_exploit": False, "status": "CONFIRMED"},
        ]
        retest = [
            {"reproducible": True},
            {"reproducible": True},
            {"reproducible": False},
            {"reproducible": True},
        ]
        patches = [{"days_to_patch": 10.0}, {"days_to_patch": 20.0}]

        table_md = generate_key_metrics_table(vulns, retest, patches)
        self.assertIn("| Mean Time to Remediation (MTTR) | 15.0 Days |", table_md)
        self.assertIn("| % Public Exploit Available | 50.0% |", table_md)
        self.assertIn("| % Reproducible Findings | 75.0% |", table_md)

    def test_executive_summary_generator(self):
        """Verify Jinja2 rendering of executive summary with mandatory disclaimer."""
        ctx = SimpleNamespace(
            target="https://target.test/user@domain.com?key=AKIA1234567890EXAMPLE",
            vulnerabilities=[
                {
                    "severity": "CRITICAL",
                    "title": "Unauthenticated Remote Code Execution in /api/v1/user@domain.com",
                    "cve": "CVE-2026-1234",
                    "details": "RCE vulnerability with password=SecretAdmin123!",
                    "has_exploit": True
                },
                {
                    "severity": "HIGH",
                    "title": "SQL Injection in Search Endpoint",
                    "cve": "CVE-2026-5678",
                    "details": "SQLi vulnerability in parameter q",
                    "has_exploit": False
                }
            ]
        )

        gen = ExecutiveSummaryGenerator()
        res = gen.render(ctx, industry="technology", mask_sensitive=True)

        self.assertIn("EXECUTIVE SECURITY ASSESSMENT SUMMARY", res["text"])
        self.assertIn(MANDATORY_DISCLAIMER, res["text"])
        self.assertIn("Critical: 1", res["text"])
        self.assertIn("High:     1", res["text"])
        self.assertIn("u***r@domain.com", res["text"])
        self.assertNotIn("SecretAdmin123!", res["text"])
        self.assertIn("password=[MASKED]", res["text"])
        self.assertIn("<div class='exec-summary'>", res["html"])


if __name__ == "__main__":
    unittest.main()
