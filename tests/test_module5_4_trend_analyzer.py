"""
Unit tests for Phase 5 Module 5.4: Trend Analyzer (core/trend_analyzer.py)
"""

import os
import unittest
from core.reporting.trend_analyzer import TrendAnalyzer


class TestModule5_4_TrendAnalyzer(unittest.TestCase):

    def setUp(self):
        self.db_path = "data/test_scan_history.sqlite"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        self.analyzer = TrendAnalyzer(db_path=self.db_path)

    def tearDown(self):
        # Force garbage collection to release SQLite lock on Windows
        import gc
        del self.analyzer
        gc.collect()
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    def test_record_scan_summary_and_recurring_detection(self):
        """Verify recording scan summary and flagging recurring vulnerabilities after 3 consecutive scans."""
        vulns_scan1 = [
            {"cve": "CVE-2026-1001", "severity": "CRITICAL", "risk_score": 9.0},
            {"type": "XSS", "target": "/search", "severity": "HIGH", "risk_score": 7.0}
        ]
        res1 = self.analyzer.record_scan_summary("scan-001", "target.test", vulns_scan1)
        self.assertEqual(len(res1["recurring_vulnerabilities"]), 0)

        # Scan 2
        self.analyzer.record_scan_summary("scan-002", "target.test", vulns_scan1)

        # Scan 3 (should flag recurring)
        res3 = self.analyzer.record_scan_summary("scan-003", "target.test", vulns_scan1)
        self.assertTrue(len(res3["recurring_vulnerabilities"]) >= 1)
        self.assertIn("persisted across 3 scans", res3["recurring_vulnerabilities"][0]["warning"])

    def test_mttd_and_remediation_rate(self):
        """Verify calculation of MTTD and remediation rate."""
        vulns_scan1 = [{"cve": "CVE-2026-1001", "severity": "CRITICAL"}]
        self.analyzer.record_scan_summary("scan-001", "target.test", vulns_scan1)

        # Scan 2 (remediated)
        self.analyzer.record_scan_summary("scan-002", "target.test", [])

        metrics = self.analyzer.compute_mttd_and_remediation_rate("target.test")
        self.assertTrue(metrics["remediation_rate_percent"] > 0)
        self.assertEqual(metrics["remediated_count"], 1)

    def test_predictive_trend_analysis_linregress(self):
        """Verify scipy.stats.linregress linear regression trend predictions and graph output."""
        target = "target.test"
        # Simulate increasing trend: 5, 8, 12, 15 findings
        for i, count in enumerate([5, 8, 12, 15]):
            vulns = [{"severity": "MEDIUM"} for _ in range(count)]
            self.analyzer.record_scan_summary(f"scan-00{i+1}", target, vulns)

        pred = self.analyzer.predict_future_trends(target)
        self.assertTrue(pred["slope"] > 0)
        self.assertIn("will increase to", pred["prediction"])
        self.assertTrue(len(pred["base64_graph"]) > 50)


if __name__ == "__main__":
    unittest.main()
