"""
Unit test suite for Phase 4 Module 4.2: Automated Retesting (core/retest_engine.py).
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from core.security.authorization import TargetScopeValidator
from core.reporting.retest_engine import RetestEngine


class TestModule42RetestEngine(unittest.TestCase):

    def setUp(self):
        TargetScopeValidator.set(TargetScopeValidator(["example.com", "127.0.0.1"]))
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.baseline_path = os.path.join(self.tmp_dir.name, "test_baseline.json")
        self.engine = RetestEngine(timeout=1, rate_limit_per_sec=100)

    def tearDown(self):
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_revalidate_port_finding_closed(self):
        finding = {
            "type": "port_scan",
            "port": 59999,  # Unused port
            "target": "127.0.0.1",
            "confidence_score": 0.80
        }
        res = self.engine.process_finding_retest(finding)
        self.assertEqual(res["reproducibility_status"], "NOT REPRODUCIBLE")
        self.assertEqual(res["confidence_score"], 0.30)
        self.assertEqual(res["confidence_category"], "LOW")

    @patch("urllib.request.urlopen")
    def test_revalidate_http_finding_reproducible(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        finding = {
            "type": "http",
            "url": "https://example.com",
            "status_code": 200,
            "confidence_score": 0.85
        }
        res = self.engine.process_finding_retest(finding)
        self.assertEqual(res["reproducibility_status"], "REPRODUCIBLE")
        self.assertEqual(res["confidence_score"], 0.90)  # +5% confidence boost

    def test_regression_analysis_delta(self):
        old_findings = [
            {"cve_id": "CVE-2021-44228", "url": "https://example.com/app"},
            {"cve_id": "CVE-2017-0143", "url": "https://example.com/smb"}
        ]
        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump(old_findings, f)

        new_findings = [
            {"cve_id": "CVE-2021-44228", "url": "https://example.com/app"},  # PERSISTENT
            {"cve_id": "CVE-2023-12345", "url": "https://example.com/api"}   # NEW_VULNERABILITY
        ]

        delta = self.engine.perform_regression_analysis(new_findings, baseline_path=self.baseline_path)
        self.assertEqual(len(delta["NEW_VULNERABILITY"]), 1)
        self.assertEqual(delta["NEW_VULNERABILITY"][0]["cve_id"], "CVE-2023-12345")

        self.assertEqual(len(delta["REMEDIATED"]), 1)
        self.assertEqual(delta["REMEDIATED"][0]["cve_id"], "CVE-2017-0143")

        self.assertEqual(len(delta["PERSISTENT"]), 1)
        self.assertEqual(delta["PERSISTENT"][0]["cve_id"], "CVE-2021-44228")


if __name__ == "__main__":
    unittest.main()
