"""
Unit tests for core/retest_engine.py automated reproducibility engine.
"""

import asyncio
import unittest
from unittest.mock import patch

from core.reporting.retest_engine import RetestEngine


class TestRetestEngine(unittest.TestCase):

    def setUp(self):
        self.engine = RetestEngine()

    @patch.object(RetestEngine, "_single_probe")
    def test_retest_finding_confirmed_3_of_3_successes(self, mock_probe):
        mock_probe.return_value = (200, "probe_xss_check_12345 reflected in body")

        finding = {
            "id": "VULN-001",
            "type": "unencoded_input_reflection",
            "title": "Unencoded Reflection",
            "location": "http://example.com/search?q=probe_xss_check_12345",
            "tracer_used": "probe_xss_check_12345"
        }

        reproducible, count = asyncio.run(self.engine.can_reproduce(finding, attempts=3, min_success_threshold=2))
        self.assertTrue(reproducible)
        self.assertEqual(count, 3)

    @patch.object(RetestEngine, "_single_probe")
    def test_retest_finding_unconfirmed_intermittent_failure(self, mock_probe):
        # 1 success, 2 failures
        mock_probe.side_effect = [
            (200, "probe_xss_check_12345"),
            (500, "Internal Error"),
            (500, "Internal Error")
        ]

        finding = {
            "id": "VULN-002",
            "type": "unencoded_input_reflection",
            "title": "Unencoded Reflection",
            "location": "http://example.com/search",
            "tracer_used": "probe_xss_check_12345"
        }

        reproducible, count = asyncio.run(self.engine.can_reproduce(finding, attempts=3, min_success_threshold=2))
        self.assertFalse(reproducible)
        self.assertEqual(count, 1)

    @patch.object(RetestEngine, "_single_probe")
    def test_retest_findings_list_updates_status(self, mock_probe):
        mock_probe.return_value = (500, "Database error: You have an error in your SQL syntax near '''")

        findings = [
            {
                "id": "VULN-003",
                "type": "verbose_error_disclosure",
                "title": "Verbose SQL Error",
                "location": "http://example.com/product?id=1",
                "matched_error": "You have an error in your SQL syntax"
            }
        ]

        results = asyncio.run(self.engine.retest_findings(findings))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "CONFIRMED")
        self.assertEqual(results[0]["retest_successes"], 3)


if __name__ == "__main__":
    unittest.main()
