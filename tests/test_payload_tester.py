"""
Unit tests for core/payload_tester.py defensive vulnerability verification module.
"""

import unittest
from unittest.mock import patch, MagicMock
from core.payload_tester import PayloadTester
from core.shared_context import SharedContext



class TestPayloadTester(unittest.TestCase):

    def setUp(self):
        from core.dedup_tracker import DeduplicationTracker
        DeduplicationTracker().reset_all()

    @patch("urllib.request.urlopen")
    def test_unencoded_input_reflection_detected(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"<html><body>Search results for: probe_xss_check_12345</body></html>"
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        tester = PayloadTester()
        finding = tester.test_xss("http://example.com/search", "q")

        self.assertIsNotNone(finding)
        self.assertEqual(finding["type"], "UNENCODED_INPUT_REFLECTION")
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertIn("probe_xss_check_12345", finding["proof"])
        self.assertIn("context-aware output encoding", finding["remediation"])

    @patch("urllib.request.urlopen")
    def test_encoded_input_reflection_not_flagged(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"<html><body>Search results for: probe_xss_check_clean</body></html>"
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        tester = PayloadTester()
        finding = tester.test_xss("http://example.com/search", "q")

        self.assertIsNone(finding)

    @patch("urllib.request.urlopen")
    def test_verbose_sql_error_disclosure_detected(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 500
        mock_resp.read.return_value = b"Database error: You have an error in your SQL syntax near '''"
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        tester = PayloadTester()
        finding = tester.test_sqli("http://example.com/product", "id")

        self.assertIsNotNone(finding)
        self.assertEqual(finding["type"], "VERBOSE_ERROR_DISCLOSURE")
        self.assertEqual(finding["severity"], "LOW")
        self.assertIn("You have an error in your SQL syntax", finding["proof"])
        self.assertIn("Disable detailed database and framework error disclosures", finding["remediation"])

    @patch("urllib.request.urlopen")
    def test_verify_and_report_registers_vulnerabilities(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"Search: probe_xss_check_12345; Error: You have an error in your SQL syntax"
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        ctx = SharedContext("http://example.com")
        tester = PayloadTester()
        findings = tester.verify_and_report(ctx, "http://example.com/search", "q")

        self.assertEqual(len(findings), 2)
        self.assertEqual(len(ctx.vulnerabilities), 2)


if __name__ == "__main__":
    unittest.main()
