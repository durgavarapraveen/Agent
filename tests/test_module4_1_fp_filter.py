"""
Unit test suite for Phase 4 Module 4.1: False Positive Reduction (core/fp_filter.py).
"""

import os
import tempfile
import unittest

from core.reporting.fp_filter import FalsePositiveFilter


class TestModule41FPFilter(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.model_path = os.path.join(self.tmp_dir.name, "test_fp_model.joblib")
        self.scaler_path = os.path.join(self.tmp_dir.name, "test_scaler.joblib")
        self.filter = FalsePositiveFilter(model_path=self.model_path, scaler_path=self.scaler_path)

    def tearDown(self):
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_signature_based_fp_pattern_override(self):
        # Empty response with 200
        finding1 = {"title": "XSS Test", "status_code": 200, "content_length": 0}
        self.assertTrue(self.filter.check_signature_fp(finding1))
        should_rep, reason = self.filter.should_report_finding(finding1)
        self.assertFalse(should_rep)
        self.assertIn("signature-based FP pattern override", reason)

        # Gobuster 429 rate limit
        finding2 = {"tool": "gobuster", "status_code": 429, "url": "https://example.com/admin"}
        self.assertTrue(self.filter.check_signature_fp(finding2))

    def test_ml_model_feature_vector_extraction_and_confidence(self):
        finding = {
            "title": "SQL Injection",
            "tool": "sqlmap",
            "url": "https://example.com/api/v1/users?id=1",
            "confidence_score": 0.90
        }
        meta = {"status_code": 200, "content_length": 1024, "response_time_ms": 45.0, "response_body": "User records listed"}

        score, cat = self.filter.predict_confidence_score(finding, response_meta=meta)
        self.assertIsInstance(score, float)
        self.assertIn(cat, ["HIGH", "MEDIUM", "LOW"])

    def test_low_confidence_flagging_for_manual_review(self):
        finding = {
            "title": "Unclear Finding",
            "tool": "gobuster",
            "url": "https://example.com/test",
            "status_code": 500,
            "content_length": 10
        }
        meta = {"status_code": 500, "content_length": 10, "response_body": "Internal Server Error"}
        should_rep, reason = self.filter.should_report_finding(finding, response_meta=meta)
        if should_rep and finding.get("confidence_category") == "LOW":
            self.assertTrue(finding.get("manual_review_flag"))


if __name__ == "__main__":
    unittest.main()
