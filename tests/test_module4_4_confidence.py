"""
Unit test suite for Phase 4 Module 4.4: Confidence Calibration & QualityGate Orchestrator.
"""

import os
import tempfile
import unittest

from core.security.authorization import TargetScopeValidator
from core.validation.confidence import ConfidenceCalibrator
from core.reporting.quality_gate import QualityGate


class TestModule44Confidence(unittest.TestCase):

    def setUp(self):
        TargetScopeValidator.set(TargetScopeValidator(["example.com", "127.0.0.1"]))
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_conf.sqlite")
        self.calibrator = ConfidenceCalibrator(db_path=self.db_path)
        self.quality_gate = QualityGate(db_path=self.db_path)

    def tearDown(self):
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_base_confidence_matrix_and_dynamic_modifiers(self):
        finding = {
            "type": "SQLI_ERROR_BASED",
            "title": "SQL Injection",
            "waf_detected": True,                # -20%
            "public_exploit_available": True,   # +10%
            "reproducibility_status": "REPRODUCIBLE" # +5%
        }
        calibrated = self.calibrator.calibrate(finding)
        # base=0.95, modifiers = -0.20 + 0.10 + 0.05 = -0.05
        # adj = 0.95 * 0.95 = 0.9025 -> 0.90
        self.assertEqual(calibrated["confidence_score"], 0.90)
        self.assertTrue(calibrated["auto_accepted"])

    def test_historical_fp_penalty_learning(self):
        finding_type = "XSS_REFLECTED"
        # Log 5 FP verdicts for XSS_REFLECTED
        for _ in range(5):
            self.calibrator.record_fp_verdict(finding_type, 0.60, "FP")

        penalty = self.calibrator.get_historical_fp_penalty(finding_type)
        self.assertEqual(penalty, -0.15)

        finding = {"type": "XSS_REFLECTED", "title": "XSS"}
        calibrated = self.calibrator.calibrate(finding)
        # base=0.60, modifier = -0.15 -> 0.60 * 0.85 = 0.51
        self.assertEqual(calibrated["confidence_score"], 0.51)
        self.assertFalse(calibrated["auto_accepted"])
        self.assertIn("Manual review recommended", calibrated["review_recommendation"])

    def test_master_quality_gate_pipeline(self):
        raw_findings = [
            {"title": "Valid SQLi", "type": "SQLI_ERROR_BASED", "url": "https://example.com/api?id=1", "status_code": 200, "content_length": 1024},
            {"title": "Empty Response FP", "status_code": 200, "content_length": 0}  # Should be rejected by FP rules
        ]

        result = self.quality_gate.process_findings("scan_100", "example.com", raw_findings, first_scan_mode=True)
        self.assertEqual(result["fp_rejected_count"], 1)
        self.assertEqual(len(result["final_findings"]), 1)
        self.assertTrue(result["final_findings"][0]["auto_accepted"])


if __name__ == "__main__":
    unittest.main()
