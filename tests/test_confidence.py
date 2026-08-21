"""Unit tests for validation.confidence scoring."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validation.confidence import (assess, assess_finding, gate,
                                    HIGH, MEDIUM, LOW,
                                    W_VERSION_MATCH, W_REACHABLE, W_EPSS, W_KEV)


class TestConfidence(unittest.TestCase):

    def test_all_signals_high(self):
        v = assess(version_match_exact=True, reachable=True, epss=0.5, kev_match=True)
        self.assertEqual(v.score, W_VERSION_MATCH + W_REACHABLE + W_EPSS + W_KEV)
        self.assertEqual(v.level, HIGH)
        self.assertFalse(v.needs_review)
        self.assertEqual(len(v.evidence), 4)

    def test_no_signals_low(self):
        v = assess()
        self.assertEqual(v.score, 0)
        self.assertEqual(v.level, LOW)
        self.assertTrue(v.needs_review)

    def test_medium_band(self):
        # version match (40) + epss>0.1 (15) = 55 -> MEDIUM
        v = assess(version_match_exact=True, epss=0.2)
        self.assertEqual(v.score, W_VERSION_MATCH + W_EPSS)
        self.assertEqual(v.level, MEDIUM)

    def test_epss_threshold_exclusive(self):
        # exactly 0.1 does NOT count (> 0.1 required)
        v = assess(epss=0.1)
        self.assertEqual(v.score, 0)
        v2 = assess(epss=0.11)
        self.assertEqual(v2.score, W_EPSS)

    def test_high_threshold_boundary(self):
        # reachable(30)+version(40)=70 -> HIGH (>=70)
        v = assess(version_match_exact=True, reachable=True)
        self.assertEqual(v.score, 70)
        self.assertEqual(v.level, HIGH)

    def test_assess_finding_keys(self):
        f = {"exact_version_match": True, "reachable_status": "reachable",
             "epss_percentile": 0.3, "kev_match": False}
        v = assess_finding(f)
        # 40 + 30 + 15 = 85
        self.assertEqual(v.score, 85)
        self.assertEqual(v.level, HIGH)

    def test_gate_routes_low_to_review(self):
        findings = [
            {"id": "A", "version_match_exact": True, "reachable": True},  # 70 HIGH
            {"id": "B"},                                                  # 0 LOW
        ]
        out = gate(findings)
        ids_report = {f["id"] for f in out["report"]}
        ids_review = {f["id"] for f in out["needs_review"]}
        self.assertIn("A", ids_report)
        self.assertIn("B", ids_review)
        # evidence attached
        self.assertIn("_confidence", findings[0])


if __name__ == "__main__":
    unittest.main()
