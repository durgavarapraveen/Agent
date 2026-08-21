"""Unit tests for vuln_intel.scorer composite risk scoring."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vuln_intel.scorer import (compute_score, score_cve, severity_from_score,
                               W_CVSS, W_EPSS, W_KEV)


class TestScorer(unittest.TestCase):

    def test_all_max_signals(self):
        # CVSS 10, EPSS 1.0, KEV True -> full 100
        self.assertEqual(compute_score(10.0, 1.0, True), 100.0)

    def test_all_zero_signals(self):
        self.assertEqual(compute_score(0.0, 0.0, False), 0.0)

    def test_weighting(self):
        # Only CVSS maxed -> 0.3 * 100
        self.assertAlmostEqual(compute_score(10.0, 0.0, False), W_CVSS * 100, places=1)
        # Only EPSS maxed -> 0.4 * 100
        self.assertAlmostEqual(compute_score(0.0, 1.0, False), W_EPSS * 100, places=1)
        # Only KEV -> 0.3 * 100
        self.assertAlmostEqual(compute_score(0.0, 0.0, True), W_KEV * 100, places=1)

    def test_clamping(self):
        # Out-of-range inputs clamp, not overflow
        self.assertEqual(compute_score(99.0, 5.0, True), 100.0)
        self.assertEqual(compute_score(-3.0, -1.0, False), 0.0)

    def test_severity_bands(self):
        self.assertEqual(severity_from_score(95), "CRITICAL")
        self.assertEqual(severity_from_score(70), "HIGH")
        self.assertEqual(severity_from_score(40), "MEDIUM")
        self.assertEqual(severity_from_score(10), "LOW")
        self.assertEqual(severity_from_score(0), "INFO")

    def test_score_cve_verdict(self):
        v = score_cve("CVE-2021-23337", cvss_base=7.2, epss=0.42,
                      kev=True, cvss_vector="CVSS:3.1/AV:N/AC:H")
        self.assertEqual(v.cve_id, "CVE-2021-23337")
        self.assertTrue(v.kev_match)
        self.assertEqual(v.epss_percentile, 0.42)
        # components sum ~ score
        comp_sum = sum(v.components.values())
        self.assertAlmostEqual(comp_sum, v.score, delta=0.2)

    def test_kev_pushes_severity_up(self):
        low = score_cve("CVE-X", cvss_base=4.0, epss=0.01, kev=False).score
        high = score_cve("CVE-X", cvss_base=4.0, epss=0.01, kev=True).score
        self.assertGreater(high, low)


if __name__ == "__main__":
    unittest.main()
