"""
Unit test suite for Phase 2 Module 2.2: Automated CVSS Scoring & Contextualization (core/contextual_scorer.py).
"""

import os
import tempfile
import unittest

from core.contextual_scorer import parse_cvss_vector, check_exploit_availability, ContextualScorer


class TestModule22Scorer(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_vuln.sqlite")
        self.overrides_path = os.path.join(self.tmp_dir.name, "test_overrides.json")
        self.audit_log_path = os.path.join(self.tmp_dir.name, "test_audit.hashlog")
        self.csv_path = os.path.join(self.tmp_dir.name, "test_exploits.csv")

        # Create test CSV
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write("cve_id,has_public_poc,has_metasploit,source\n")
            f.write("CVE-2023-12345,true,false,GitHub PoC\n")

        self.scorer = ContextualScorer(
            db_path=self.db_path,
            overrides_path=self.overrides_path,
            audit_log_path=self.audit_log_path
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_vector_parsing(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        parsed = parse_cvss_vector(vector)
        self.assertEqual(parsed.get("AV"), "N")
        self.assertEqual(parsed.get("AC"), "L")
        self.assertEqual(parsed.get("C"), "H")

    def test_exploit_availability_lookup(self):
        has_exploit = check_exploit_availability("CVE-2023-12345", csv_path=self.csv_path)
        self.assertTrue(has_exploit)
        no_exploit = check_exploit_availability("CVE-9999-0000", csv_path=self.csv_path)
        self.assertFalse(no_exploit)

    def test_contextual_risk_adjustment(self):
        # Base score 8.5 + 1.5 exploit bonus capped at 10.0
        score = self.scorer.calculate_adjusted_score("CVE-2023-12345", is_critical_asset=True, is_public_facing=True, csv_path=self.csv_path)
        self.assertEqual(score, 10.0)

    def test_custom_override_and_audit_trail(self):
        new_score = self.scorer.apply_override("CVE-2023-12345", 9.9, user="test_admin")
        self.assertEqual(new_score, 9.9)

        # Check audit log file exists and contains hash line
        self.assertTrue(os.path.exists(self.audit_log_path))
        with open(self.audit_log_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("HASH=", content)
            self.assertIn("USER=test_admin", content)
            self.assertIn("CVE=CVE-2023-12345", content)

    def test_formatted_cve_summary(self):
        summary = self.scorer.format_cve_summary("CVE-2023-12345", csv_path=self.csv_path)
        self.assertIn("CVE-2023-12345", summary)
        self.assertIn("CVSS:", summary)
        self.assertIn("Vector:", summary)
        self.assertIn("Public PoC available", summary)


if __name__ == "__main__":
    unittest.main()
