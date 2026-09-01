"""
Unit test suite for Phase 2 Module 2.4: Patch Management Intelligence & VulnerabilityIntelligence Orchestrator.
"""

import os
import tempfile
import unittest

from core.security.authorization import TargetScopeValidator
from core.intelligence.patch_tracker import PatchTracker
from core.intelligence.vulnerability_intelligence import VulnerabilityIntelligence


class TestModule24PatchIntel(unittest.TestCase):

    def setUp(self):
        TargetScopeValidator.set(TargetScopeValidator(["192.168.1.10", "example.com"]))
        self.patch_tracker = PatchTracker()
        self.tmp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite")
        self.tmp_db.close()
        self.master_intel = VulnerabilityIntelligence(db_path=self.tmp_db.name, offline_mode=True)

    def tearDown(self):
        try:
            if os.path.exists(self.tmp_db.name):
                os.unlink(self.tmp_db.name)
        except Exception:
            pass

    def test_patch_availability_detector(self):
        patch_info = self.patch_tracker.get_patch_status("CVE-2021-44228", running_version="2.14.0", published_date_str="2021-12-10")
        self.assertTrue(patch_info["patch_available"])
        self.assertEqual(patch_info["fixed_version"], "2.15.0")
        self.assertEqual(patch_info["patch_status"], "MISSING")
        self.assertGreater(patch_info["days_since_release"], 365)
        self.assertIn("1+ year old vulnerability", patch_info["flags"])

    def test_workaround_suggestion(self):
        workaround = self.patch_tracker.get_workaround("CVE-2021-44228")
        self.assertIn("Workaround Suggestion:", workaround)
        self.assertIn("-Dlog4j2.formatMsgNoLookups=true", workaround)

        no_workaround = self.patch_tracker.get_workaround("CVE-9999-0000")
        self.assertEqual(no_workaround, "No known workaround - apply patch immediately.")

    def test_patch_urgency_score_calculation(self):
        urgency = self.patch_tracker.compute_patch_urgency(cvss_base=9.8, days_since_patch=400, public_exploit_exists=True)
        self.assertGreaterEqual(urgency, 90.0)
        self.assertLessEqual(urgency, 100.0)

    def test_master_vulnerability_intelligence_orchestrator(self):
        findings = self.master_intel.correlate(service_name="apache httpd", version="2.4.49", target_ip="192.168.1.10", target_port=80)
        self.assertGreaterEqual(len(findings), 1)
        first = findings[0]
        self.assertIn("cve_id", first)
        self.assertIn("adjusted_cvss_score", first)
        self.assertIn("manual_cmd", first)
        self.assertIn("patch_urgency_score", first)
        self.assertIn("workaround", first)


if __name__ == "__main__":
    unittest.main()
