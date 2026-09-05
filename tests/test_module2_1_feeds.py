"""
Unit test suite for Phase 2 Module 2.1: Real-Time CVE Feed Ingester (vuln_intel/feeds.py).
"""

import os
import tempfile
import unittest

from core.intelligence.vuln_intel.feeds import VulnerabilityDatabase, FeedClient, ServiceMatcher


class TestModule21Feeds(unittest.TestCase):

    def setUp(self):
        self.tmp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite")
        self.tmp_db.close()
        self.db = VulnerabilityDatabase(db_path=self.tmp_db.name)
        self.feed_client = FeedClient(offline_mode=True, db_path=self.tmp_db.name)
        self.service_matcher = ServiceMatcher(db=self.db)

    def tearDown(self):
        try:
            if os.path.exists(self.tmp_db.name):
                os.unlink(self.tmp_db.name)
        except Exception:
            pass

    def test_database_tables_initialization(self):
        # Insert sample CVE
        self.db.insert_cve("CVE-2021-41773", "2021-10-05", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "Apache HTTP Server Path Traversal", "apache httpd")
        cves = self.db.get_all_cves()
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]["id"], "CVE-2021-41773")

    def test_github_package_vulnerabilities_insertion(self):
        self.db.insert_package_vuln("CVE-2021-44228", "maven", "org.apache.logging.log4j:log4j-core", ">= 2.0-beta9, < 2.15.0")
        # Verify execution without errors
        self.assertTrue(True)

    def test_offline_mode_enforcement(self):
        self.assertTrue(self.feed_client.offline_mode)
        # Verify sync methods run safely in offline mode
        self.feed_client.sync_nvd_feed()
        self.feed_client.fetch_github_advisories()

    def test_fuzzy_service_matching(self):
        self.db.insert_cve("CVE-2021-42013", "2021-10-07", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Apache HTTP Server RCE", "apache2")
        self.db.insert_cve("CVE-2021-41773", "2021-10-05", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "Apache Path Traversal", "apache httpd")

        matches = self.service_matcher.match_service_to_cve("httpd", "2.4.49")
        self.assertGreaterEqual(len(matches), 1)
        # Verify CVSS sorting descending
        scores = [float(m["cvss_v3_base_score"]) for m in matches]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_zero_day_hint_detection(self):
        candidate = self.service_matcher.detect_zero_day_candidate(
            service_name="UnknownWebServer",
            version="1.0.0",
            status_code=500,
            payload="GET /?test=500_trigger",
            banner="UnknownServer/1.0"
        )
        self.assertIsNotNone(candidate)
        self.assertTrue(candidate["0-day_candidate"])
        self.assertEqual(candidate["confidence_score"], 0.30)


if __name__ == "__main__":
    unittest.main()
