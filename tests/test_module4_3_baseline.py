"""
Unit test suite for Phase 4 Module 4.3: Baseline Normalization (core/baseline.py).
"""

import json
import os
import tempfile
import unittest

from core.baseline import BaselineManager, sha256_hash


class TestModule43Baseline(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_baseline.sqlite")
        self.whitelist_path = os.path.join(self.tmp_dir.name, "test_whitelist.json")

        whitelist_content = [
            {"port": 22, "reason": "management SSH"},
            {"url": "https://example.com/health", "reason": "health endpoint"}
        ]
        with open(self.whitelist_path, "w", encoding="utf-8") as f:
            json.dump(whitelist_content, f)

        self.manager = BaselineManager(db_path=self.db_path, whitelist_file=self.whitelist_path)

    def tearDown(self):
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_sha256_hashing(self):
        h = sha256_hash("test_response_data")
        self.assertEqual(len(h), 16)

    def test_whitelist_filtering(self):
        f1 = {"port": 22, "title": "SSH Port"}
        self.assertTrue(self.manager.is_whitelisted(f1))

        f2 = {"url": "https://example.com/health", "title": "Health endpoint"}
        self.assertTrue(self.manager.is_whitelisted(f2))

        f3 = {"port": 8080, "title": "Dev web server"}
        self.assertFalse(self.manager.is_whitelisted(f3))

    def test_baseline_capture_and_noise_filtering(self):
        findings = [
            {"port": 80, "banner": "Apache/2.4.49", "status_code": 200},
            {"port": 443, "banner": "Nginx/1.21.0", "status_code": 200}
        ]
        # First scan mode: capture baseline
        cnt = self.manager.capture_baseline("scan_001", "192.168.1.10", findings)
        self.assertEqual(cnt, 2)

        # Subsequent scan with identical findings + 1 whitelisted + 1 new change
        subsequent = [
            {"port": 80, "banner": "Apache/2.4.49", "status_code": 200},  # Exact baseline match (Noise)
            {"port": 22, "title": "SSH Port"},                           # Whitelisted
            {"port": 8080, "banner": "Tomcat/9.0", "status_code": 200}     # New change
        ]

        filtered, stats = self.manager.filter_noise_and_detect_drift("192.168.1.10", subsequent)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["port"], 8080)
        self.assertEqual(stats["noise_filtered"], 2)

    def test_drift_detection_alert(self):
        findings = [{"port": p, "banner": f"Service-{p}"} for p in range(10)]
        self.manager.capture_baseline("scan_001", "10.0.0.1", findings)

        # 5 new ports opened vs 10 baseline -> 50% drift ratio > 20%
        new_scan = [{"port": p + 100, "banner": f"NewService-{p}"} for p in range(5)]
        filtered, stats = self.manager.filter_noise_and_detect_drift("10.0.0.1", new_scan)

        self.assertTrue(stats["drift_alert"])
        self.assertIn("DRIFT_ALERT", stats["drift_message"])


if __name__ == "__main__":
    unittest.main()
