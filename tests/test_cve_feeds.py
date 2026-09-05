"""
Unit tests for vuln_intel/feeds.py real-time CVE lookup and exploit intelligence feed module.
"""

import json
import unittest
from unittest.mock import patch, MagicMock

from core.intelligence.vuln_intel.feeds import CVEDatabase
from core.intelligence.vuln_intel.scorer import enrich_finding_with_cve


class TestCVEFeeds(unittest.TestCase):

    def setUp(self):
        self.db = CVEDatabase()

    @patch("urllib.request.urlopen")
    def test_search_cve_for_software_parsing(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        nvd_json = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-12345",
                        "descriptions": [{"lang": "en", "value": "Sample remote code execution flaw."}],
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
                        },
                        "references": [{"url": "https://example.com/cve-2023-12345"}]
                    }
                }
            ]
        }
        mock_response.read.return_value = json.dumps(nvd_json).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        results = self.db.search_cve_for_software("nginx", "1.20.0")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cve_id"], "CVE-2023-12345")
        self.assertEqual(results[0]["cvss_score"], 9.8)
        self.assertEqual(results[0]["description"], "Sample remote code execution flaw.")

    @patch("urllib.request.urlopen")
    def test_in_memory_query_caching(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        nvd_json = {"vulnerabilities": []}
        mock_response.read.return_value = json.dumps(nvd_json).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # First call hits network
        res1 = self.db.search_cve_for_software("apache", "2.4.49")
        # Second call hits in-memory cache
        res2 = self.db.search_cve_for_software("apache", "2.4.49")

        self.assertEqual(res1, res2)
        self.assertEqual(mock_urlopen.call_count, 1)  # Only 1 network request made

    @patch("urllib.request.urlopen")
    def test_cisa_kev_exploit_availability_matching(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        kev_json = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "requiredAction": "Apply updates per vendor instructions.",
                    "shortDescription": "Apache Log4j RCE"
                }
            ]
        }
        mock_response.read.return_value = json.dumps(kev_json).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        exploit_info = self.db.get_exploit_availability("CVE-2021-44228")
        self.assertTrue(exploit_info["has_public_exploit"])
        self.assertIn("CISA", exploit_info["source"])
        self.assertIn("CVE-2021-44228", exploit_info["exploit_url"])

    @patch("urllib.request.urlopen")
    def test_rate_limit_fallback_handling(self, mock_urlopen):
        mock_urlopen.side_effect = Exception("HTTP 429 Too Many Requests")

        results = self.db.search_cve_for_software("wordpress", "6.0")
        self.assertEqual(results, [])

    def test_enrich_finding_with_cve(self):
        mock_db = MagicMock()
        mock_db.search_cve_for_software.return_value = [{
            "cve_id": "CVE-2022-9999",
            "cvss_score": 8.5,
            "description": "Critical flaw"
        }]
        mock_db.get_exploit_availability.return_value = {
            "has_public_exploit": True,
            "source": "CISA KEV"
        }

        finding = {"software": "wordpress", "version": "5.8"}
        enriched = enrich_finding_with_cve(finding, cve_db=mock_db)

        self.assertEqual(enriched["cve"], "CVE-2022-9999")
        self.assertEqual(enriched["cvss_score"], 8.5)
        self.assertTrue(enriched["has_public_exploit"])


if __name__ == "__main__":
    unittest.main()
