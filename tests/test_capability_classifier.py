"""
Unit test verifying capability classification in core/normalizer.py
"""

import unittest
from core.normalizer import PlannerResponseNormalizer
from core.schemas import CapabilityType


class TestCapabilityClassification(unittest.TestCase):

    def test_directory_discovery_priority_over_subdomain(self):
        objective = "Discover hidden directories and files on the target and its subdomains"
        cap = PlannerResponseNormalizer._infer_capability(objective, {})
        self.assertEqual(cap, CapabilityType.ENDPOINT_DISCOVERY)

    def test_subdomain_enumeration(self):
        objective = "Enumerate subdomains for example.com using subfinder"
        cap = PlannerResponseNormalizer._infer_capability(objective, {})
        self.assertEqual(cap, CapabilityType.DNS_ENUMERATION)

    def test_vulnerability_scanning_priority(self):
        objective = "Run nuclei vulnerability scan to detect RCE and SQLi"
        cap = PlannerResponseNormalizer._infer_capability(objective, {})
        self.assertEqual(cap, CapabilityType.VULNERABILITY_SCANNING)


if __name__ == "__main__":
    unittest.main()
