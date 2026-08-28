"""
Unit test verifying capability classification in core/normalizer.py
Covers all known keyword collision and priority issues.
"""

import unittest
from core.normalizer import PlannerResponseNormalizer
from core.schemas import CapabilityType
from core.chain_executor import get_capability_for_vuln


class TestCapabilityClassification(unittest.TestCase):

    # ── Existing collision fixes ──────────────────────────────────────────────

    def test_directory_discovery_priority_over_subdomain(self):
        """Objectives with both 'directories' and 'subdomains' → ENDPOINT_DISCOVERY"""
        objective = "Discover hidden directories and files on the target and its subdomains"
        cap = PlannerResponseNormalizer._infer_capability(objective, {})
        self.assertEqual(cap, CapabilityType.ENDPOINT_DISCOVERY)

    def test_subdomain_enumeration(self):
        """Pure subdomain tasks → DNS_ENUMERATION"""
        objective = "Enumerate subdomains for example.com using subfinder"
        cap = PlannerResponseNormalizer._infer_capability(objective, {})
        self.assertEqual(cap, CapabilityType.DNS_ENUMERATION)

    def test_vulnerability_scanning_priority(self):
        """Nuclei + vuln keywords → VULNERABILITY_SCANNING"""
        objective = "Run nuclei vulnerability scan to detect RCE and SQLi"
        cap = PlannerResponseNormalizer._infer_capability(objective, {})
        self.assertEqual(cap, CapabilityType.VULNERABILITY_SCANNING)

    # ── Issue #1: Port scan on subdomains ────────────────────────────────────

    def test_port_scan_on_subdomains_not_dns(self):
        """'Port scanning on subdomains' → PORT_SCANNING, not DNS_ENUMERATION (Issue #1)"""
        objective = "Perform port scanning on the discovered subdomains (milliseconds, preview.owasp-juice.shop)"
        cap = PlannerResponseNormalizer._infer_capability(objective, {})
        self.assertEqual(cap, CapabilityType.PORT_SCANNING)

    def test_port_scan_explicit(self):
        """Explicit nmap port scan → PORT_SCANNING"""
        objective = "Run nmap TCP scan on target to find open ports and services"
        cap = PlannerResponseNormalizer._infer_capability(objective, {})
        self.assertEqual(cap, CapabilityType.PORT_SCANNING)

    # ── Issue #2: SSRF misclassified as endpoint_discovery ───────────────────

    def test_ssrf_payload_not_endpoint_discovery(self):
        """'SSRF payload testing on endpoint' → VULNERABILITY_SCANNING (Issue #2)"""
        objective = "Perform active SSRF payload testing on endpoint /html to check for server-side request forgery"
        cap = PlannerResponseNormalizer._infer_capability(objective, {})
        self.assertEqual(cap, CapabilityType.VULNERABILITY_SCANNING)

    def test_xss_payload_on_endpoint(self):
        """'XSS payload injection on endpoint' → VULNERABILITY_SCANNING"""
        objective = "Test XSS injection payload on the /search endpoint"
        cap = PlannerResponseNormalizer._infer_capability(objective, {})
        self.assertEqual(cap, CapabilityType.VULNERABILITY_SCANNING)

    # ── Issue #3: VULN_TO_CAPABILITY_MAP no longer maps to invalid values ────

    def test_missing_csp_maps_to_http_analysis(self):
        """'missing_csp' → 'http_analysis' (not 'web_scanning')"""
        self.assertEqual(get_capability_for_vuln("missing_csp"), "http_analysis")

    def test_xss_maps_to_vulnerability_scanning(self):
        """'xss' → 'vulnerability_scanning' (not 'exploits')"""
        self.assertEqual(get_capability_for_vuln("xss"), "vulnerability_scanning")

    def test_sqli_maps_to_vulnerability_scanning(self):
        """'sqli' → 'vulnerability_scanning'"""
        self.assertEqual(get_capability_for_vuln("sqli"), "vulnerability_scanning")

    def test_auth_bypass_maps_to_authentication_testing(self):
        """'auth_bypass' → 'authentication_testing'"""
        self.assertEqual(get_capability_for_vuln("auth_bypass"), "authentication_testing")

    def test_unknown_vuln_fallback(self):
        """Unknown vuln type falls back to 'vulnerability_scanning'"""
        self.assertEqual(get_capability_for_vuln("unknown_vuln_xyz"), "vulnerability_scanning")

    def test_none_safe_vuln_lookup(self):
        """None/empty vuln_type returns fallback gracefully"""
        self.assertEqual(get_capability_for_vuln(""), "vulnerability_scanning")

    def test_all_map_values_are_valid_capabilities(self):
        """Every value in VULN_TO_CAPABILITY_MAP must be a valid CapabilityType value"""
        from core.chain_executor import VULN_TO_CAPABILITY_MAP
        valid = {c.value for c in CapabilityType}
        for vuln, cap in VULN_TO_CAPABILITY_MAP.items():
            self.assertIn(cap, valid, f"Invalid capability '{cap}' for vuln_type '{vuln}'")


if __name__ == "__main__":
    unittest.main()
