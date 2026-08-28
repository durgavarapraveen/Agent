"""
Unit test suite for Module 1.3: Web Application Advanced Testing & API Security Testing.
"""

import unittest
from core.authorization import TargetScopeValidator
from core.web_advanced import WebAdvancedTester
from core.api_testing import APISecurityTester


class TestModule13WebAndAPITesting(unittest.TestCase):

    def setUp(self):
        TargetScopeValidator.set(TargetScopeValidator(["example.com", "api.example.com", "192.168.1.10"]))
        self.web_tester = WebAdvancedTester(dry_run=True)
        self.api_tester = APISecurityTester(dry_run=True)

    def test_smart_parameter_discovery(self):
        discovered = self.web_tester.crawl_and_fuzz_params("example.com", wordlist_path="common_params.txt")
        self.assertGreaterEqual(len(discovered), 100)
        self.assertIn("parameter", discovered[0])

    def test_benign_polyglot_upload(self):
        findings = self.web_tester.test_benign_polyglot_upload("https://example.com/upload")
        self.assertEqual(len(findings), 2)
        vulns = {f["vulnerability"] for f in findings}
        self.assertIn("Potential RCE via MIME/Extension bypass", vulns)
        self.assertIn("Path Traversal in Filename", vulns)

    def test_zip_bomb_decompress_test(self):
        findings = self.web_tester.test_zip_bomb_decompress("https://example.com/upload-zip")
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Zip Bomb vulnerability")

    def test_ssti_filename_injection(self):
        findings = self.web_tester.test_ssti_filename_injection("https://example.com/upload")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Server-Side Template Injection")

    def test_business_logic_price_tampering(self):
        findings = self.web_tester.test_business_logic_price_tampering("https://example.com/checkout")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Parameter Tampering")

    def test_business_logic_race_condition(self):
        findings = self.web_tester.test_business_logic_race_condition("https://example.com/checkout")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Race Condition")

    def test_business_logic_coupon_abuse(self):
        findings = self.web_tester.test_business_logic_coupon_abuse("https://example.com/checkout")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Coupon Reuse Vulnerability")

    def test_graphql_introspection_and_batching(self):
        findings = self.api_tester.test_graphql_introspection_and_batching("https://api.example.com/graphql")
        self.assertEqual(len(findings), 2)
        vulns = {f["vulnerability"] for f in findings}
        self.assertIn("GraphQL Introspection Enabled", vulns)
        self.assertIn("GraphQL Batch Query DoS", vulns)

    def test_soap_wsdl_xxe_injection(self):
        findings = self.api_tester.test_soap_wsdl_xxe_injection("https://api.example.com/ws")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "XXE Vulnerability")

    def test_grpc_reflection_enumeration(self):
        findings = self.api_tester.test_grpc_reflection_enumeration("api.example.com:50051")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "gRPC Server Reflection Enabled")

    def test_rest_versioning_bypass(self):
        findings = self.api_tester.test_rest_versioning_bypass("https://api.example.com")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Deprecated REST API Version Accessible")


if __name__ == "__main__":
    unittest.main()
