"""
Unit test suite for Module 1.4: Cloud Infrastructure Scanner (core/cloud_scanner.py).
"""

import unittest
from core.security.authorization import TargetScopeValidator
from core.intelligence.cloud_scanner import CloudInfrastructureScanner


class TestModule14CloudScanner(unittest.TestCase):

    def setUp(self):
        TargetScopeValidator.set(TargetScopeValidator(["example.com", "192.168.1.1"]))
        self.scanner = CloudInfrastructureScanner(dry_run=True)

    def test_aws_s3_bucket_enumeration(self):
        findings = self.scanner.audit_aws_s3_buckets("testcompany")
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Publicly Readable S3 Bucket")

    def test_aws_iam_policy_analysis(self):
        findings = self.scanner.audit_aws_iam_policies()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Over-permissive IAM Policy")

    def test_aws_imds_v1_check(self):
        findings = self.scanner.simulate_aws_imds_v1_check()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "IMDSv1 Accessible")

    def test_aws_secrets_manager_audit(self):
        findings = self.scanner.audit_aws_secrets_manager()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Secrets Manager Deletion Protection Disabled")

    def test_gcp_cloud_storage_audit(self):
        findings = self.scanner.audit_gcp_cloud_storage("testcompany")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Publicly Accessible GCP Bucket")

    def test_gcp_service_account_key_rotation(self):
        findings = self.scanner.audit_gcp_service_account_keys()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Service Account Key not rotated")

    def test_gcp_iam_conditions_audit(self):
        findings = self.scanner.audit_gcp_iam_conditions()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Missing IAM Policy Condition")

    def test_azure_sas_token_scan(self):
        findings = self.scanner.scan_azure_sas_tokens("https://storage.blob.core.windows.net/data?sig=123&se=2026")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Exposed SAS Token")

    def test_azure_keyvault_firewall_audit(self):
        findings = self.scanner.audit_azure_keyvault_firewall()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Key Vault Public Firewall Exposure")

    def test_azure_managed_identity_check(self):
        findings = self.scanner.simulate_azure_managed_identity_check()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Managed Identity IMDS Endpoint Accessible")


if __name__ == "__main__":
    unittest.main()
