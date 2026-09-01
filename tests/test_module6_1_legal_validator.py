"""
Unit tests for Phase 6 Module 6.1: Automated Legal Validator (core/legal_validator.py)
"""

import os
import unittest
from core.security.legal_validator import LegalValidator, ScopeViolationException


class TestModule6_1_LegalValidator(unittest.TestCase):

    def setUp(self):
        self.db_path = "data/test_legal_scopes.sqlite"
        self.audit_path = "data/test_legal_audit.jsonl"
        for p in [self.db_path, self.audit_path]:
            if os.path.exists(p):
                os.remove(p)
        self.validator = LegalValidator(db_path=self.db_path, audit_log_path=self.audit_path)

    def tearDown(self):
        import gc
        del self.validator
        gc.collect()
        for p in [self.db_path, self.audit_path]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass

    def test_add_scope_and_validate_target_pass(self):
        """Verify target IP and domain validation within authorized scope."""
        self.validator.add_authorized_scope(cidr="10.0.0.0/24", domain="example.com")
        self.assertTrue(self.validator.validate_target("10.0.0.5", target_domain="sub.example.com"))

    def test_validate_target_fail_raises_scope_violation(self):
        """Verify out-of-scope target IP raises ScopeViolationException."""
        self.validator.add_authorized_scope(cidr="10.0.0.0/24", domain="example.com")
        with self.assertRaises(ScopeViolationException):
            self.validator.validate_target("192.168.1.1", target_domain="unauthorized.org")

    def test_contract_expiration_and_force_override(self):
        """Verify expired SOW raises exception unless force_expired=True."""
        # Expired yesterday
        self.validator.add_authorized_scope(cidr="10.0.0.0/24", expiry_date="2020-01-01")
        with self.assertRaises(ScopeViolationException):
            self.validator.validate_target("10.0.0.5")

        # Override with force_expired=True
        self.assertTrue(self.validator.validate_target("10.0.0.5", force_expired=True))

    def test_parse_authorization_document_text(self):
        """Verify SOW text document parsing for CIDRs and domains."""
        doc_path = "data/test_sow.txt"
        with open(doc_path, "w", encoding="utf-8") as f:
            f.write("Statement of Work\nTarget scope: 172.16.0.0/16 and target.test domain.\nSigning: 2026-01-01 Expiry: 2030-12-31")

        try:
            res = self.validator.parse_authorization_document(doc_path)
            self.assertIn("172.16.0.0/16", res["cidrs"])
            self.assertIn("target.test", res["domains"])

            # Verify target validation against parsed doc
            self.assertTrue(self.validator.validate_target("172.16.2.10", target_domain="api.target.test"))
        finally:
            if os.path.exists(doc_path):
                os.remove(doc_path)


if __name__ == "__main__":
    unittest.main()
