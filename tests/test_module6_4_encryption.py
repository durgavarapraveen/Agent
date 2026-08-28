"""
Unit tests for Phase 6 Module 6.4: Encryption at Rest (core/encryption.py)
"""

import os
import unittest
from core.encryption import (
    encrypt,
    decrypt,
    re_encrypt_data,
    encrypt_finding_value,
    decrypt_finding_value,
    mask_sensitive
)


class TestModule6_4_Encryption(unittest.TestCase):

    def test_aes_256_gcm_encrypt_decrypt(self):
        """Verify AES-256-GCM authenticated encryption and decryption."""
        data = b"Sensitive Security Finding Payload"
        encrypted = encrypt(data)
        self.assertNotEqual(data, encrypted)
        self.assertTrue(len(encrypted) > 28)

        decrypted = decrypt(encrypted)
        self.assertEqual(data, decrypted)

    def test_key_rotation(self):
        """Verify re_encrypt_data decrypts with old key and re-encrypts with new key."""
        old_key = b"OLD_SECRET_KEY_32BYTES_LONG_KEY!"
        new_key = b"NEW_SECRET_KEY_32BYTES_LONG_KEY!"

        original = b"Confidential DB Field"
        enc_old = encrypt(original, key=old_key)

        # Re-encrypt with new key
        enc_new = re_encrypt_data(enc_old, old_key=old_key, new_key=new_key)

        # Decrypt with new key
        decrypted = decrypt(enc_new, key=new_key)
        self.assertEqual(original, decrypted)

    def test_transparent_db_wrapper(self):
        """Verify application-layer SQLite BLOB encryption wrapper."""
        val = "SQLi Payload: ' OR 1=1 --"
        blob = encrypt_finding_value(val)
        self.assertIsInstance(blob, bytes)

        recovered = decrypt_finding_value(blob)
        self.assertEqual(val, recovered)

    def test_mask_sensitive_pii(self):
        """Verify PII redaction engine masking emails, IPs, credit cards, and AWS keys."""
        text = "Found AKIA1234567890EXAMPLE and admin@company.com with IP 10.0.0.1 and card 4111111111111111"
        masked = mask_sensitive(text)

        self.assertNotIn("AKIA1234567890EXAMPLE", masked)
        self.assertIn("AKIA************EXAMPLE", masked)
        self.assertIn("a***n@company.com", masked)
        self.assertIn("10.0.*.*", masked)
        self.assertIn("1111", masked)


if __name__ == "__main__":
    unittest.main()
