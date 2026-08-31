"""
Phase 6 Module 6.4: Encryption at Rest & Crypto Engine (core/encryption.py)

AES-256-GCM authenticated encryption/decryption, environment key management,
key rotation, transparent database BLOB encryption, and PII masking.
"""

import base64
import os
import re
import logging
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

# Master key fallback if environment variable is not set
DEFAULT_FALLBACK_KEY_RAW = b"ANTIGRAVITY_DEFAULT_KEY_32BYTES!"

MASKING_PATTERNS = {
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "ip": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    "credit_card": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
    "aws_key": r'\b(AKIA)[A-Z0-9]+?([A-Z0-9]{7})\b'
}


def get_encryption_key(env_var_name: str = "ENCRYPTION_KEY") -> bytes:
    """
    Load 256-bit (32 bytes) master key from environment variable.
    Supports raw strings or base64-encoded strings.
    """
    key_str = os.getenv(env_var_name) or os.getenv("ENCRYPTION_KEY_CURRENT")
    if not key_str:
        return DEFAULT_FALLBACK_KEY_RAW

    try:
        # Try base64 decode first
        decoded = base64.b64decode(key_str)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass

    raw_bytes = key_str.encode("utf-8")
    if len(raw_bytes) == 32:
        return raw_bytes
    elif len(raw_bytes) > 32:
        return raw_bytes[:32]
    else:
        # Pad to 32 bytes
        return raw_bytes.ljust(32, b"0")


def encrypt(data: bytes, key: Optional[bytes] = None) -> bytes:
    """
    AES-256-GCM authenticated encryption:
      - 12-byte random nonce
      - Ciphertext + 16-byte authentication tag
    Returns nonce + ciphertext_with_tag concatenated.
    """
    if not isinstance(data, bytes):
        data = str(data).encode("utf-8")

    k = key or get_encryption_key()
    aesgcm = AESGCM(k)
    nonce = os.urandom(12)  # 12-byte GCM nonce
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt(encrypted_data: bytes, key: Optional[bytes] = None) -> bytes:
    """
    AES-256-GCM decryption:
      - Split nonce (first 12 bytes) and ciphertext_with_tag
    """
    if len(encrypted_data) < 28:
        raise ValueError("Invalid encrypted data length (minimum 28 bytes required).")

    k = key or get_encryption_key()
    aesgcm = AESGCM(k)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def re_encrypt_data(encrypted_data: bytes, old_key: bytes, new_key: bytes) -> bytes:
    """
    Decrypt data using old_key and re-encrypt using new_key (Key Rotation).
    """
    plaintext = decrypt(encrypted_data, key=old_key)
    return encrypt(plaintext, key=new_key)


def encrypt_finding_value(value: str, key: Optional[bytes] = None) -> bytes:
    """Transparent application-layer encryption wrapper for database BLOB columns."""
    return encrypt(value.encode("utf-8"), key=key)


def decrypt_finding_value(blob: bytes, key: Optional[bytes] = None) -> str:
    """Transparent application-layer decryption wrapper for database BLOB columns."""
    return decrypt(blob, key=key).decode("utf-8", errors="ignore")


def mask_sensitive(text: str) -> str:
    """
    PII Redaction Engine:
    Replaces matched emails, credit cards, IPs, and AWS keys using MASKING_PATTERNS.
    """
    if not text:
        return ""
    s = str(text)

    # Emails
    def _mask_email(m):
        e = m.group(0)
        parts = e.split("@")
        name = parts[0]
        domain = parts[1]
        if len(name) <= 2:
            m_name = name[0] + "*"
        else:
            m_name = name[0] + "*" * (len(name) - 2) + name[-1]
        return f"{m_name}@{domain}"

    s = re.sub(MASKING_PATTERNS["email"], _mask_email, s)

    # Credit cards
    def _mask_cc(m):
        cc = m.group(0)
        return "****" * 3 + cc[-4:]

    s = re.sub(MASKING_PATTERNS["credit_card"], _mask_cc, s)

    # AWS Keys
    s = re.sub(MASKING_PATTERNS["aws_key"], r'\1************\2', s)

    # IP addresses
    def _mask_ip(m):
        ip = m.group(0)
        octs = ip.split(".")
        if len(octs) == 4:
            return f"{octs[0]}.{octs[1]}.*.*"
        return ip

    s = re.sub(MASKING_PATTERNS["ip"], _mask_ip, s)

    return s
