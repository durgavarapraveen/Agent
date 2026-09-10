
import base64
import os
import re
import logging
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

# NOTE: The previous hardcoded fallback constant has been removed. Any deployment
# that reaches `get_encryption_key` without ENCRYPTION_KEY / ENCRYPTION_KEY_CURRENT
# set will now hard-fail, which is the correct behavior — a hardcoded default is
# equivalent to no encryption at all (anyone with the source can decrypt).
#
# For local development, set:
#     ANTIGRAVITY_ENV=development ENCRYPTION_KEY_DEV_UNSAFE=1
# and a per-machine dev key is auto-generated at `.antigravity/dev_encryption_key`.

MASKING_PATTERNS = {
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "ip": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    "credit_card": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
    "aws_key": r'\b(AKIA)[A-Z0-9]+?([A-Z0-9]{7})\b'
}


class EncryptionKeyMissingError(RuntimeError):
    pass

def _load_or_create_dev_key() -> bytes:
    import secrets
    from pathlib import Path
    _repo_root = Path(__file__).resolve().parents[2]
    key_path = _repo_root / ".antigravity" / "dev_encryption_key"
    if key_path.exists():
        try:
            data = base64.b64decode(key_path.read_text().strip())
            if len(data) == 32:
                return data
        except Exception:
            pass  # fall through and regenerate
    key = secrets.token_bytes(32)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(base64.b64encode(key).decode("ascii"))
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass  # Windows
    logger.warning(
        "DEV MODE: auto-generated encryption key at %s. Never deploy this key.",
        key_path)
    return key


def get_encryption_key(env_var_name: str = "ENCRYPTION_KEY") -> bytes:
    key_str = os.getenv(env_var_name) or os.getenv("ENCRYPTION_KEY_CURRENT")
    if not key_str:
        env_mode = os.getenv("ANTIGRAVITY_ENV", "development").strip().lower()
        dev_ok = os.getenv("ENCRYPTION_KEY_DEV_UNSAFE", "").strip() == "1"
        if env_mode not in ("production", "prod") and dev_ok:
            return _load_or_create_dev_key()
        raise EncryptionKeyMissingError(
            f"{env_var_name} is not set. Generate one with: "
            "python -c 'import secrets,base64; "
            "print(base64.b64encode(secrets.token_bytes(32)).decode())'  "
            "and export ENCRYPTION_KEY=<value>. "
            "For local dev only, set ENCRYPTION_KEY_DEV_UNSAFE=1 to auto-generate "
            "a per-machine dev key (never use in production).")

    try:
        # Try base64 decode first
        # ensure proper padding for base64
        padded = key_str + "=" * ((4 - len(key_str) % 4) % 4)
        decoded = base64.b64decode(padded)
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
        # Pad to 32 bytes (backwards-compat for existing short keys)
        return raw_bytes.ljust(32, b"0")


def encrypt(data: bytes, key: Optional[bytes] = None) -> bytes:
    if not isinstance(data, bytes):
        data = str(data).encode("utf-8")

    k = key or get_encryption_key()
    aesgcm = AESGCM(k)
    nonce = os.urandom(12)  # 12-byte GCM nonce
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt(encrypted_data: bytes, key: Optional[bytes] = None) -> bytes:
    if len(encrypted_data) < 28:
        raise ValueError("Invalid encrypted data length (minimum 28 bytes required).")

    k = key or get_encryption_key()
    aesgcm = AESGCM(k)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def re_encrypt_data(encrypted_data: bytes, old_key: bytes, new_key: bytes) -> bytes:
    plaintext = decrypt(encrypted_data, key=old_key)
    return encrypt(plaintext, key=new_key)


def encrypt_finding_value(value: str, key: Optional[bytes] = None) -> bytes:
    return encrypt(value.encode("utf-8"), key=key)


def decrypt_finding_value(blob: bytes, key: Optional[bytes] = None) -> str:
    return decrypt(blob, key=key).decode("utf-8", errors="ignore")


def mask_sensitive(text: str) -> str:
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
