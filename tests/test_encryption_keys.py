"""Tests for Phase 0.1: encryption key generation and startup checks."""

import base64
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]


class TestGenerateKeysScript:
    def test_stdout_produces_valid_base64_key(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate_keys.py"), "--stdout"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        key_b64 = result.stdout.strip()
        raw = base64.b64decode(key_b64)
        assert len(raw) == 32

    def test_stdout_keys_are_unique(self):
        keys = set()
        for _ in range(5):
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "generate_keys.py"), "--stdout"],
                capture_output=True, text=True, timeout=10,
            )
            keys.add(result.stdout.strip())
        assert len(keys) == 5


class TestEncryptionKeyLoading:
    def test_base64_key_loads(self):
        from core.security.encryption import get_encryption_key
        key_bytes = os.urandom(32)
        key_b64 = base64.b64encode(key_bytes).decode("ascii")
        with mock.patch.dict(os.environ, {"ENCRYPTION_KEY": key_b64}):
            loaded = get_encryption_key()
        assert loaded == key_bytes

    def test_encrypt_decrypt_roundtrip_with_base64_key(self):
        from core.security.encryption import encrypt, decrypt
        key_bytes = os.urandom(32)
        key_b64 = base64.b64encode(key_bytes).decode("ascii")
        with mock.patch.dict(os.environ, {"ENCRYPTION_KEY": key_b64}):
            plaintext = b"sensitive vulnerability data"
            ct = encrypt(plaintext)
            assert decrypt(ct) == plaintext


class TestStartupDiagnosticsKeyCheck:
    def test_insecure_key_warns_in_dev(self):
        from core.common.startup_diagnostics import _check_encryption_key
        env = {
            "ENCRYPTION_KEY": "ANTIGRAVITY_MASTER_KEY_32BYTES_LONG!",
            "ANTIGRAVITY_ENV": "development",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            _check_encryption_key()

    def test_insecure_key_exits_in_production(self):
        from core.common.startup_diagnostics import _check_encryption_key
        env = {
            "ENCRYPTION_KEY": "ANTIGRAVITY_MASTER_KEY_32BYTES_LONG!",
            "ANTIGRAVITY_ENV": "production",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            with pytest.raises(SystemExit):
                _check_encryption_key()

    def test_placeholder_key_exits_in_production(self):
        from core.common.startup_diagnostics import _check_encryption_key
        env = {
            "ENCRYPTION_KEY": "CHANGE_ME_RUN_generate_keys",
            "ANTIGRAVITY_ENV": "production",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            with pytest.raises(SystemExit):
                _check_encryption_key()

    def test_valid_key_passes(self):
        from core.common.startup_diagnostics import _check_encryption_key
        key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
        env = {
            "ENCRYPTION_KEY": key_b64,
            "ENCRYPTION_KEY_CURRENT": key_b64,
            "ANTIGRAVITY_ENV": "production",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            _check_encryption_key()
