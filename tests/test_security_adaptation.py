import json
import os
import pytest
import tempfile
from pathlib import Path
from core.security.secret_manager import SecretManager
from core.security.execution_auditor import ExecutionAuditor, _redact_value
from core.security.encryption import encrypt, decrypt, get_encryption_key
from core.adaptation.generic_site_adapter import GenericSiteAdapter, SiteProfile, AuthModel, APIStructure
from core.checkpointing.secure_checkpoint import SecureCheckpoint


class TestSecretManager:
    def test_store_and_retrieve(self, tmp_path):
        sm = SecretManager(storage_path=str(tmp_path / "secrets.enc"))
        sm.store_credential("db_password", "super_secret_123")

        retrieved = sm.retrieve_credential("db_password")
        assert retrieved == "super_secret_123"

    def test_encrypted_at_rest(self, tmp_path):
        path = tmp_path / "secrets.enc"
        sm = SecretManager(storage_path=str(path))
        sm.store_credential("api_key", "sk-test-abcdef123456")

        raw_bytes = path.read_bytes()
        assert b"sk-test-abcdef123456" not in raw_bytes
        assert b"api_key" not in raw_bytes

    def test_retrieve_nonexistent_raises(self, tmp_path):
        sm = SecretManager(storage_path=str(tmp_path / "secrets.enc"))
        with pytest.raises(KeyError):
            sm.retrieve_credential("nonexistent")

    def test_key_rotation(self, tmp_path):
        sm = SecretManager(storage_path=str(tmp_path / "secrets.enc"))
        sm.store_credential("token", "my-token-value")

        new_key = os.urandom(32)
        sm.rotate_key(new_key)

        assert sm.retrieve_credential("token") == "my-token-value"

    def test_persistence_across_instances(self, tmp_path):
        path = str(tmp_path / "secrets.enc")
        key = os.urandom(32)

        sm1 = SecretManager(storage_path=path, encryption_key=key)
        sm1.store_credential("pwd", "hunter2")

        sm2 = SecretManager(storage_path=path, encryption_key=key)
        assert sm2.retrieve_credential("pwd") == "hunter2"

    def test_multiple_credentials(self, tmp_path):
        sm = SecretManager(storage_path=str(tmp_path / "secrets.enc"))
        sm.store_credential("a", "val_a")
        sm.store_credential("b", "val_b")
        sm.store_credential("c", "val_c")

        assert sm.retrieve_credential("a") == "val_a"
        assert sm.retrieve_credential("b") == "val_b"
        assert sm.retrieve_credential("c") == "val_c"
        assert set(sm.list_keys()) == {"a", "b", "c"}

    def test_delete_credential(self, tmp_path):
        sm = SecretManager(storage_path=str(tmp_path / "secrets.enc"))
        sm.store_credential("temp", "temporary")
        sm.delete_credential("temp")
        assert not sm.has_credential("temp")


class TestExecutionAuditor:
    def test_log_action_no_secrets(self, tmp_path):
        auditor = ExecutionAuditor(audit_log_path=str(tmp_path / "audit.log"))
        entry = auditor.log_action(
            action="TOOL_EXEC",
            params={"tool": "sqlmap", "password": "admin123", "api_key": "sk-secret"},
            result={"success": True},
        )

        assert entry["params"]["password"] == "[REDACTED]"
        assert entry["params"]["api_key"] == "[REDACTED]"
        assert entry["params"]["tool"] == "sqlmap"

    def test_log_action_redacts_in_strings(self, tmp_path):
        auditor = ExecutionAuditor(audit_log_path=str(tmp_path / "audit.log"))
        entry = auditor.log_action(
            action="SCAN",
            params={"command": "curl -H 'Authorization: Bearer sk-12345'"},
            result=None,
        )
        assert "sk-12345" not in json.dumps(entry["params"])

    def test_immutable_hash_chain(self, tmp_path):
        path = str(tmp_path / "audit.log")
        auditor = ExecutionAuditor(audit_log_path=path)

        auditor.log_action("ACTION_1", {"key": "val1"})
        auditor.log_action("ACTION_2", {"key": "val2"})
        auditor.log_action("ACTION_3", {"key": "val3"})

        assert auditor.verify_integrity()

    def test_tamper_detection(self, tmp_path):
        path = tmp_path / "audit.log"
        auditor = ExecutionAuditor(audit_log_path=str(path))
        auditor.log_action("ACTION_1", {"key": "val1"})
        auditor.log_action("ACTION_2", {"key": "val2"})

        lines = path.read_text(encoding="utf-8").strip().split("\n")
        tampered = json.loads(lines[0])
        tampered["action"] = "TAMPERED"
        lines[0] = json.dumps(tampered)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        auditor2 = ExecutionAuditor(audit_log_path=str(path))
        assert not auditor2.verify_integrity()

    def test_nested_redaction(self):
        data = {
            "config": {"token": "secret-tok", "normal": "ok"},
            "list": [{"password": "pass123"}],
        }
        redacted = _redact_value(data)
        assert redacted["config"]["token"] == "[REDACTED]"
        assert redacted["config"]["normal"] == "ok"
        assert redacted["list"][0]["password"] == "[REDACTED]"

    def test_get_entries(self, tmp_path):
        auditor = ExecutionAuditor(audit_log_path=str(tmp_path / "audit.log"))
        auditor.log_action("SCAN", {"target": "example.com"})
        auditor.log_action("EXPLOIT", {"target": "example.com"})
        auditor.log_action("SCAN", {"target": "other.com"})

        all_entries = auditor.get_entries()
        assert len(all_entries) == 3

        scan_entries = auditor.get_entries(action_filter="SCAN")
        assert len(scan_entries) == 2


class TestGenericSiteAdapter:
    def test_detect_django_cookie_rest(self):
        adapter = GenericSiteAdapter(
            target_url="https://example.com/api/v1/users",
            headers={"Server": "nginx", "X-Frame-Options": "DENY", "Set-Cookie": "csrftoken=abc123"},
            body_content="<html>Django powered</html>",
        )
        profile = adapter.profile()

        assert "django" in profile.technology_stack
        assert "nginx" in profile.technology_stack
        assert profile.auth_model == AuthModel.COOKIE
        assert profile.api_structure == APIStructure.REST
        assert len(profile.applicable_tests) > 5
        assert "csrf.basic" in profile.applicable_tests

    def test_detect_react_jwt_graphql(self):
        adapter = GenericSiteAdapter(
            target_url="https://app.example.com/graphql",
            headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9"},
            body_content='<div id="root" data-reactroot>React App</div>',
        )
        profile = adapter.profile()

        assert "react" in profile.technology_stack
        assert profile.auth_model == AuthModel.JWT
        assert profile.api_structure == APIStructure.GRAPHQL
        assert "jwt.manipulation" in profile.applicable_tests
        assert "graphql.introspection" in profile.applicable_tests
        assert "xss.dom" in profile.applicable_tests

    def test_detect_php_basic_auth(self):
        adapter = GenericSiteAdapter(
            target_url="https://legacy.example.com/index.php",
            headers={"Server": "Apache/2.4", "X-Powered-By": "PHP/7.4",
                     "WWW-Authenticate": "Basic realm=admin"},
        )
        profile = adapter.profile()

        assert "php" in profile.technology_stack
        assert "apache" in profile.technology_stack
        assert profile.auth_model == AuthModel.BASIC
        assert "input_validation.sqli" in profile.applicable_tests
        assert "authentication.brute_force" in profile.applicable_tests

    def test_unknown_site(self):
        adapter = GenericSiteAdapter(
            target_url="https://mystery.example.com",
            headers={},
        )
        profile = adapter.profile()

        assert profile.auth_model == AuthModel.UNKNOWN
        assert profile.api_structure == APIStructure.UNKNOWN
        assert len(profile.applicable_tests) >= len(["xss.reflected", "information_disclosure.error_messages",
                                                      "misconfiguration.server", "cryptography.weak_crypto",
                                                      "input_validation.general"])

    def test_profile_to_dict(self):
        adapter = GenericSiteAdapter(
            target_url="https://example.com",
            headers={"Server": "nginx"},
        )
        profile = adapter.profile()
        d = profile.to_dict()
        assert "target_url" in d
        assert "technology_stack" in d
        assert "auth_model" in d
        assert "applicable_tests" in d

    def test_api_key_detection(self):
        adapter = GenericSiteAdapter(
            target_url="https://api.example.com/v2/data",
            headers={"X-API-Key": "key-123456"},
        )
        profile = adapter.profile()
        assert profile.auth_model == AuthModel.API_KEY


class TestSecureCheckpoint:
    def test_save_and_load(self, tmp_path):
        cp = SecureCheckpoint(state_path=str(tmp_path / "cp.enc"))
        state = {"phase": "SCAN", "coverage": 45.0, "findings": ["sqli", "xss"]}
        cp.save_checkpoint(state)

        loaded = cp.load_checkpoint()
        assert loaded["phase"] == "SCAN"
        assert loaded["coverage"] == 45.0
        assert loaded["findings"] == ["sqli", "xss"]

    def test_encrypted_at_rest(self, tmp_path):
        path = tmp_path / "cp.enc"
        cp = SecureCheckpoint(state_path=str(path))
        state = {"secret_data": "should_not_be_readable"}
        cp.save_checkpoint(state)

        raw = path.read_bytes()
        assert b"should_not_be_readable" not in raw
        assert b"secret_data" not in raw

    def test_integrity_verification(self, tmp_path):
        path = tmp_path / "cp.enc"
        key = os.urandom(32)
        cp = SecureCheckpoint(state_path=str(path), encryption_key=key)
        cp.save_checkpoint({"data": "original"})

        # Tamper with encrypted bytes
        raw = path.read_bytes()
        tampered = bytearray(raw)
        if len(tampered) > 20:
            tampered[20] ^= 0xFF
        path.write_bytes(bytes(tampered))

        cp2 = SecureCheckpoint(state_path=str(path), encryption_key=key)
        with pytest.raises(Exception):
            cp2.load_checkpoint()

    def test_load_nonexistent_raises(self, tmp_path):
        cp = SecureCheckpoint(state_path=str(tmp_path / "nope.enc"))
        with pytest.raises(FileNotFoundError):
            cp.load_checkpoint()

    def test_exists_and_delete(self, tmp_path):
        cp = SecureCheckpoint(state_path=str(tmp_path / "cp.enc"))
        assert not cp.exists()
        cp.save_checkpoint({"x": 1})
        assert cp.exists()
        cp.delete()
        assert not cp.exists()

    def test_complex_state(self, tmp_path):
        cp = SecureCheckpoint(state_path=str(tmp_path / "cp.enc"))
        state = {
            "target": "https://example.com",
            "endpoints": ["/api/v1/users", "/api/v1/orders"],
            "coverage_map": {"sqli": "CONFIRMED", "xss": "READY"},
            "nested": {"deep": {"value": 42}},
        }
        cp.save_checkpoint(state)
        loaded = cp.load_checkpoint()
        assert loaded == state
