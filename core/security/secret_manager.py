import base64
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Optional, Dict, Any, Protocol

from core.security.encryption import encrypt, decrypt, get_encryption_key

logger = logging.getLogger(__name__)

SENSITIVE_KEYS = {"password", "api_key", "token", "secret", "credential", "private_key"}

# On-disk envelope format:
#   {
#     "version": 2,
#     "key_version": 3,
#     "created_at": "2026-09-06T…",
#     "cache": { "<name>": "<base64>", ... }
#   }
# The envelope is encrypted with the current master key. Version 1 stored
# raw `{k: b64}` without the envelope — `_load` transparently upgrades it.
CURRENT_STORE_VERSION = 2


class SecretManager:
    def __init__(self, storage_path: str = ".antigravity/secrets.enc",
                 encryption_key: Optional[bytes] = None):
        self._storage_path = Path(storage_path)
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._key = encryption_key or get_encryption_key()
        self._cache: Dict[str, bytes] = {}
        self._key_version = 1
        self._load()

    # ── Public API ──────────────────────────────────────────────────────
    def store_credential(self, key: str, value: str) -> None:
        encrypted = encrypt(value.encode("utf-8"), self._key)
        self._cache[key] = encrypted
        self._persist()
        logger.info("SECRET_STORED key=%s", key)

    def retrieve_credential(self, key: str) -> str:
        if key not in self._cache:
            raise KeyError(f"No credential stored for key: {key}")
        decrypted = decrypt(self._cache[key], self._key)
        return decrypted.decode("utf-8")

    def delete_credential(self, key: str) -> None:
        if key in self._cache:
            del self._cache[key]
            self._persist()

    def has_credential(self, key: str) -> bool:
        return key in self._cache

    def list_keys(self) -> list:
        return list(self._cache.keys())

    def key_version(self) -> int:
        return self._key_version

    def rotate_key(self, new_key: bytes) -> None:
        new_cache: Dict[str, bytes] = {}
        for k, encrypted_val in self._cache.items():
            plaintext = decrypt(encrypted_val, self._key)
            new_cache[k] = encrypt(plaintext, new_key)

        new_version = self._key_version + 1
        tmp_path = self._storage_path.with_suffix(self._storage_path.suffix + ".tmp")
        prev_path = self._storage_path.with_suffix(self._storage_path.suffix + ".prev")

        # Build the on-disk envelope encrypted with the NEW key.
        envelope = {
            "version": CURRENT_STORE_VERSION,
            "key_version": new_version,
            "cache": {k: base64.b64encode(v).decode("ascii") for k, v in new_cache.items()},
        }
        raw = json.dumps(envelope).encode("utf-8")
        blob = encrypt(raw, new_key)
        tmp_path.write_bytes(blob)

        # Rotate files atomically. On POSIX both `rename` calls are atomic;
        # on Windows `os.replace` is best-effort but still crash-safer than
        # in-place overwrite.
        if self._storage_path.exists():
            os.replace(self._storage_path, prev_path)
        os.replace(tmp_path, self._storage_path)

        # Commit in-memory state ONLY after the on-disk swap succeeded.
        self._key = new_key
        self._cache = new_cache
        self._key_version = new_version

        # Success — drop the `.prev` backup.
        try:
            if prev_path.exists():
                prev_path.unlink()
        except OSError:
            pass

        logger.info("SECRET_KEY_ROTATED to version=%d", new_version)

    # ── Persistence ─────────────────────────────────────────────────────
    def _persist(self):
        envelope = {
            "version": CURRENT_STORE_VERSION,
            "key_version": self._key_version,
            "cache": {k: base64.b64encode(v).decode("ascii") for k, v in self._cache.items()},
        }
        raw = json.dumps(envelope).encode("utf-8")
        blob = encrypt(raw, self._key)
        # Write to a temp then rename so an interrupted write doesn't leave
        # a truncated file.
        tmp_path = self._storage_path.with_suffix(self._storage_path.suffix + ".tmp")
        tmp_path.write_bytes(blob)
        os.replace(tmp_path, self._storage_path)

    def _load(self):
        if not self._storage_path.exists():
            return
        try:
            blob = self._storage_path.read_bytes()
            raw = decrypt(blob, self._key)
            data = json.loads(raw.decode("utf-8"))
            if isinstance(data, dict) and data.get("version") == CURRENT_STORE_VERSION:
                self._key_version = int(data.get("key_version", 1))
                store = data.get("cache", {}) or {}
                self._cache = {k: base64.b64decode(v) for k, v in store.items()}
                return
            # Legacy V1 payload: flat {k: b64}. Migrate on next persist.
            if isinstance(data, dict):
                self._cache = {k: base64.b64decode(v) for k, v in data.items()}
                self._key_version = 1
                logger.info("Upgrading secret store from v1 to v%d", CURRENT_STORE_VERSION)
                self._persist()
                return
            raise ValueError("Unrecognized secret store format")
        except Exception as e:
            # If the load fails and a `.prev` backup exists from a mid-
            # rotation crash, try that too — it's still encrypted with the
            # PREVIOUS key which the current process may or may not hold,
            # but attempting is strictly better than silent zero-secrets.
            prev_path = self._storage_path.with_suffix(self._storage_path.suffix + ".prev")
            if prev_path.exists():
                logger.warning(
                    "Failed to load current secrets (%s); attempting .prev backup", e)
                try:
                    blob = prev_path.read_bytes()
                    raw = decrypt(blob, self._key)
                    data = json.loads(raw.decode("utf-8"))
                    if isinstance(data, dict) and "cache" in data:
                        self._cache = {k: base64.b64decode(v) for k, v in data["cache"].items()}
                        self._key_version = int(data.get("key_version", 1))
                        logger.warning("Loaded secrets from .prev backup — please investigate")
                        return
                except Exception as e2:
                    logger.warning("Backup load also failed: %s", e2)
            logger.warning("Failed to load secrets: %s", e)
            self._cache = {}
