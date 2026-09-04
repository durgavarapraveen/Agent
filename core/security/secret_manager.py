import json
import logging
import os
from pathlib import Path
from typing import Optional, Dict, Any, Protocol
from core.security.encryption import encrypt, decrypt, get_encryption_key

logger = logging.getLogger(__name__)

SENSITIVE_KEYS = {"password", "api_key", "token", "secret", "credential", "private_key"}


class SecretManager:
    def __init__(self, storage_path: str = ".antigravity/secrets.enc", encryption_key: Optional[bytes] = None):
        self._storage_path = Path(storage_path)
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._key = encryption_key or get_encryption_key()
        self._cache: Dict[str, bytes] = {}
        self._load()

    def store_credential(self, key: str, value: str) -> None:
        encrypted = encrypt(value.encode("utf-8"), self._key)
        self._cache[key] = encrypted
        self._persist()
        logger.info(f"SECRET_STORED key={key}")

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

    def rotate_key(self, new_key: bytes) -> None:
        new_cache = {}
        for k, encrypted_val in self._cache.items():
            plaintext = decrypt(encrypted_val, self._key)
            new_cache[k] = encrypt(plaintext, new_key)
        self._key = new_key
        self._cache = new_cache
        self._persist()
        logger.info("SECRET_KEY_ROTATED")

    def _persist(self):
        import base64
        store = {k: base64.b64encode(v).decode("ascii") for k, v in self._cache.items()}
        raw = json.dumps(store).encode("utf-8")
        encrypted_blob = encrypt(raw, self._key)
        self._storage_path.write_bytes(encrypted_blob)

    def _load(self):
        import base64
        if not self._storage_path.exists():
            return
        try:
            encrypted_blob = self._storage_path.read_bytes()
            raw = decrypt(encrypted_blob, self._key)
            store = json.loads(raw.decode("utf-8"))
            self._cache = {k: base64.b64decode(v) for k, v in store.items()}
        except Exception as e:
            logger.warning(f"Failed to load secrets: {e}")
            self._cache = {}
