import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from core.security.encryption import encrypt, decrypt, get_encryption_key

logger = logging.getLogger(__name__)


class SecureCheckpoint:
    def __init__(self, state_path: str = ".antigravity/checkpoint.enc",
                 encryption_key: Optional[bytes] = None):
        self._path = Path(state_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._key = encryption_key or get_encryption_key()

    def save_checkpoint(self, state: Dict[str, Any]) -> None:
        raw = json.dumps(state, sort_keys=True, default=str).encode("utf-8")
        integrity_hash = hashlib.sha256(raw).hexdigest()

        payload = {
            "state": state,
            "integrity_hash": integrity_hash,
        }
        payload_bytes = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        encrypted = encrypt(payload_bytes, self._key)
        self._path.write_bytes(encrypted)
        logger.info(f"CHECKPOINT_SAVED path={self._path} hash={integrity_hash[:16]}...")

    def load_checkpoint(self) -> Dict[str, Any]:
        if not self._path.exists():
            raise FileNotFoundError(f"No checkpoint at {self._path}")

        encrypted = self._path.read_bytes()
        decrypted = decrypt(encrypted, self._key)
        payload = json.loads(decrypted.decode("utf-8"))

        state = payload["state"]
        stored_hash = payload["integrity_hash"]

        raw = json.dumps(state, sort_keys=True, default=str).encode("utf-8")
        computed_hash = hashlib.sha256(raw).hexdigest()

        if computed_hash != stored_hash:
            raise ValueError(f"Checkpoint integrity check failed: expected {stored_hash[:16]}..., got {computed_hash[:16]}...")

        logger.info(f"CHECKPOINT_LOADED path={self._path} integrity=OK")
        return state

    def exists(self) -> bool:
        return self._path.exists()

    def delete(self) -> None:
        if self._path.exists():
            self._path.unlink()
