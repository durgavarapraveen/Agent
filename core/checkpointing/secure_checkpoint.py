import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Dict, Any, Optional

from core.security.encryption import encrypt, decrypt, get_encryption_key

logger = logging.getLogger(__name__)


# On-disk envelope:
# Enveloping lets us stamp a key version so a checkpoint saved with key vN
# can be recognised (and refused with a clear error) when the process is
# now running with key vN+1. Previously an ENCRYPTION_KEY rotation without a
# separate file migration produced an opaque "decrypt failed" on load.
CHECKPOINT_STORE_VERSION = 1


class SecureCheckpoint:
    def __init__(self, state_path: str = ".antigravity/checkpoint.enc",
                 encryption_key: Optional[bytes] = None, key_version: int = 1):
        self._path = Path(state_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._key = encryption_key or get_encryption_key()
        self._key_version = int(key_version)

    def save_checkpoint(self, state: Dict[str, Any]) -> None:
        raw = json.dumps(state, sort_keys=True, default=str).encode("utf-8")
        integrity_hash = hashlib.sha256(raw).hexdigest()

        payload = {
            "version": CHECKPOINT_STORE_VERSION,
            "key_version": self._key_version,
            "state": state,
            "integrity_hash": integrity_hash,
        }
        payload_bytes = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        encrypted = encrypt(payload_bytes, self._key)

        # Atomic write via tmp + rename so a crash mid-write doesn't leave a
        # truncated file that fails integrity checks on the next load.
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_bytes(encrypted)
        os.replace(tmp, self._path)
        logger.info("CHECKPOINT_SAVED path=%s hash=%s... key_version=%d",
                    self._path, integrity_hash[:16], self._key_version)

    def load_checkpoint(self) -> Dict[str, Any]:
        if not self._path.exists():
            raise FileNotFoundError(f"No checkpoint at {self._path}")

        encrypted = self._path.read_bytes()
        try:
            decrypted = decrypt(encrypted, self._key)
        except Exception as e:
            # Rewrap decrypt errors with a clearer diagnostic — the operator
            # needs to know it's likely a key mismatch, not corruption.
            raise ValueError(
                f"Checkpoint decrypt failed at {self._path}. This usually "
                f"means ENCRYPTION_KEY has changed since the checkpoint was "
                f"written. Restore the previous key or delete the checkpoint "
                f"file to start a fresh scan. ({e})"
            ) from e

        payload = json.loads(decrypted.decode("utf-8"))

        # Version compatibility. Missing keys = legacy save.
        stored_key_version = payload.get("key_version", self._key_version)
        if stored_key_version != self._key_version:
            raise ValueError(
                f"Checkpoint at {self._path} was saved with key_version="
                f"{stored_key_version} but current process is running with "
                f"key_version={self._key_version}. Roll the process key back "
                f"or delete the checkpoint."
            )

        state = payload["state"]
        stored_hash = payload["integrity_hash"]

        raw = json.dumps(state, sort_keys=True, default=str).encode("utf-8")
        computed_hash = hashlib.sha256(raw).hexdigest()

        if computed_hash != stored_hash:
            raise ValueError(
                f"Checkpoint integrity check failed: expected {stored_hash[:16]}..., "
                f"got {computed_hash[:16]}..."
            )

        logger.info("CHECKPOINT_LOADED path=%s integrity=OK key_version=%d",
                    self._path, self._key_version)
        return state

    def rotate_key(self, new_key: bytes, new_key_version: int) -> None:
        state = self.load_checkpoint()
        self._key = new_key
        self._key_version = int(new_key_version)
        self.save_checkpoint(state)
        logger.info("CHECKPOINT_KEY_ROTATED path=%s new_key_version=%d",
                    self._path, self._key_version)

    def exists(self) -> bool:
        return self._path.exists()

    def delete(self) -> None:
        if self._path.exists():
            self._path.unlink()
