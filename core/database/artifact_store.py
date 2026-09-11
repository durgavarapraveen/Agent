"""Phase 6.4 — filesystem-backed artifact store.

Binary scan artifacts (screenshots, PoC bundles, captures) do not belong in the
``scan_artifacts`` BYTEA column — large blobs bloat the DB and slow every query.
This stores the bytes on disk under ``data/artifacts/{scan_id}/{artifact_id}``
and keeps only metadata + path in the DB, and rejects anything over 10 MB.

Pure filesystem logic — unit-testable with a temp directory and no DB.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

MAX_ARTIFACT_BYTES = 10 * 1024 * 1024  # 10 MB
_ROOT = Path("data") / "artifacts"


class ArtifactTooLargeError(ValueError):
    def __init__(self, size: int, limit: int = MAX_ARTIFACT_BYTES):
        self.size = size
        self.limit = limit
        super().__init__(f"artifact is {size} bytes, exceeds limit of {limit} bytes")


@dataclass
class ArtifactMetadata:
    scan_id: str
    artifact_id: str
    path: str
    size: int
    sha256: str
    kind: str = ""
    content_type: str = ""

    def to_db_row(self) -> Dict[str, Any]:
        # What is persisted in the DB — metadata + path, NOT the bytes.
        return {"scan_id": self.scan_id, "artifact_id": self.artifact_id,
                "path": self.path, "size": self.size, "sha256": self.sha256,
                "kind": self.kind, "content_type": self.content_type}


class ArtifactStore:

    def __init__(self, root: Optional[str] = None, max_bytes: int = MAX_ARTIFACT_BYTES):
        self.root = Path(root) if root else _ROOT
        self.max_bytes = max_bytes

    def _path(self, scan_id: str, artifact_id: str) -> Path:
        safe_scan = _safe(scan_id)
        safe_id = _safe(artifact_id)
        return self.root / safe_scan / safe_id

    def store(self, scan_id: str, artifact_id: str, content: bytes,
              kind: str = "", content_type: str = "") -> ArtifactMetadata:
        if not isinstance(content, (bytes, bytearray)):
            content = str(content).encode("utf-8")
        size = len(content)
        if size > self.max_bytes:
            raise ArtifactTooLargeError(size, self.max_bytes)
        path = self._path(scan_id, artifact_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return ArtifactMetadata(
            scan_id=scan_id, artifact_id=artifact_id, path=str(path), size=size,
            sha256=hashlib.sha256(content).hexdigest(), kind=kind, content_type=content_type)

    def load(self, scan_id: str, artifact_id: str) -> Optional[bytes]:
        path = self._path(scan_id, artifact_id)
        if not path.exists():
            return None
        return path.read_bytes()

    def exists(self, scan_id: str, artifact_id: str) -> bool:
        return self._path(scan_id, artifact_id).exists()

    def delete(self, scan_id: str, artifact_id: str) -> bool:
        path = self._path(scan_id, artifact_id)
        if path.exists():
            path.unlink()
            return True
        return False


def _safe(name: str) -> str:
    return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in (name or "x"))[:200]
