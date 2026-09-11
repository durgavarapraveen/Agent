"""Phase 6.4 — DB performance: artifact store (filesystem + 10MB limit)."""
from __future__ import annotations

import pytest

from core.database.artifact_store import (
    MAX_ARTIFACT_BYTES,
    ArtifactStore,
    ArtifactTooLargeError,
)


def test_store_and_load_roundtrip(tmp_path):
    store = ArtifactStore(root=str(tmp_path))
    meta = store.store("scan1", "shot1", b"PNGDATA", kind="screenshot", content_type="image/png")
    assert meta.size == 7
    assert meta.sha256
    assert "scan1" in meta.path and "shot1" in meta.path
    assert store.load("scan1", "shot1") == b"PNGDATA"
    # DB row carries metadata + path, never the bytes.
    row = meta.to_db_row()
    assert "path" in row and "content" not in row


def test_rejects_over_10mb(tmp_path):
    store = ArtifactStore(root=str(tmp_path))
    big = b"x" * (MAX_ARTIFACT_BYTES + 1)
    with pytest.raises(ArtifactTooLargeError):
        store.store("scan1", "big", big)
    # Nothing was written.
    assert not store.exists("scan1", "big")


def test_at_limit_allowed(tmp_path):
    store = ArtifactStore(root=str(tmp_path))
    meta = store.store("s", "a", b"y" * MAX_ARTIFACT_BYTES)
    assert meta.size == MAX_ARTIFACT_BYTES


def test_path_structure_and_sanitization(tmp_path):
    store = ArtifactStore(root=str(tmp_path))
    meta = store.store("scan/../evil", "id with spaces", b"data")
    # Path traversal / spaces sanitized.
    assert ".." not in Path_parts(meta.path)
    assert store.load("scan/../evil", "id with spaces") == b"data"


def Path_parts(p):
    from pathlib import Path
    return set(Path(p).parts)


def test_delete(tmp_path):
    store = ArtifactStore(root=str(tmp_path))
    store.store("s", "a", b"data")
    assert store.delete("s", "a") is True
    assert store.delete("s", "a") is False  # already gone


def test_load_missing_returns_none(tmp_path):
    assert ArtifactStore(root=str(tmp_path)).load("s", "nope") is None


def test_custom_max_bytes(tmp_path):
    store = ArtifactStore(root=str(tmp_path), max_bytes=10)
    store.store("s", "ok", b"1234567890")
    with pytest.raises(ArtifactTooLargeError):
        store.store("s", "toobig", b"12345678901")
