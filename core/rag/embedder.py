"""
Embedding abstraction for the RAG pipeline.

Primary path: OpenAI-compatible embeddings API (EMBEDDING_API_URL /
EMBEDDING_API_KEY / EMBEDDING_MODEL). Produces 1536-dim vectors that go into
the shared `rag_documents.embedding vector(1536)` column.

Fallback path: local sentence-transformers all-MiniLM-L6-v2 — TRUE semantic
embeddings, 384-dim, ~80 MB RAM, no API key. Vectors go into a SEPARATE
`rag_documents.embedding_local vector(384)` column because mixing embedding
spaces in one index is nonsense.

Last-resort path: deterministic hash-bag (`_hash_embed`). Only used when
sentence-transformers itself cannot be loaded. The last slot carries
`LOCAL_MARKER_VALUE` and the pipeline refuses to persist those.

`embed()` and `embed_batch()` now return `EmbedResult(vec, dim, source)` so
callers know which vector column and index to use.
"""

import hashlib
import logging
import math
import os
from dataclasses import dataclass
from typing import List, Optional

import httpx

from core.rag.local_embedder import LOCAL_DIMENSION, LocalSemanticEmbedder

logger = logging.getLogger(__name__)

DIMENSION = 1536


@dataclass
class EmbedResult:
    vector: List[float]
    dim: int          # 1536 (api) | 384 (local_semantic) | 1536 (hash_bag)
    source: str       # 'api' | 'local_semantic' | 'hash_bag'

    @property
    def is_api(self) -> bool:
        return self.source == "api"

    @property
    def is_semantic(self) -> bool:
        return self.source in ("api", "local_semantic")

    @property
    def is_hash(self) -> bool:
        return self.source == "hash_bag"


class Embedder:
    """Generates embeddings via a configured API or local fallback."""

    LOCAL_MARKER_VALUE = -9.87654321  # last-slot sentinel for hash-bag path
    _warned_missing = False

    def __init__(self, api_key: Optional[str] = None, dimension: int = DIMENSION):
        self.api_url = (os.getenv("EMBEDDING_API_URL") or "").rstrip("/")
        self.api_key = api_key or os.getenv("EMBEDDING_API_KEY", "")
        self.model = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")
        self.dimension = dimension
        self._client: Optional[httpx.AsyncClient] = None
        self._use_api = bool(self.api_url and self.api_key)
        self._api_disabled = False
        if not self._use_api and not Embedder._warned_missing:
            logger.info("[Embedder] No EMBEDDING_API_URL/KEY set — will use "
                         "local sentence-transformers (MiniLM) if available, "
                         "else hash-bag fallback")
            Embedder._warned_missing = True

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def embed(self, text: str) -> EmbedResult:
        if self._use_api and not self._api_disabled:
            try:
                v = await self._api_embed(text)
                return EmbedResult(v, DIMENSION, "api")
            except Exception as e:
                self._handle_api_failure(e)

        # Semantic local fallback
        v_local = LocalSemanticEmbedder.embed(text)
        if v_local is not None:
            return EmbedResult(v_local, LOCAL_DIMENSION, "local_semantic")

        return EmbedResult(self._hash_embed(text), DIMENSION, "hash_bag")

    async def embed_batch(self, texts: List[str]) -> List[EmbedResult]:
        if self._use_api and not self._api_disabled:
            try:
                vecs = await self._api_embed_batch(texts)
                return [EmbedResult(v, DIMENSION, "api") for v in vecs]
            except Exception as e:
                self._handle_api_failure(e)

        v_locals = LocalSemanticEmbedder.embed_batch(texts)
        if v_locals is not None:
            return [EmbedResult(v, LOCAL_DIMENSION, "local_semantic") for v in v_locals]

        return [EmbedResult(self._hash_embed(t), DIMENSION, "hash_bag") for t in texts]

    def _handle_api_failure(self, err: Exception):
        msg = str(err)
        if "404" in msg or "401" in msg or "403" in msg:
            self._api_disabled = True
            logger.warning(f"[Embedder] API disabled after error, using local: {msg[:200]}")
        else:
            logger.warning(f"[Embedder] API embed failed, using local: {msg[:200]}")

    async def _api_embed(self, text: str) -> List[float]:
        client = await self._get_client()
        r = await client.post(
            f"{self.api_url}/embeddings",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={"model": self.model, "input": text[:8000]},
        )
        if r.status_code == 200:
            data = r.json()
            return data["data"][0]["embedding"]
        raise RuntimeError(f"Embedding API {r.status_code}: {r.text[:200]}")

    async def _api_embed_batch(self, texts: List[str]) -> List[List[float]]:
        client = await self._get_client()
        truncated = [t[:8000] for t in texts]
        r = await client.post(
            f"{self.api_url}/embeddings",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={"model": self.model, "input": truncated},
        )
        if r.status_code == 200:
            data = r.json()
            return [item["embedding"] for item in sorted(data["data"], key=lambda x: x["index"])]
        raise RuntimeError(f"Batch embedding API {r.status_code}: {r.text[:200]}")

    def _hash_embed(self, text: str) -> List[float]:
        """Last-resort deterministic bag-of-words hash embedding.

        Only reached when sentence-transformers itself is unavailable.
        Marked via `LOCAL_MARKER_VALUE` in the last slot so pipeline refuses
        to store it (see pipeline._store_chunk).
        """
        vec = [0.0] * (self.dimension - 1)
        for token in str(text).lower().split():
            h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
            idx = h % (self.dimension - 1)
            sign = 1.0 if (h >> 128) % 2 == 0 else -1.0
            vec[idx] += sign
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        normalized = [v / norm for v in vec]
        normalized.append(self.LOCAL_MARKER_VALUE)
        return normalized

    @classmethod
    def is_local_embedding(cls, vec: List[float]) -> bool:
        """True only for the hash-bag last-resort vectors."""
        if not vec:
            return False
        return abs(vec[-1] - cls.LOCAL_MARKER_VALUE) < 1e-6

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
