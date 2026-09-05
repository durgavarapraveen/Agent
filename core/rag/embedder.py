"""
Embedding abstraction for the RAG pipeline.
Primary: OpenAI-compatible embeddings API (configured via EMBEDDING_API_URL,
EMBEDDING_API_KEY, EMBEDDING_MODEL). Fallback: local hash-bag embedding.

DeepSeek does not currently expose an embeddings endpoint — attempting to
use its chat API key against /v1/embeddings returns 404. The API path is
therefore disabled unless an explicit embedding provider is configured.
"""

import hashlib
import logging
import math
import os
from typing import List, Optional

import httpx

logger = logging.getLogger(__name__)

DIMENSION = 1536


class Embedder:
    """Generates embeddings via a configured API or local fallback."""

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
            logger.info("[Embedder] No EMBEDDING_API_URL/KEY set — using local hash embedding")
            Embedder._warned_missing = True

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def embed(self, text: str) -> List[float]:
        if self._use_api and not self._api_disabled:
            try:
                return await self._api_embed(text)
            except Exception as e:
                self._handle_api_failure(e)
        return self._local_embed(text)

    async def embed_batch(self, texts: List[str]) -> List[List[float]]:
        if self._use_api and not self._api_disabled:
            try:
                return await self._api_embed_batch(texts)
            except Exception as e:
                self._handle_api_failure(e)
        return [self._local_embed(t) for t in texts]

    def _handle_api_failure(self, err: Exception):
        msg = str(err)
        # Disable API path on hard endpoint errors so we don't spam logs every call.
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

    def _local_embed(self, text: str) -> List[float]:
        """Deterministic bag-of-words hash embedding (stable fallback)."""
        vec = [0.0] * self.dimension
        for token in str(text).lower().split():
            h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
            idx = h % self.dimension
            sign = 1.0 if (h >> 128) % 2 == 0 else -1.0
            vec[idx] += sign
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
