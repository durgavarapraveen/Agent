"""
Embedding abstraction for the RAG pipeline.
Primary: DeepSeek embedding API.  Fallback: local TF-IDF + hashing.
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
    """Generates embeddings via DeepSeek API or local fallback."""

    def __init__(self, api_key: Optional[str] = None, dimension: int = DIMENSION):
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY", "")
        self.dimension = dimension
        self._client: Optional[httpx.AsyncClient] = None
        self._use_api = bool(self.api_key)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def embed(self, text: str) -> List[float]:
        if self._use_api:
            try:
                return await self._api_embed(text)
            except Exception as e:
                logger.warning(f"[Embedder] API embed failed, using local: {e}")
        return self._local_embed(text)

    async def embed_batch(self, texts: List[str]) -> List[List[float]]:
        if self._use_api:
            try:
                return await self._api_embed_batch(texts)
            except Exception as e:
                logger.warning(f"[Embedder] Batch API embed failed, using local: {e}")
        return [self._local_embed(t) for t in texts]

    async def _api_embed(self, text: str) -> List[float]:
        client = await self._get_client()
        r = await client.post(
            "https://api.deepseek.com/v1/embeddings",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={"model": "deepseek-embedding", "input": text[:8000]},
        )
        if r.status_code == 200:
            data = r.json()
            return data["data"][0]["embedding"]
        raise RuntimeError(f"Embedding API {r.status_code}: {r.text[:200]}")

    async def _api_embed_batch(self, texts: List[str]) -> List[List[float]]:
        client = await self._get_client()
        truncated = [t[:8000] for t in texts]
        r = await client.post(
            "https://api.deepseek.com/v1/embeddings",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={"model": "deepseek-embedding", "input": truncated},
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
