
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

_LOCAL_MODEL_NAME = os.getenv("RERANKER_MODEL", "BAAI/bge-reranker-base")

_ce_model = None
_ce_lock = threading.Lock()
_ce_failed = False


def _load_cross_encoder():
    global _ce_model, _ce_failed
    if _ce_model is not None or _ce_failed:
        return _ce_model
    with _ce_lock:
        if _ce_model is not None or _ce_failed:
            return _ce_model
        try:
            from sentence_transformers import CrossEncoder
            logger.info(f"[Reranker] loading {_LOCAL_MODEL_NAME}")
            _ce_model = CrossEncoder(_LOCAL_MODEL_NAME, max_length=512)
            logger.info("[Reranker] cross-encoder loaded")
        except Exception as e:
            _ce_failed = True
            logger.info(f"[Reranker] local cross-encoder unavailable ({e}); "
                        "will use Cohere or identity fallback")
    return _ce_model


class Reranker:

    def __init__(self):
        self.cohere_key = os.getenv("COHERE_API_KEY", "").strip()
        self.cohere_model = os.getenv("COHERE_RERANK_MODEL", "rerank-english-v3.0")

    async def rerank(self, query: str, docs: List[Dict[str, Any]],
                     top_k: int = 5) -> List[Dict[str, Any]]:
        if not docs:
            return []
        if len(docs) <= top_k and len(docs) <= 3:
            return docs

        # Prefer Cohere when configured — highest quality, no local RAM cost.
        if self.cohere_key:
            try:
                return await self._cohere_rerank(query, docs, top_k)
            except Exception as e:
                logger.warning(f"[Reranker] Cohere failed, trying local: {e}")

        m = _load_cross_encoder()
        if m is not None:
            try:
                return self._local_rerank(m, query, docs, top_k)
            except Exception as e:
                logger.warning(f"[Reranker] local CE failed: {e}")

        # Identity fallback — never break retrieval.
        for d in docs:
            d.setdefault("rerank_score", d.get("similarity", 0.0))
        return docs[:top_k]

    def _local_rerank(self, model, query: str, docs: List[Dict[str, Any]],
                       top_k: int) -> List[Dict[str, Any]]:
        pairs = [(query, str(d.get("content", ""))[:2000]) for d in docs]
        scores = model.predict(pairs, batch_size=16, show_progress_bar=False)
        for d, s in zip(docs, scores):
            d["rerank_score"] = float(s)
        docs.sort(key=lambda x: x["rerank_score"], reverse=True)
        return docs[:top_k]

    async def _cohere_rerank(self, query: str, docs: List[Dict[str, Any]],
                              top_k: int) -> List[Dict[str, Any]]:
        payload = {
            "model": self.cohere_model,
            "query": query,
            "documents": [str(d.get("content", ""))[:4000] for d in docs],
            "top_n": min(top_k, len(docs)),
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                "https://api.cohere.ai/v1/rerank",
                headers={
                    "Authorization": f"Bearer {self.cohere_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            r.raise_for_status()
            data = r.json()
        out = []
        for item in data.get("results", []):
            idx = item.get("index")
            if idx is None or idx >= len(docs):
                continue
            d = docs[idx]
            d["rerank_score"] = float(item.get("relevance_score", 0.0))
            out.append(d)
        return out or docs[:top_k]


_reranker: Optional[Reranker] = None


def get_reranker() -> Reranker:
    global _reranker
    if _reranker is None:
        _reranker = Reranker()
    return _reranker
