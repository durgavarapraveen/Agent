"""
Local semantic embedder using sentence-transformers all-MiniLM-L6-v2.

Replaces the MD5 hash-bag fallback with true semantic embeddings.
Model is ~80 MB, runs on CPU, produces 384-dim vectors.

Loaded lazily: first call downloads/loads the model. Downstream code must
distinguish 384-dim local vectors from 1536-dim API vectors — the pipeline
stores them in a separate `embedding_local vector(384)` column and queries
whichever column matches the active embedder path.
"""

from __future__ import annotations

import logging
import threading
from typing import List, Optional

logger = logging.getLogger(__name__)

LOCAL_DIMENSION = 384
_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

_model = None
_model_lock = threading.Lock()
_load_failed = False


def _load_model():
    global _model, _load_failed
    if _model is not None or _load_failed:
        return _model
    with _model_lock:
        if _model is not None or _load_failed:
            return _model
        try:
            from sentence_transformers import SentenceTransformer
            logger.info(f"[LocalEmbedder] loading {_MODEL_NAME} (first call, ~80 MB)")
            _model = SentenceTransformer(_MODEL_NAME)
            logger.info(f"[LocalEmbedder] model loaded, dim={_model.get_sentence_embedding_dimension()}")
        except Exception as e:
            _load_failed = True
            logger.warning(f"[LocalEmbedder] failed to load {_MODEL_NAME}: {e}. "
                            "Install with: pip install sentence-transformers")
    return _model


class LocalSemanticEmbedder:
    """Thin wrapper around sentence-transformers MiniLM."""

    dimension = LOCAL_DIMENSION

    @classmethod
    def available(cls) -> bool:
        return _load_model() is not None

    @classmethod
    def embed(cls, text: str) -> Optional[List[float]]:
        m = _load_model()
        if m is None:
            return None
        try:
            v = m.encode(str(text)[:8000], normalize_embeddings=True)
            return v.tolist() if hasattr(v, "tolist") else list(v)
        except Exception as e:
            logger.warning(f"[LocalEmbedder] encode failed: {e}")
            return None

    @classmethod
    def embed_batch(cls, texts: List[str]) -> Optional[List[List[float]]]:
        m = _load_model()
        if m is None:
            return None
        try:
            trimmed = [str(t)[:8000] for t in texts]
            arr = m.encode(trimmed, normalize_embeddings=True, batch_size=32)
            return [row.tolist() if hasattr(row, "tolist") else list(row) for row in arr]
        except Exception as e:
            logger.warning(f"[LocalEmbedder] batch encode failed: {e}")
            return None
