
from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# P3-1: persist the HuggingFace / sentence-transformers model cache to a stable
# on-disk location so the ~80 MB MiniLM model downloads ONCE and is reused by
# every scan subprocess, instead of re-downloading each run. Honors an existing
# HF_HOME if the operator already set one.
_CACHE_DIR = os.environ.get("HF_HOME") or str(
    Path(os.environ.get("ANTIGRAVITY_CACHE_DIR", str(Path.home() / ".cache" / "antigravity")))
    / "huggingface")
try:
    Path(_CACHE_DIR).mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("HF_HOME", _CACHE_DIR)
    os.environ.setdefault("SENTENCE_TRANSFORMERS_HOME", _CACHE_DIR)
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
except Exception:
    pass

LOCAL_DIMENSION = 384
_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

_model = None
_model_lock = threading.Lock()
# Count of hard load failures. We do NOT permanently latch on failure: a
# long-running server may attempt a load before the package is installed /
# the model is cached, and must succeed on a later attempt once it is —
# without needing a process restart. Give up only after repeated hard failures.
_load_attempts = 0
_MAX_LOAD_ATTEMPTS = 5


def _load_model():
    global _model, _load_attempts
    if _model is not None:
        return _model
    if _load_attempts >= _MAX_LOAD_ATTEMPTS:
        return None
    with _model_lock:
        if _model is not None:
            return _model
        if _load_attempts >= _MAX_LOAD_ATTEMPTS:
            return None
        try:
            from sentence_transformers import SentenceTransformer
            logger.info(f"[LocalEmbedder] loading {_MODEL_NAME} (first call, ~80 MB)")
            _model = SentenceTransformer(_MODEL_NAME)
            _dim_fn = getattr(_model, "get_embedding_dimension",
                              _model.get_sentence_embedding_dimension)
            logger.info(f"[LocalEmbedder] model loaded, dim={_dim_fn()}")
            _load_attempts = 0
        except Exception as e:
            _load_attempts += 1
            logger.warning(
                f"[LocalEmbedder] load attempt {_load_attempts}/{_MAX_LOAD_ATTEMPTS} "
                f"for {_MODEL_NAME} failed: {e}. "
                "Install with: pip install sentence-transformers")
    return _model


class LocalSemanticEmbedder:

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
