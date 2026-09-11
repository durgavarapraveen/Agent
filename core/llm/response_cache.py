"""Phase 8.1 — LLM response caching.

Testing SQLi on /api/products/1 and /api/products/2 produces near-identical
prompts. This caches responses keyed on the *template* of the prompt — with
endpoint-specific values (ids, paths, numbers, UUIDs) stripped out — so the
second and later instances are free.

In-memory with TTL; an optional persist hook writes an ``llm_cache`` DB table.
``token_optimizer`` handles compression, not caching, so this is complementary.
Pure and unit-testable.
"""
from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_NUM = re.compile(r"\b\d+\b")
_URL_PATH_SEG = re.compile(r"(/)(\d+|[0-9a-fA-F]{8,})(?=/|\b)")

TTL_SAME_SCAN = 24 * 3600          # 24h
TTL_SAME_TARGET = 7 * 24 * 3600    # 7d


def normalize_prompt(prompt: str) -> str:
    """Strip endpoint-specific values so instances of the same test collapse to
    one template. /products/1 and /products/42 → /products/{n}."""
    s = prompt or ""
    s = _UUID.sub("{uuid}", s)
    s = _URL_PATH_SEG.sub(r"\1{id}", s)
    s = _LONG_HEX.sub("{hex}", s)
    s = _NUM.sub("{n}", s)
    return s


def cache_key(prompt: str, model: str = "", system: str = "") -> str:
    template = f"{model}\x00{normalize_prompt(system)}\x00{normalize_prompt(prompt)}"
    return hashlib.sha256(template.encode("utf-8")).hexdigest()


@dataclass
class _Entry:
    response: Any
    created_at: float
    hit_count: int = 0


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    stores: int = 0
    tokens_saved: int = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return round(self.hits / total, 3) if total else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {"hits": self.hits, "misses": self.misses, "stores": self.stores,
                "tokens_saved": self.tokens_saved, "hit_rate": self.hit_rate}


class LLMResponseCache:

    def __init__(self, ttl_seconds: int = TTL_SAME_SCAN,
                 persist: Optional[Callable[[str, Any], None]] = None,
                 now: Optional[Callable[[], float]] = None):
        self.ttl = ttl_seconds
        self._persist = persist
        self._now = now or time.time
        self._store: Dict[str, _Entry] = {}
        self._lock = threading.RLock()
        self.stats = CacheStats()

    def get(self, prompt: str, model: str = "", system: str = "") -> Optional[Any]:
        key = cache_key(prompt, model, system)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self.stats.misses += 1
                return None
            if self._now() - entry.created_at > self.ttl:
                del self._store[key]
                self.stats.misses += 1
                return None
            entry.hit_count += 1
            self.stats.hits += 1
            self.stats.tokens_saved += _estimate_tokens(prompt)
            return entry.response

    def set(self, prompt: str, response: Any, model: str = "", system: str = "") -> None:
        key = cache_key(prompt, model, system)
        with self._lock:
            self._store[key] = _Entry(response=response, created_at=self._now())
            self.stats.stores += 1
        if self._persist:
            try:
                self._persist(key, response)
            except Exception as e:
                logger.debug("response_cache: persist failed (%s)", e)

    def get_or_call(self, prompt: str, producer: Callable[[], Any],
                    model: str = "", system: str = "") -> Any:
        cached = self.get(prompt, model, system)
        if cached is not None:
            return cached
        result = producer()
        self.set(prompt, result, model, system)
        return result

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


def _estimate_tokens(text: str) -> int:
    return max(1, len(text or "") // 4)  # ~4 chars/token
