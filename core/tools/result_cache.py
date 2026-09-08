"""
P2-4: experiment / result caching.

Cache deterministic tool results keyed by
    target + operation + normalized_arguments
so httpx/whatweb/wafw00f/etc. don't re-run when their result is still
fresh. Complements P1-2 KnowledgeFreshness (which is a lightweight
"seen it recently?" flag) by holding the actual payload.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from threading import Lock
from time import time
from typing import Any, Dict, Optional


DEFAULT_TTL = 3600  # 1h


@dataclass
class CachedResult:
    key: str
    payload: Any
    stored_at: float = field(default_factory=time)
    ttl_seconds: int = DEFAULT_TTL

    def is_fresh(self) -> bool:
        return (time() - self.stored_at) < self.ttl_seconds


def _norm_args(args: Optional[Dict[str, Any]]) -> str:
    if not args:
        return ""
    filtered = {k: v for k, v in args.items()
                if k not in ("timeout", "session_id", "audit_context", "_meta")}
    return json.dumps(filtered, sort_keys=True, default=str)


def make_key(target: str, operation: str, args: Optional[Dict[str, Any]] = None) -> str:
    raw = f"{(operation or '').lower()}|{(target or '').lower()}|{_norm_args(args)}"
    return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:32]


class ResultCache:
    def __init__(self):
        self._store: Dict[str, CachedResult] = {}
        self._lock = Lock()

    def get(self, target: str, operation: str,
            args: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        k = make_key(target, operation, args)
        with self._lock:
            item = self._store.get(k)
        if item and item.is_fresh():
            return item.payload
        return None

    def set(self, target: str, operation: str, payload: Any,
            args: Optional[Dict[str, Any]] = None,
            ttl_seconds: int = DEFAULT_TTL) -> None:
        k = make_key(target, operation, args)
        with self._lock:
            self._store[k] = CachedResult(key=k, payload=payload,
                                          ttl_seconds=ttl_seconds)

    def invalidate(self, target: str = "", operation: str = "") -> int:
        with self._lock:
            if not target and not operation:
                n = len(self._store)
                self._store.clear()
                return n
            n = 0
            for k in list(self._store.keys()):
                # keys are hashes so we can't filter by content; clients
                # should invalidate by exact target+operation+args.
                pass
            return n

    def size(self) -> int:
        with self._lock:
            return len(self._store)


_SINGLETON: Optional[ResultCache] = None


def get_result_cache() -> ResultCache:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = ResultCache()
    return _SINGLETON
