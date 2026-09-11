from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from time import time
from typing import Dict, Optional


DEFAULT_TTL_SECONDS: Dict[str, int] = {
    # Recon results are cheap-fresh; regulated by target churn.
    "subdomain_enumeration": 6 * 3600,
    "dns_enumeration": 6 * 3600,
    "technology_fingerprinting": 2 * 3600,
    "waf_detection": 1 * 3600,
    "endpoint_discovery": 4 * 3600,
    "web_crawling": 2 * 3600,
    "port_scanning": 4 * 3600,
    "tls_analysis": 12 * 3600,
    # Expensive brute-force: skip aggressively.
    "directory_bruteforce": 8 * 3600,
    "parameter_discovery": 6 * 3600,
    # Vulnerability probes: shorter TTL, they can be re-run after evidence changes.
    "vulnerability_scanning": 30 * 60,
    "sql_injection": 15 * 60,
    "xss_scanning": 15 * 60,
}


@dataclass
class FreshnessEntry:
    operation: str
    target: str
    stored_at: float
    ttl_seconds: int
    payload_ref: str = ""
    confidence: float = 1.0

    def is_fresh(self, now: Optional[float] = None) -> bool:
        return (now or time()) - self.stored_at < self.ttl_seconds


class KnowledgeFreshness:
    def __init__(self):
        self._store: Dict[str, FreshnessEntry] = {}
        self._lock = Lock()

    @staticmethod
    def _key(target: str, operation: str, scope: str = "") -> str:
        t = (target or "").strip().lower()
        return f"{operation}|{t}|{scope}"

    def has_fresh_result(self, target: str, operation: str, scope: str = "",
                         ttl_override: Optional[int] = None) -> bool:
        with self._lock:
            entry = self._store.get(self._key(target, operation, scope))
            if entry is None:
                return False
            ttl = ttl_override or entry.ttl_seconds
            return (time() - entry.stored_at) < ttl

    def record(self, target: str, operation: str, payload_ref: str = "",
               scope: str = "", ttl_seconds: Optional[int] = None,
               confidence: float = 1.0) -> None:
        with self._lock:
            self._store[self._key(target, operation, scope)] = FreshnessEntry(
                operation=operation, target=(target or "").lower(),
                stored_at=time(),
                ttl_seconds=ttl_seconds or DEFAULT_TTL_SECONDS.get(operation, 1800),
                payload_ref=payload_ref, confidence=confidence,
            )

    def invalidate(self, target: str, operation: str = "", scope: str = "") -> int:
        with self._lock:
            if operation:
                k = self._key(target, operation, scope)
                return 1 if self._store.pop(k, None) is not None else 0
            n = 0
            t = (target or "").lower()
            for k in [k for k in self._store if f"|{t}|" in k]:
                del self._store[k]
                n += 1
            return n

    def snapshot(self) -> Dict[str, Dict]:
        with self._lock:
            return {k: {"stored_at": v.stored_at, "ttl": v.ttl_seconds,
                        "confidence": v.confidence} for k, v in self._store.items()}


_SINGLETON: Optional[KnowledgeFreshness] = None


def get_freshness() -> KnowledgeFreshness:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = KnowledgeFreshness()
    return _SINGLETON
