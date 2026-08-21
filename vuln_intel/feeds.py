"""
Live vulnerability-intelligence feed fetchers.

Async clients for the three public feeds used to enrich findings:
  - NVD API v2      (CVE detail + CVSS)   TTL 2h
  - EPSS API        (exploit probability) TTL 24h
  - CISA KEV feed   (known-exploited)     TTL 6h

All calls are retried (3 attempts, exponential backoff) and degrade gracefully:
if a feed is unreachable, the last cached value is returned and flagged stale.
No API keys are required for any of these feeds.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import aiohttp
except Exception:       # noqa: BLE001 - import guarded so the module still loads
    aiohttp = None      # type: ignore

logger = logging.getLogger(__name__)

# Feed endpoints
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

# Cache TTLs (seconds)
TTL_NVD = 2 * 3600
TTL_EPSS = 24 * 3600
TTL_KEV = 6 * 3600

# NVD public rate limit is ~5 req / 30s (no key). Keep a safe min interval.
_NVD_MIN_INTERVAL = 6.5
DEFAULT_CACHE = ".vuln_intel_cache.sqlite"


@dataclass
class FeedResult:
    """Wraps a feed payload with freshness metadata."""
    data: Any
    source: str
    fetched_at: float
    stale: bool = False
    error: str = ""

    @property
    def age_sec(self) -> float:
        return max(0.0, time.time() - self.fetched_at)

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "fetched_at": self.fetched_at,
                "stale": self.stale, "age_sec": round(self.age_sec, 1),
                "error": self.error}


class CacheDB:
    """Tiny SQLite key/value cache with per-entry timestamps."""

    def __init__(self, path: str = DEFAULT_CACHE):
        self.path = path
        self._init()

    def _conn(self):
        # NOTE: explicit open/close — `with sqlite3.connect()` commits but does
        # not close, which leaks handles and locks the file on Windows.
        return sqlite3.connect(self.path)

    def _init(self):
        c = self._conn()
        try:
            c.execute(
                "CREATE TABLE IF NOT EXISTS cache ("
                "key TEXT PRIMARY KEY, value TEXT, fetched_at REAL, source TEXT)")
            c.commit()
        finally:
            c.close()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        c = self._conn()
        try:
            row = c.execute(
                "SELECT value, fetched_at, source FROM cache WHERE key=?",
                (key,)).fetchone()
        finally:
            c.close()
        if not row:
            return None
        try:
            value = json.loads(row[0])
        except Exception:       # noqa: BLE001
            return None
        return {"value": value, "fetched_at": row[1], "source": row[2]}

    def set(self, key: str, value: Any, source: str = ""):
        c = self._conn()
        try:
            c.execute(
                "INSERT OR REPLACE INTO cache(key, value, fetched_at, source) "
                "VALUES(?,?,?,?)",
                (key, json.dumps(value, default=str), time.time(), source))
            c.commit()
        finally:
            c.close()


class _RateLimiter:
    """Enforce a minimum interval between requests to a host."""

    def __init__(self, min_interval: float):
        self.min_interval = min_interval
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def wait(self):
        async with self._lock:
            delta = time.time() - self._last
            if delta < self.min_interval:
                await asyncio.sleep(self.min_interval - delta)
            self._last = time.time()


class FeedClient:
    """Fetches + caches the NVD / EPSS / KEV feeds."""

    def __init__(self, cache_path: str = DEFAULT_CACHE,
                 max_retries: int = 3, timeout: float = 30.0):
        self.cache = CacheDB(cache_path)
        self.max_retries = max_retries
        self.timeout = timeout
        self._nvd_limiter = _RateLimiter(_NVD_MIN_INTERVAL)

    # ── low-level HTTP with retry + backoff ──

    async def _get_json(self, url: str, params: Optional[Dict] = None,
                        limiter: Optional[_RateLimiter] = None) -> Any:
        if aiohttp is None:
            raise RuntimeError("aiohttp is not installed")
        last_err: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            if limiter:
                await limiter.wait()
            try:
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url, params=params) as resp:
                        if resp.status == 429 or resp.status >= 500:
                            raise RuntimeError(f"HTTP {resp.status}")
                        resp.raise_for_status()
                        return await resp.json(content_type=None)
            except Exception as e:      # noqa: BLE001
                last_err = e
                backoff = 2 ** (attempt - 1)     # 1, 2, 4 ...
                logger.warning(f"[feeds] {url} attempt {attempt}/{self.max_retries} "
                               f"failed: {e} (retry in {backoff}s)")
                if attempt < self.max_retries:
                    await asyncio.sleep(backoff)
        raise last_err if last_err else RuntimeError("request failed")

    def _cached_or_stale(self, key: str, ttl: int) -> Optional[FeedResult]:
        row = self.cache.get(key)
        if not row:
            return None
        fresh = (time.time() - row["fetched_at"]) < ttl
        return FeedResult(data=row["value"], source=row["source"],
                          fetched_at=row["fetched_at"], stale=not fresh)

    async def _fetch_cached(self, key: str, ttl: int, source: str,
                            url: str, params: Optional[Dict],
                            limiter: Optional[_RateLimiter]) -> FeedResult:
        """Return fresh cache, else fetch, else stale cache (graceful degrade)."""
        cached = self._cached_or_stale(key, ttl)
        if cached and not cached.stale:
            return cached
        try:
            data = await self._get_json(url, params, limiter)
            self.cache.set(key, data, source)
            return FeedResult(data=data, source=source, fetched_at=time.time())
        except Exception as e:      # noqa: BLE001
            if cached:  # serve stale, flagged
                logger.warning(f"[feeds] {source} unreachable — serving stale cache "
                               f"(age {cached.age_sec:.0f}s): {e}")
                cached.error = str(e)
                return cached
            logger.error(f"[feeds] {source} unreachable and no cache: {e}")
            return FeedResult(data=None, source=source, fetched_at=0.0,
                              stale=True, error=str(e))

    # ── public feed methods ──

    async def nvd_cve(self, cve_id: str) -> FeedResult:
        """Fetch a single CVE record from NVD v2."""
        key = f"nvd:cve:{cve_id.upper()}"
        return await self._fetch_cached(
            key, TTL_NVD, "nvd", NVD_URL, {"cveId": cve_id.upper()},
            self._nvd_limiter)

    async def nvd_cpe(self, cpe_name: str, results: int = 20) -> FeedResult:
        """Fetch CVEs matching a CPE name from NVD v2."""
        key = f"nvd:cpe:{cpe_name}"
        return await self._fetch_cached(
            key, TTL_NVD, "nvd", NVD_URL,
            {"cpeName": cpe_name, "resultsPerPage": results}, self._nvd_limiter)

    async def epss(self, cve_ids: List[str]) -> FeedResult:
        """Fetch EPSS scores for a batch of CVE ids."""
        ids = ",".join(sorted({c.upper() for c in cve_ids if c}))
        key = f"epss:{ids}"
        if not ids:
            return FeedResult(data={"data": []}, source="epss", fetched_at=time.time())
        return await self._fetch_cached(
            key, TTL_EPSS, "epss", EPSS_URL, {"cve": ids}, None)

    async def kev_catalog(self) -> FeedResult:
        """Fetch the full CISA KEV catalog (cached whole)."""
        return await self._fetch_cached(
            "kev:catalog", TTL_KEV, "kev", KEV_URL, None, None)

    async def kev_cve_ids(self) -> set:
        """Return the set of KEV CVE ids (empty set on total failure)."""
        res = await self.kev_catalog()
        ids = set()
        if res.data and isinstance(res.data, dict):
            for v in res.data.get("vulnerabilities", []):
                cid = v.get("cveID")
                if cid:
                    ids.add(cid.upper())
        return ids
