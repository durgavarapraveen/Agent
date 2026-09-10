"""Phase 14.1 — Multi-channel discovery.

Unifies crawling, browser traffic mining, sitemap/robots parsing, API schema
discovery, client-code extraction, passive metadata, link analysis, and legacy
endpoint discovery into one deduplicated inventory. Respects scope at every step.
"""
from __future__ import annotations

import hashlib
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class DiscoverySource(str, Enum):
    CRAWL = "crawl"
    BROWSER_TRAFFIC = "browser_traffic"
    SITEMAP = "sitemap"
    ROBOTS = "robots"
    API_SCHEMA = "api_schema"
    CLIENT_CODE = "client_code"
    PASSIVE_METADATA = "passive_metadata"
    LINK_ANALYSIS = "link_analysis"
    LEGACY = "legacy"
    MANUAL = "manual"


@dataclass
class DiscoveredAsset:
    asset_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    url: str = ""
    method: str = "GET"
    asset_type: str = "endpoint"
    source: DiscoverySource = DiscoverySource.CRAWL
    confidence: float = 1.0
    parameters: List[str] = field(default_factory=list)
    content_type: str = ""
    technology: str = ""
    authenticated: bool = False
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def canonical_key(self) -> str:
        parsed = urlparse(self.url)
        path = parsed.path.rstrip("/") or "/"
        return f"{self.method}:{parsed.scheme}://{parsed.netloc}{path}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id, "url": self.url, "method": self.method,
            "source": self.source.value, "confidence": self.confidence,
            "parameters": self.parameters, "technology": self.technology,
        }


class MultiChannelDiscovery:
    """Unified discovery inventory across all channels with scope enforcement."""

    def __init__(self, scope_checker: Optional[Callable[[str], bool]] = None):
        self._lock = threading.RLock()
        self._assets: Dict[str, DiscoveredAsset] = {}
        self._canonical_map: Dict[str, str] = {}
        self._sources_seen: Dict[str, Set[str]] = {}
        self._scope_checker = scope_checker

    def add_asset(self, asset: DiscoveredAsset) -> Optional[str]:
        if self._scope_checker and not self._scope_checker(asset.url):
            logger.debug(f"[Discovery] Out of scope: {asset.url}")
            return None
        canon = asset.canonical_key
        with self._lock:
            existing_id = self._canonical_map.get(canon)
            if existing_id:
                existing = self._assets[existing_id]
                existing.confidence = max(existing.confidence, asset.confidence)
                self._sources_seen.setdefault(existing_id, set()).add(asset.source.value)
                for p in asset.parameters:
                    if p not in existing.parameters:
                        existing.parameters.append(p)
                if asset.technology and not existing.technology:
                    existing.technology = asset.technology
                return existing_id
            self._assets[asset.asset_id] = asset
            self._canonical_map[canon] = asset.asset_id
            self._sources_seen[asset.asset_id] = {asset.source.value}
        return asset.asset_id

    def get_asset(self, asset_id: str) -> Optional[DiscoveredAsset]:
        return self._assets.get(asset_id)

    def get_all(self, source: Optional[DiscoverySource] = None,
                min_confidence: float = 0.0) -> List[DiscoveredAsset]:
        with self._lock:
            assets = list(self._assets.values())
        if source:
            assets = [a for a in assets
                      if source.value in self._sources_seen.get(a.asset_id, set())]
        if min_confidence > 0:
            assets = [a for a in assets if a.confidence >= min_confidence]
        return assets

    def get_sources_for(self, asset_id: str) -> Set[str]:
        return self._sources_seen.get(asset_id, set())

    def search(self, path_contains: str = "", method: str = "",
               technology: str = "") -> List[DiscoveredAsset]:
        with self._lock:
            results = list(self._assets.values())
        if path_contains:
            results = [a for a in results if path_contains in a.url]
        if method:
            results = [a for a in results if a.method == method.upper()]
        if technology:
            results = [a for a in results if technology.lower() in (a.technology or "").lower()]
        return results

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_source: Dict[str, int] = {}
            for sources in self._sources_seen.values():
                for s in sources:
                    by_source[s] = by_source.get(s, 0) + 1
        return {
            "total_assets": len(self._assets),
            "unique_canonical": len(self._canonical_map),
            "by_source": by_source,
        }

    def export(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._assets.values()]
