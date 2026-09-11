from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlsplit


def _origin_of(url: str) -> str:
    try:
        p = urlsplit(url)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
    except Exception:
        pass
    return ""


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


@dataclass
class Asset:
    asset_id: str
    source_url: str                 # the URL exactly as discovered (authoritative)
    resolved_url: str = ""          # URL actually fetched (defaults to source_url)
    origin: str = ""                # scheme://host[:port] the asset was served from
    origin_host: str = ""
    discovered_by: str = ""
    content_type: str = ""
    status_code: Optional[int] = None
    in_scope: bool = True
    parent_endpoint: str = ""
    first_seen: str = ""

    def as_dict(self) -> Dict:
        return {
            "asset_id": self.asset_id, "source_url": self.source_url,
            "resolved_url": self.resolved_url, "origin": self.origin,
            "origin_host": self.origin_host, "discovered_by": self.discovered_by,
            "content_type": self.content_type, "status_code": self.status_code,
            "in_scope": self.in_scope, "parent_endpoint": self.parent_endpoint,
        }


def _asset_id(source_url: str) -> str:
    return "as_" + hashlib.sha256((source_url or "").encode("utf-8")).hexdigest()[:20]


class AssetRegistry:
    def __init__(self):
        self._assets: Dict[str, Asset] = {}
        self._by_url: Dict[str, str] = {}       # source_url -> asset_id
        self._origin_hits: Dict[str, int] = {}  # origin -> count (for primary_origin)

    def register(self, source_url: str, discovered_by: str = "",
                 parent_endpoint: str = "", content_type: str = "",
                 status_code: Optional[int] = None, in_scope: bool = True,
                 resolved_url: str = "") -> Optional[Asset]:
        if not source_url:
            return None
        origin = _origin_of(source_url)
        if not origin:
            # Not absolute — cannot anchor an origin; skip (caller should resolve).
            return None
        existing_id = self._by_url.get(source_url)
        if existing_id:
            a = self._assets[existing_id]
            # Enrich, never overwrite the authoritative source_url/origin.
            if content_type and not a.content_type:
                a.content_type = content_type
            if status_code is not None and a.status_code is None:
                a.status_code = status_code
            if resolved_url and not a.resolved_url:
                a.resolved_url = resolved_url
            return a
        aid = _asset_id(source_url)
        a = Asset(
            asset_id=aid, source_url=source_url,
            resolved_url=resolved_url or source_url,
            origin=origin, origin_host=_host_of(source_url),
            discovered_by=discovered_by, content_type=content_type,
            status_code=status_code, in_scope=in_scope,
            parent_endpoint=parent_endpoint,
        )
        self._assets[aid] = a
        self._by_url[source_url] = aid
        self._origin_hits[origin] = self._origin_hits.get(origin, 0) + 1
        return a

    def resolve(self, ref: str, base_origin: str) -> str:
        if not ref:
            return ""
        if _origin_of(ref):
            return ref                      # already absolute — keep its origin
        base = base_origin or self.primary_origin()
        if not base:
            return ref
        return urljoin(base.rstrip("/") + "/", ref.lstrip("/"))

    def primary_origin(self) -> str:
        if not self._origin_hits:
            return ""
        return max(self._origin_hits.items(), key=lambda kv: kv[1])[0]

    def get(self, asset_id: str) -> Optional[Asset]:
        return self._assets.get(asset_id)

    def all(self) -> List[Asset]:
        return list(self._assets.values())

    def js_assets(self) -> List[Asset]:
        out = []
        for a in self._assets.values():
            u = a.source_url.lower()
            if u.endswith(".js") or ".chunk.js" in u or ".bundle." in u or u.endswith(".mjs"):
                out.append(a)
        return out

    def js_urls(self) -> List[str]:
        return [a.source_url for a in self.js_assets()]

    def summary(self) -> Dict:
        return {
            "assets": len(self._assets),
            "js_assets": len(self.js_assets()),
            "origins": dict(self._origin_hits),
            "primary_origin": self.primary_origin(),
        }
