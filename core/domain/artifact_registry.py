from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional


class ArtifactType(str, Enum):
    OPENAPI = "OPENAPI"
    SWAGGER = "SWAGGER"
    GRAPHQL_SCHEMA = "GRAPHQL_SCHEMA"
    JS_BUNDLE = "JS_BUNDLE"
    SOURCE_CODE = "SOURCE_CODE"
    ROBOTS = "ROBOTS"
    SITEMAP = "SITEMAP"
    AUTH_METADATA = "AUTH_METADATA"


# Substring hints → artifact type (order matters; first match wins).
_HINTS = [
    ("swagger.json", ArtifactType.SWAGGER), ("swagger.yaml", ArtifactType.SWAGGER),
    ("swagger.yml", ArtifactType.SWAGGER), ("/swagger", ArtifactType.SWAGGER),
    ("openapi.json", ArtifactType.OPENAPI), ("openapi.yaml", ArtifactType.OPENAPI),
    ("openapi.yml", ArtifactType.OPENAPI), ("/openapi", ArtifactType.OPENAPI),
    ("v3/api-docs", ArtifactType.OPENAPI), ("v2/api-docs", ArtifactType.OPENAPI),
    ("api-docs", ArtifactType.OPENAPI),
    (".well-known/openid-configuration", ArtifactType.AUTH_METADATA),
    ("oauth-authorization-server", ArtifactType.AUTH_METADATA),
    ("graphql", ArtifactType.GRAPHQL_SCHEMA), ("graphiql", ArtifactType.GRAPHQL_SCHEMA),
    ("robots.txt", ArtifactType.ROBOTS), ("sitemap.xml", ArtifactType.SITEMAP),
]


def classify_url(url: str) -> Optional[ArtifactType]:
    u = (url or "").lower()
    for hint, t in _HINTS:
        if hint in u:
            return t
    if u.endswith(".js") or ".chunk.js" in u or ".bundle." in u or u.endswith(".mjs"):
        return ArtifactType.JS_BUNDLE
    return None


@dataclass
class Artifact:
    artifact_id: str
    artifact_type: str
    url: str
    source: str = ""
    status: str = "discovered"
    content_hash: str = ""
    body: str = ""
    in_scope: bool = True
    discovered_at: str = ""


def _tval(t) -> str:
    return t.value if hasattr(t, "value") else str(t)


class ArtifactRegistry:
    def __init__(self):
        self._items: Dict[str, Artifact] = {}

    def register(self, url: str, artifact_type=None, source: str = "",
                 body: str = "", in_scope: bool = True,
                 status: str = "discovered") -> Optional[Artifact]:
        if not url:
            return None
        t = artifact_type or classify_url(url)
        if t is None:
            return None
        tval = _tval(t)
        aid = "art_" + hashlib.sha256(f"{tval}:{url}".encode("utf-8")).hexdigest()[:16]
        if aid in self._items:
            a = self._items[aid]
            if body and not a.body:
                a.body = body
                a.content_hash = hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()[:16]
                a.status = "verified"
            return a
        a = Artifact(
            artifact_id=aid, artifact_type=tval, url=url, source=source,
            status="verified" if body else status,
            content_hash=(hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()[:16]
                          if body else ""),
            body=body, in_scope=in_scope,
            discovered_at=datetime.now(timezone.utc).isoformat(),
        )
        self._items[aid] = a
        return a

    def by_type(self, *types) -> List[Artifact]:
        want = {_tval(t) for t in types}
        return [a for a in self._items.values() if a.artifact_type in want]

    def urls_of(self, *types) -> List[str]:
        return [a.url for a in self.by_type(*types)]

    def all(self) -> List[Artifact]:
        return list(self._items.values())

    def summary(self) -> Dict:
        return {"total": len(self._items),
                "by_type": dict(Counter(a.artifact_type for a in self._items.values()))}


def harvest_from_ctx(ctx) -> ArtifactRegistry:
    reg = getattr(ctx, "artifact_registry", None)
    if reg is None:
        reg = ArtifactRegistry()
        try:
            ctx.artifact_registry = reg
        except Exception:
            pass

    def _iter_urls():
        eps = getattr(ctx, "endpoints", None)
        ep_iter = eps.values() if isinstance(eps, dict) else (eps or [])
        for e in ep_iter:
            if isinstance(e, str):
                yield e
            elif isinstance(e, dict):
                yield e.get("url", "")
            else:
                yield getattr(e, "url", "")
        for r in (getattr(ctx, "captured_requests", []) or []):
            yield r.get("url", "") if isinstance(r, dict) else getattr(r, "url", "")
        ar = getattr(ctx, "asset_registry", None)
        if ar is not None:
            try:
                for a in ar.all():
                    yield a.source_url
            except Exception:
                pass

    for u in _iter_urls():
        t = classify_url(u)
        if t is not None:
            reg.register(u, artifact_type=t, source="recon_harvest")
    return reg
