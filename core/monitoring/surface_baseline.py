"""Phase 3.1 — attack-surface baseline & diff (PTaaS).

After a full scan we persist the complete attack surface (subdomains, endpoints,
params, response schemas, JS file hashes, DNS records). On the next scan we diff
against the baseline and return only the changed/new items, so recurring scans
re-test only what moved instead of everything.

Reuse:
  * ``AttackSurfaceState`` (core.attack_surface) is the in-memory surface model;
    :meth:`SurfaceBaseline.snapshot` serializes it (or a shared-context/dict).
  * ``scan_diff`` diffs *findings* between scans; this diffs the *surface*.
  * ``workflow_crawler.normalize_path`` gives stable endpoint identities.

The snapshot/diff logic is pure and unit-testable. Persistence defaults to a
JSON file (works with no DB); production may back it with an
``attack_surface_snapshots`` table — call :meth:`save`/`load_latest` with a
DB-backed store when Postgres is configured.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.discovery.workflow_crawler import normalize_path

logger = logging.getLogger(__name__)

_BASELINE_DIR = Path("data") / "baselines"


@dataclass
class SurfaceSnapshot:
    target: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    subdomains: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)        # "METHOD path"
    params: Dict[str, List[str]] = field(default_factory=dict)  # endpoint -> param names
    js_hashes: Dict[str, str] = field(default_factory=dict)     # url -> content hash
    dns_records: List[str] = field(default_factory=list)
    response_schemas: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SurfaceSnapshot":
        return cls(
            target=d.get("target", ""),
            created_at=d.get("created_at", ""),
            subdomains=list(d.get("subdomains", [])),
            endpoints=list(d.get("endpoints", [])),
            params={k: list(v) for k, v in (d.get("params", {}) or {}).items()},
            js_hashes=dict(d.get("js_hashes", {}) or {}),
            dns_records=list(d.get("dns_records", [])),
            response_schemas=dict(d.get("response_schemas", {}) or {}),
        )


def _endpoint_key(method: str, url_or_path: str) -> str:
    return f"{(method or 'GET').upper()} {normalize_path(url_or_path)}"


class SurfaceBaseline:

    def snapshot(self, source: Any, target: str = "") -> SurfaceSnapshot:
        """Serialize an AttackSurfaceState / shared-context / plain dict into a
        normalized surface snapshot."""
        def _g(name, default):
            if isinstance(source, dict):
                return source.get(name, default)
            return getattr(source, name, default)

        target = target or _g("target", "") or ""
        subdomains = sorted(set(str(s) for s in (_g("subdomains", []) or [])))

        endpoints_set = set()
        params: Dict[str, List[str]] = {}
        raw_eps = _g("endpoints", []) or []
        # endpoints may be a dict (AttackSurfaceState.endpoints) or a list.
        raw_iter = raw_eps.values() if isinstance(raw_eps, dict) else raw_eps
        for ep in raw_iter:
            if isinstance(ep, dict):
                url = ep.get("url", "") or ep.get("path", "")
                method = ep.get("method", "GET")
                p = ep.get("params")
            else:
                url = getattr(ep, "url", "") or getattr(ep, "path", "")
                method = getattr(ep, "method", "GET")
                p = getattr(ep, "params", None)
            if not url:
                continue
            key = _endpoint_key(method, url)
            endpoints_set.add(key)
            if p:
                names = self._param_names(p)
                if names:
                    params[key] = sorted(set(params.get(key, []) + names))

        js_hashes = self._js_hashes(_g("js_endpoints", []) or [])
        dns_records = sorted(set(str(r) for r in (_g("dns_records", []) or [])))

        return SurfaceSnapshot(
            target=target, subdomains=subdomains,
            endpoints=sorted(endpoints_set), params=params,
            js_hashes=js_hashes, dns_records=dns_records,
            response_schemas=dict(_g("response_schemas", {}) or {}))

    @staticmethod
    def _param_names(p: Any) -> List[str]:
        if isinstance(p, dict):
            return [str(k) for k in p.keys()]
        if isinstance(p, (list, tuple, set)):
            out = []
            for item in p:
                out.append(item.get("name", str(item)) if isinstance(item, dict) else str(item))
            return out
        if isinstance(p, str):
            return [s.strip() for s in p.replace("&", ",").split(",") if s.strip()]
        return []

    @staticmethod
    def _js_hashes(js_endpoints: Any) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for j in js_endpoints:
            if isinstance(j, dict):
                url = j.get("url", "")
                h = j.get("hash") or j.get("content_hash")
                content = j.get("content")
            else:
                url, h, content = str(j), None, None
            if not url:
                continue
            if not h and content is not None:
                h = hashlib.sha256(str(content).encode("utf-8", "ignore")).hexdigest()[:16]
            out[url] = h or ""
        return out

    def diff(self, old: SurfaceSnapshot, new: SurfaceSnapshot) -> Dict[str, Any]:
        old_eps, new_eps = set(old.endpoints), set(new.endpoints)
        added_eps = sorted(new_eps - old_eps)
        removed_eps = sorted(old_eps - new_eps)

        # Param changes on endpoints present in both.
        changed_params: Dict[str, Dict[str, List[str]]] = {}
        for ep in new_eps & old_eps:
            before, after = set(old.params.get(ep, [])), set(new.params.get(ep, []))
            if before != after:
                changed_params[ep] = {"added": sorted(after - before),
                                      "removed": sorted(before - after)}

        # JS hash changes.
        changed_js = sorted(u for u, h in new.js_hashes.items()
                            if u in old.js_hashes and old.js_hashes[u] != h)
        added_js = sorted(set(new.js_hashes) - set(old.js_hashes))

        added_subs = sorted(set(new.subdomains) - set(old.subdomains))
        removed_subs = sorted(set(old.subdomains) - set(new.subdomains))
        added_dns = sorted(set(new.dns_records) - set(old.dns_records))

        return {
            "target": new.target,
            "endpoints": {"added": added_eps, "removed": removed_eps},
            "params_changed": changed_params,
            "js": {"added": added_js, "changed": changed_js},
            "subdomains": {"added": added_subs, "removed": removed_subs},
            "dns": {"added": added_dns},
            "has_changes": bool(added_eps or removed_eps or changed_params or
                                changed_js or added_js or added_subs or removed_subs or added_dns),
        }

    def changed_for_rescan(self, diff: Dict[str, Any]) -> List[str]:
        """The endpoint identities worth re-scanning: new endpoints, endpoints
        whose params changed, and endpoints serving changed JS."""
        out = set(diff.get("endpoints", {}).get("added", []))
        out.update(diff.get("params_changed", {}).keys())
        return sorted(out)

    # ── Persistence (JSON file; swap for a DB-backed store in production) ─────
    def save(self, snapshot: SurfaceSnapshot, path: Optional[str] = None) -> str:
        p = Path(path) if path else _BASELINE_DIR / f"{self._slug(snapshot.target)}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(snapshot.to_dict(), indent=2), encoding="utf-8")
        return str(p)

    def load_latest(self, target: str, path: Optional[str] = None) -> Optional[SurfaceSnapshot]:
        p = Path(path) if path else _BASELINE_DIR / f"{self._slug(target)}.json"
        if not p.exists():
            return None
        try:
            return SurfaceSnapshot.from_dict(json.loads(p.read_text(encoding="utf-8")))
        except Exception as e:
            logger.warning("surface_baseline: failed to load %s (%s)", p, e)
            return None

    @staticmethod
    def _slug(target: str) -> str:
        return "".join(c if c.isalnum() else "_" for c in (target or "target"))[:120]
