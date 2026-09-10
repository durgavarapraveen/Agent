from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlsplit

logger = logging.getLogger(__name__)

_ID_KEYS = ("id", "_id", "uuid", "guid", "userId", "user_id", "orderId",
            "order_id", "pk", "slug", "key")
_ENVELOPES = ("data", "result", "user", "order", "record", "item", "resource")
_CREATE_METHODS = {"POST", "PUT"}


def _guess_type(url: str) -> str:
    try:
        segs = [s for s in urlsplit(url).path.split("/") if s and not s.isdigit()]
        return segs[-1] if segs else "resource"
    except Exception:
        return "resource"


@dataclass
class Mutation:
    mutation_id: str
    session_id: str
    method: str
    endpoint: str          # collection URL used to create the resource
    resource_type: str
    resource_id: str
    resource_url: str      # best-effort deletable URL
    created_at: str
    cleanup_strategy: str = "http_delete"
    cleanup_status: str = "pending"


class MutationLedger:
    def __init__(self):
        self._items: List[Mutation] = []
        self._seen: set = set()

    @staticmethod
    def _extract_id(body_text: str, location: str):
        if location:
            rid = location.rstrip("/").split("/")[-1]
            return (rid or None), location
        data = None
        try:
            data = json.loads(body_text) if body_text else None
        except Exception:
            data = None

        def _search(obj, depth=0):
            if depth > 4 or not isinstance(obj, dict):
                return None
            for env in _ENVELOPES:
                if isinstance(obj.get(env), dict):
                    r = _search(obj[env], depth + 1)
                    if r:
                        return r
            for k in _ID_KEYS:
                v = obj.get(k)
                if isinstance(v, (str, int)) and str(v).strip():
                    return str(v)
            return None

        return (_search(data) if data is not None else None), None

    def record(self, method: str, url: str, status: int, body_text: str = "",
               headers: Optional[Dict[str, str]] = None,
               session_id: str = "anonymous",
               resource_type: str = "") -> Optional[Mutation]:
        method = (method or "").upper()
        if method not in _CREATE_METHODS or not url:
            return None
        try:
            if not (200 <= int(status) < 300):
                return None
        except Exception:
            return None
        headers = headers or {}
        location = headers.get("Location") or headers.get("location") or ""
        rid, loc_url = self._extract_id(body_text or "", location)
        if not rid:
            return None
        if loc_url:
            resource_url = loc_url if "://" in loc_url else urljoin(url, loc_url)
        else:
            resource_url = url.rstrip("/") + "/" + str(rid)
        key = (method, resource_url)
        if key in self._seen:
            return None
        self._seen.add(key)
        m = Mutation(
            mutation_id="mut_" + uuid.uuid4().hex[:10],
            session_id=session_id or "anonymous",
            method=method, endpoint=url,
            resource_type=resource_type or _guess_type(url),
            resource_id=str(rid), resource_url=resource_url,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._items.append(m)
        logger.info(f"MUTATION_TRACKED type={m.resource_type} id={rid} url={resource_url}")
        return m

    def entries(self) -> List[Mutation]:
        return list(self._items)

    def as_dicts(self) -> List[Dict[str, Any]]:
        return [asdict(m) for m in self._items]

    async def cleanup(self, auth_header: str = "", verify_ssl: bool = False) -> Dict[str, int]:
        report = {"total": len(self._items), "cleaned": 0, "failed": 0, "skipped": 0}
        if not self._items:
            return report
        try:
            import httpx
        except Exception as e:
            logger.warning(f"MUTATION_CLEANUP_UNAVAILABLE httpx import failed: {e}")
            for m in self._items:
                m.cleanup_status = "skipped"
            report["skipped"] = len(self._items)
            return report
        async with httpx.AsyncClient(verify=verify_ssl, timeout=15,
                                     follow_redirects=True) as client:
            for m in self._items:
                if m.cleanup_status == "success":
                    continue
                try:
                    hdrs = {"Authorization": auth_header} if auth_header else {}
                    r = await client.delete(m.resource_url, headers=hdrs)
                    if 200 <= r.status_code < 300 or r.status_code == 404:
                        m.cleanup_status = "success"
                        report["cleaned"] += 1
                    else:
                        m.cleanup_status = "failed"
                        report["failed"] += 1
                        logger.warning(f"MUTATION_CLEANUP_FAILED url={m.resource_url} "
                                       f"status={r.status_code}")
                except Exception as e:
                    m.cleanup_status = "failed"
                    report["failed"] += 1
                    logger.warning(f"MUTATION_CLEANUP_ERROR url={m.resource_url} {e}")
        logger.info(f"MUTATION_CLEANUP_DONE {report}")
        return report


def get_ledger(ctx) -> Optional[MutationLedger]:
    if ctx is None:
        return None
    led = getattr(ctx, "mutation_ledger", None)
    if led is None:
        led = MutationLedger()
        try:
            ctx.mutation_ledger = led
        except Exception:
            return led
    return led
