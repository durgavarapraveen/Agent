"""HTTP exchange log — every request the agent sends + its response, deduped.

The Requests tab only showed browser-captured traffic. This records the actual
attack requests the agent makes (with their payloads) and the responses, so the
operator can see exactly what was sent and what came back. Deduped by a
canonical fingerprint (method + path + query-param NAMES + body shape) so the
same probe fired with a different random operand collapses to ONE row with a
hit count — "everything without duplicates".

Sensitive request headers (Authorization/Cookie) are redacted before storage;
bodies are size-capped. Never raises (accounting must not break a scan).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, parse_qsl

logger = logging.getLogger(__name__)

_MAX_BODY = 8000
_REDACT = {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}


def current_scan_id() -> str:
    return os.getenv("ANTIGRAVITY_SCAN_ID", "") or ""


def _canon_url(url: str) -> str:
    try:
        s = urlsplit(url)
        names = ",".join(sorted(k for k, _ in parse_qsl(s.query, keep_blank_values=True)))
        base = f"{s.scheme}://{s.netloc}{s.path}".lower().rstrip("/")
        return base + (f"?{names}" if names else "")
    except Exception:
        return (url or "").split("?")[0].lower()


def _body_shape(body: Any) -> str:
    """Operand-independent body signature: JSON→sorted keys; else length bucket."""
    if not body:
        return "-"
    s = body if isinstance(body, str) else str(body)
    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            return "json:" + ",".join(sorted(obj.keys()))
        if isinstance(obj, list):
            return f"jsonlist:{len(obj)}"
    except Exception:
        pass
    # form-encoded → key names
    if "=" in s and "\n" not in s[:200]:
        keys = sorted({p.split("=", 1)[0] for p in s.split("&") if p.split("=", 1)[0]})
        if keys:
            return "form:" + ",".join(keys)
    return f"len:{len(s) // 32 * 32}"


def _fingerprint(method: str, url: str, body: Any) -> str:
    key = f"{(method or 'GET').upper()}|{_canon_url(url)}|{_body_shape(body)}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def _redact_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    out = {}
    for k, v in (headers or {}).items():
        out[str(k)] = "[redacted]" if str(k).lower() in _REDACT else str(v)
    return out


def _cap(s: Any) -> str:
    s = s if isinstance(s, str) else ("" if s is None else str(s))
    return s[:_MAX_BODY]


def record_exchange(scan_id: str, method: str, url: str, *,
                    req_headers: Optional[Dict] = None, req_body: Any = "",
                    status: int = 0, resp_headers: Optional[Dict] = None,
                    resp_body: Any = "") -> None:
    scan_id = scan_id or current_scan_id()
    if not scan_id or not url:
        return
    fp = _fingerprint(method, url, req_body)
    try:
        from core.database.pg_store import DatabaseManager
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO http_exchanges
                        (scan_id, fingerprint, method, url, req_headers, req_body,
                         status, resp_headers, resp_body, hits, first_seen, last_seen)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,1,NOW(),NOW())
                    ON CONFLICT (scan_id, fingerprint) DO UPDATE SET
                        hits = http_exchanges.hits + 1, last_seen = NOW(),
                        status = EXCLUDED.status, resp_body = EXCLUDED.resp_body
                    """,
                    (scan_id, fp, (method or "GET").upper(), url[:2048],
                     json.dumps(_redact_headers(req_headers)), _cap(req_body),
                     int(status or 0), json.dumps(_redact_headers(resp_headers)),
                     _cap(resp_body)))
                conn.commit()
    except Exception as e:
        logger.debug("[http_log] record skipped: %s", e)


def list_by_scan(scan_id: str, limit: int = 2000) -> list:
    try:
        from core.database.pg_store import DatabaseManager
        import psycopg2.extras
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT method, url, req_headers, req_body, status, resp_headers, "
                    "resp_body, hits, first_seen, last_seen FROM http_exchanges "
                    "WHERE scan_id=%s ORDER BY last_seen DESC LIMIT %s",
                    (scan_id, int(limit)))
                rows = []
                for r in cur.fetchall():
                    r = dict(r)
                    for k in ("req_headers", "resp_headers"):
                        if isinstance(r.get(k), str):
                            try:
                                r[k] = json.loads(r[k])
                            except Exception:
                                r[k] = {}
                    for k in ("first_seen", "last_seen"):
                        if r.get(k) and not isinstance(r[k], str):
                            r[k] = r[k].isoformat()
                    rows.append(r)
                return rows
    except Exception as e:
        logger.debug("[http_log] list skipped: %s", e)
        return []
