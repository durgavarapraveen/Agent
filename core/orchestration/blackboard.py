"""Shared agent blackboard — a live cross-agent bus (delta 1).

Every agent in a scan posts what it learns (creds, findings, tool-results,
pivots, notes) to one place; every other agent — and the UI, which runs in a
separate process — reads the same rows. Postgres is the shared medium: the
scan runs in its own subprocess while the API server is a distinct process, so
an in-memory bus would not cross that boundary.

Design rules:
  * Fire-and-forget: a blackboard failure must NEVER break a scan. Every write
    is wrapped and swallowed.
  * Secrets are masked before they hit the board (defence-in-depth; the board
    is read by the UI over the wire).
  * Dedup on (scan_id, kind, ref) so parallel agents re-posting the same
    finding/cred collapse to one row.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

VALID_KINDS = ("finding", "cred", "tool", "pivot", "note")

_SECRET_KEYS = ("password", "passwd", "secret", "token", "api_key", "apikey",
                "authorization", "auth", "cookie", "session", "private_key",
                "bearer", "value")


def _mask(s: str) -> str:
    s = str(s or "")
    if len(s) <= 4:
        return "•" * len(s)
    return s[:2] + "•" * max(4, len(s) - 4) + s[-2:]


def _scrub(data: Any) -> Any:
    """Recursively mask values under secret-looking keys."""
    try:
        if isinstance(data, dict):
            out = {}
            for k, v in data.items():
                if isinstance(k, str) and k.lower() in _SECRET_KEYS and isinstance(v, (str, int, float)):
                    out[k] = _mask(str(v))
                else:
                    out[k] = _scrub(v)
            return out
        if isinstance(data, list):
            return [_scrub(x) for x in data]
        return data
    except Exception:
        return {}


def post(scan_id: str, agent_id: str, kind: str, title: str,
         data: Optional[Dict[str, Any]] = None, ref: str = "") -> None:
    """Post one entry to the shared blackboard. Never raises."""
    if not scan_id:
        return
    kind = kind if kind in VALID_KINDS else "note"
    try:
        from core.database.pg_store import DatabaseManager
        from core.utils.sanitize import clean_text, safe_json_dumps
        payload = safe_json_dumps(_scrub(data or {}))
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO agent_blackboard
                        (scan_id, agent_id, kind, title, data, ref)
                    VALUES (%s, %s, %s, %s, %s::jsonb, %s)
                    ON CONFLICT (scan_id, kind, ref) WHERE ref <> ''
                    DO NOTHING
                    """,
                    (scan_id, str(agent_id or "")[:120], kind,
                     clean_text(str(title))[:300], payload, str(ref or "")[:200]),
                )
                conn.commit()
    except Exception as e:
        logger.debug(f"[Blackboard] post skipped ({kind}): {e}")


def recent(scan_id: str, since_id: int = 0, limit: int = 200) -> List[Dict[str, Any]]:
    """Return blackboard entries newer than since_id (ascending)."""
    if not scan_id:
        return []
    try:
        from core.database.pg_store import DatabaseManager
        import psycopg2.extras
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT id, agent_id, kind, title, data, ref, created_at
                    FROM agent_blackboard
                    WHERE scan_id=%s AND id > %s
                    ORDER BY id ASC LIMIT %s
                    """,
                    (scan_id, int(since_id or 0), int(limit)),
                )
                rows = []
                for r in cur.fetchall():
                    r = dict(r)
                    if r.get("created_at") and not isinstance(r["created_at"], str):
                        r["created_at"] = r["created_at"].isoformat()
                    rows.append(r)
                return rows
    except Exception as e:
        logger.debug(f"[Blackboard] recent failed: {e}")
        return []


def summary(scan_id: str) -> Dict[str, int]:
    """Counts by kind for the live header."""
    if not scan_id:
        return {}
    try:
        from core.database.pg_store import DatabaseManager
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT kind, COUNT(*) FROM agent_blackboard WHERE scan_id=%s GROUP BY kind",
                    (scan_id,),
                )
                out = {k: 0 for k in VALID_KINDS}
                for kind, n in cur.fetchall():
                    out[kind] = int(n)
                out["total"] = sum(out.values())
                return out
    except Exception:
        return {}
