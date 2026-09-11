from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_ALLOWED_KINDS = frozenset({"note", "tool", "result", "dm", "finding", "beacon"})
_MAX_BODY_BYTES = 64 * 1024  # 64 KiB per entry — enough for a JSON finding


def _get_db_manager():
    try:
        from core.database.pg_store import DatabaseManager
        return DatabaseManager
    except Exception as e:
        logger.debug(f"[Scratchpad] DatabaseManager unavailable: {e}")
        return None


def _ensure_table() -> None:
    dbm = _get_db_manager()
    if dbm is None:
        return
    with dbm.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS agent_scratchpad (
                    id           BIGSERIAL PRIMARY KEY,
                    scan_id      TEXT NOT NULL,
                    agent_id     TEXT NOT NULL,
                    kind         TEXT NOT NULL,
                    topic        TEXT NOT NULL DEFAULT '',
                    to_agent     TEXT NOT NULL DEFAULT '',
                    body         JSONB NOT NULL,
                    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS ix_scratchpad_scan_topic
                    ON agent_scratchpad(scan_id, topic, created_at DESC)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS ix_scratchpad_dm
                    ON agent_scratchpad(scan_id, to_agent, created_at DESC)
                    WHERE to_agent <> ''
            """)
        conn.commit()


def _sanitize_id(s: str, maxlen: int = 128) -> str:
    if not s:
        return ""
    return re.sub(r"[^\w.:@\-/]", "_", str(s))[:maxlen]


@dataclass
class ScratchpadEntry:
    id: int
    scan_id: str
    agent_id: str
    kind: str
    topic: str
    to_agent: str
    body: Dict[str, Any]
    created_at_iso: str


class Scratchpad:

    def __init__(self, scan_id: str, agent_id: str):
        self.scan_id = _sanitize_id(scan_id) or "unscoped"
        self.agent_id = _sanitize_id(agent_id) or "unknown"
        try:
            _ensure_table()
        except Exception as e:
            logger.debug(f"[Scratchpad] ensure_table failed: {e}")

    def post(self, kind: str, body: Dict[str, Any],
             topic: str = "", to_agent: str = "") -> Optional[int]:
        if kind not in _ALLOWED_KINDS:
            logger.warning(f"[Scratchpad] rejected unknown kind={kind!r}")
            return None
        topic = _sanitize_id(topic)
        to_agent = _sanitize_id(to_agent)
        try:
            js = json.dumps(body, default=str)
        except (TypeError, ValueError):
            js = json.dumps({"repr": repr(body)[:2000]})
        if len(js.encode("utf-8")) > _MAX_BODY_BYTES:
            js = json.dumps({"truncated": True,
                             "preview": js[:_MAX_BODY_BYTES // 2]})
        dbm = _get_db_manager()
        if dbm is None:
            return None
        with dbm.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO agent_scratchpad
                        (scan_id, agent_id, kind, topic, to_agent, body)
                    VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                    RETURNING id
                """, (self.scan_id, self.agent_id, kind, topic, to_agent, js))
                row = cur.fetchone()
            conn.commit()
            return int(row[0]) if row else None

    def tail(self, topic: str = "", kind: Optional[str] = None,
             since_id: int = 0, limit: int = 100) -> List[ScratchpadEntry]:
        clauses = ["scan_id = %s", "id > %s"]
        args: List[Any] = [self.scan_id, since_id]
        if topic:
            clauses.append("topic = %s")
            args.append(_sanitize_id(topic))
        if kind:
            clauses.append("kind = %s")
            args.append(kind)
        sql = (f"SELECT id, scan_id, agent_id, kind, topic, to_agent, body, "
               f"created_at::text FROM agent_scratchpad WHERE "
               f"{' AND '.join(clauses)} ORDER BY id DESC LIMIT %s")
        args.append(int(limit))
        dbm = _get_db_manager()
        if dbm is None:
            return []
        with dbm.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, args)
                rows = cur.fetchall()
        out: List[ScratchpadEntry] = []
        for r in rows or []:
            body = r[6] if isinstance(r[6], dict) else {}
            out.append(ScratchpadEntry(
                id=r[0], scan_id=r[1], agent_id=r[2], kind=r[3],
                topic=r[4], to_agent=r[5], body=body, created_at_iso=r[7]))
        return out

    def inbox(self, since_id: int = 0, limit: int = 100) -> List[ScratchpadEntry]:
        dbm = _get_db_manager()
        if dbm is None:
            return []
        with dbm.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, scan_id, agent_id, kind, topic, to_agent, body,
                           created_at::text
                    FROM agent_scratchpad
                    WHERE scan_id = %s AND to_agent = %s AND id > %s
                    ORDER BY id DESC LIMIT %s
                """, (self.scan_id, self.agent_id, since_id, int(limit)))
                rows = cur.fetchall()
        return [ScratchpadEntry(
            id=r[0], scan_id=r[1], agent_id=r[2], kind=r[3],
            topic=r[4], to_agent=r[5],
            body=r[6] if isinstance(r[6], dict) else {},
            created_at_iso=r[7]) for r in rows or []]

    def request(self, topic: str, body: Dict[str, Any],
                to_agent: str = "") -> Optional[int]:
        return self.post("note", {"request": True, **body},
                         topic=topic, to_agent=to_agent)

    def announce_finding(self, finding: Dict[str, Any]) -> Optional[int]:
        return self.post("finding", finding, topic=str(finding.get("type", "misc")))

    def clear_scan(self) -> int:
        dbm = _get_db_manager()
        if dbm is None:
            return 0
        with dbm.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM agent_scratchpad WHERE scan_id = %s",
                            (self.scan_id,))
                n = cur.rowcount or 0
            conn.commit()
            return n


# ── Module-level singleton cache — one Scratchpad per (scan_id, agent_id) ──
_pads: Dict[str, Scratchpad] = {}


def get_scratchpad(scan_id: str, agent_id: str) -> Scratchpad:
    key = f"{scan_id}::{agent_id}"
    if key not in _pads:
        _pads[key] = Scratchpad(scan_id, agent_id)
    return _pads[key]
