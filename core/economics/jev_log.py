"""Jev decision log — records every typed decision Jev made, in order, per scan.

Feeds the UI "Jev Decisions" tab so the operator can audit exactly what Jev was
asked (state + question), what it decided (value + probability), and where in the
harness the decision was made (routing / phase_gate / tool_gate / triage).

Fire-and-forget: a logging failure must never break a decision. State/question
text is secret-scrubbed and length-capped before storage (it is shown over the
wire). Mirrors core/economics/llm_log.py.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

from core.economics.llm_log import _scrub  # reuse the same secret scrubber

logger = logging.getLogger(__name__)


def current_scan_id() -> str:
    return os.getenv("ANTIGRAVITY_SCAN_ID", "") or ""


def log(scan_id: str, *, site: str = "", decision_type: str = "",
        question: str = "", state_preview: str = "", value: str = "",
        probability: float = 0.0, model: str = "", duration_ms: int = 0,
        error: str = "") -> None:
    """Record one Jev decision. Never raises."""
    scan_id = scan_id or current_scan_id()
    if not scan_id:
        return
    try:
        from core.database.pg_store import DatabaseManager
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO jev_decisions
                        (scan_id, site, decision_type, question, state_preview,
                         value, probability, model, duration_ms, error)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (scan_id, str(site)[:40], str(decision_type)[:20],
                     _scrub(question), _scrub(state_preview), str(value)[:200],
                     float(probability or 0.0), str(model)[:120],
                     int(duration_ms or 0), str(error or "")[:500]),
                )
                conn.commit()
    except Exception as e:
        logger.debug(f"[JevLog] log skipped: {e}")


def recent(scan_id: str, since_id: int = 0, limit: int = 200) -> List[Dict[str, Any]]:
    if not scan_id:
        return []
    try:
        from core.database.pg_store import DatabaseManager
        import psycopg2.extras
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT id, site, decision_type, question, state_preview, value,
                           probability, model, duration_ms, error, created_at
                    FROM jev_decisions WHERE scan_id=%s AND id > %s
                    ORDER BY id ASC LIMIT %s
                    """,
                    (scan_id, int(since_id or 0), int(limit)),
                )
                rows = []
                for r in cur.fetchall():
                    r = dict(r)
                    if r.get("created_at") and not isinstance(r["created_at"], str):
                        r["created_at"] = r["created_at"].isoformat()
                    if r.get("probability") is not None:
                        r["probability"] = float(r["probability"])
                    rows.append(r)
                return rows
    except Exception as e:
        logger.debug(f"[JevLog] recent failed: {e}")
        return []


def summary(scan_id: str) -> Dict[str, Any]:
    if not scan_id:
        return {}
    try:
        from core.database.pg_store import DatabaseManager
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*), COALESCE(AVG(probability),0) "
                    "FROM jev_decisions WHERE scan_id=%s", (scan_id,))
                n, avg_p = cur.fetchone()
                cur.execute(
                    "SELECT site, COUNT(*) FROM jev_decisions WHERE scan_id=%s "
                    "GROUP BY site", (scan_id,))
                by_site = {str(s): int(c) for s, c in cur.fetchall()}
                return {"decisions": int(n), "avg_probability": round(float(avg_p or 0.0), 3),
                        "by_site": by_site}
    except Exception:
        return {}
