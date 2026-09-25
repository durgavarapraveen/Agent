"""LLM I/O log — records every request→response, in order, per scan.

Feeds the UI "LLM I/O" tab so the operator can audit exactly what each model
was asked and what it returned. Fire-and-forget: a logging failure must never
break an LLM call. Prompts/responses are secret-scrubbed and length-capped
before they hit the DB (they are shown over the wire).
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_MAX = 24000  # per-field char cap; long prompts/responses are truncated

# Redact obvious secrets from free text before storing.
_SECRET_RES = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?[A-Za-z0-9._\-]{12,}"), r"\1\2••••"),
    (re.compile(r"(?i)\b(api[_-]?key|token|password|secret)(\"?\s*[:=]\s*\"?)[^\s\"',]{6,}"), r"\1\2••••"),
    (re.compile(r"\beyJ[A-Za-z0-9._\-]{20,}"), "••••jwt••••"),          # JWTs
    (re.compile(r"\b(sk|xoxb|ghp|AKIA)[A-Za-z0-9_\-]{16,}"), "••••key••••"),
]


def _scrub(s: str) -> str:
    s = str(s or "")
    for rx, repl in _SECRET_RES:
        try:
            s = rx.sub(repl, s)
        except Exception:
            pass
    return s[:_MAX]


def current_scan_id() -> str:
    return os.getenv("ANTIGRAVITY_SCAN_ID", "") or ""


def log(scan_id: str, *, provider: str = "", model: str = "", tier: str = "",
        kind: str = "text", system: str = "", prompt: str = "", response: str = "",
        tokens_in: int = 0, tokens_out: int = 0, cost_usd: float = 0.0,
        duration_ms: int = 0, error: str = "") -> None:
    """Record one LLM call. Never raises."""
    scan_id = scan_id or current_scan_id()
    if not scan_id:
        return
    # ZDR: never persist prompt/response CONTENT — keep metadata only.
    try:
        from core.llm.zdr import persist_content_allowed
        if not persist_content_allowed():
            system = prompt = response = ""
            kind = (kind or "text") + "|zdr"
    except Exception:
        pass
    try:
        from core.database.pg_store import DatabaseManager
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO llm_calls
                        (scan_id, provider, model, tier, kind, system_prompt,
                         prompt, response, tokens_in, tokens_out, cost_usd,
                         duration_ms, error)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (scan_id, str(provider)[:120], str(model)[:120], str(tier)[:20],
                     str(kind)[:20], _scrub(system), _scrub(prompt), _scrub(response),
                     int(tokens_in or 0), int(tokens_out or 0), float(cost_usd or 0.0),
                     int(duration_ms or 0), str(error or "")[:500]),
                )
                conn.commit()
    except Exception as e:
        logger.debug(f"[LLMLog] log skipped: {e}")


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
                    SELECT id, provider, model, tier, kind, system_prompt, prompt,
                           response, tokens_in, tokens_out, cost_usd, duration_ms,
                           error, created_at
                    FROM llm_calls WHERE scan_id=%s AND id > %s
                    ORDER BY id ASC LIMIT %s
                    """,
                    (scan_id, int(since_id or 0), int(limit)),
                )
                rows = []
                for r in cur.fetchall():
                    r = dict(r)
                    if r.get("created_at") and not isinstance(r["created_at"], str):
                        r["created_at"] = r["created_at"].isoformat()
                    if r.get("cost_usd") is not None:
                        r["cost_usd"] = float(r["cost_usd"])
                    rows.append(r)
                return rows
    except Exception as e:
        logger.debug(f"[LLMLog] recent failed: {e}")
        return []


def summary(scan_id: str) -> Dict[str, Any]:
    if not scan_id:
        return {}
    try:
        from core.database.pg_store import DatabaseManager
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*), COALESCE(SUM(tokens_in),0), COALESCE(SUM(tokens_out),0), "
                    "COALESCE(SUM(cost_usd),0) FROM llm_calls WHERE scan_id=%s", (scan_id,))
                n, ti, to, cost = cur.fetchone()
                return {"calls": int(n), "tokens_in": int(ti or 0),
                        "tokens_out": int(to or 0), "cost_usd": round(float(cost or 0.0), 4)}
    except Exception:
        return {}
