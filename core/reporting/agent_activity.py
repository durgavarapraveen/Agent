"""
AgentActivityLog — read-only timeline of what the agent did during a scan.

Records every significant action: tool execution, finding discovery, retest
results, critic verdicts, exploit attempts, phase transitions.  The human
sees WHAT was tested, HOW it was tested, and WHAT output was produced.

This is NOT the ReviewQueue (human worklist).  This is a passive, read-only
audit trail of agent behaviour.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Action categories shown in the UI
ACTION_PHASE = "phase"
ACTION_TOOL = "tool_run"
ACTION_FINDING = "finding"
ACTION_RETEST = "retest"
ACTION_CRITIC = "critic"
ACTION_EXPLOIT = "exploit"
ACTION_CREDENTIAL = "credential"
ACTION_INJECTION = "injection"
ACTION_BROWSER = "browser"
ACTION_ERROR = "error"
ACTION_DECISION = "decision"


def _pg():
    try:
        from core.database.pg_store import ActivityLogRepo
        ActivityLogRepo.list_by_scan("__ping__", limit=1)
        return ActivityLogRepo
    except Exception:
        return None


class AgentActivityLog:
    """Append-only activity log backed by Postgres (file fallback if DB unreachable)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._buffer: List[Dict[str, Any]] = []

    def record(
        self,
        scan_id: str,
        action: str,
        title: str,
        detail: str = "",
        tool: str = "",
        target: str = "",
        phase: str = "",
        input_data: str = "",
        output_data: str = "",
        status: str = "ok",
        duration_s: float = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        rec = {
            "id": uuid.uuid4().hex[:12],
            "scan_id": scan_id,
            "timestamp": now,
            "action": action,
            "title": title[:500],
            "detail": str(detail)[:2000],
            "tool": tool[:100],
            "target": target[:500],
            "phase": phase[:50],
            "input_data": str(input_data)[:3000],
            "output_data": str(output_data)[:5000],
            "status": status[:30],
            "duration_s": round(duration_s, 2),
            "metadata": metadata or {},
        }

        repo = _pg()
        if repo is not None:
            try:
                repo.insert(rec)
                return rec
            except Exception as e:
                logger.debug(f"[Activity] pg insert failed, buffering: {e}")

        with self._lock:
            self._buffer.append(rec)
            if len(self._buffer) > 5000:
                self._buffer = self._buffer[-5000:]
        return rec

    def get(self, scan_id: str, limit: int = 500) -> List[Dict[str, Any]]:
        repo = _pg()
        if repo is not None:
            try:
                return repo.list_by_scan(scan_id, limit)
            except Exception:
                pass
        with self._lock:
            return [r for r in self._buffer if r.get("scan_id") == scan_id][-limit:]

    def flush_buffer_to_pg(self):
        repo = _pg()
        if repo is None or not self._buffer:
            return
        with self._lock:
            buf = list(self._buffer)
            self._buffer.clear()
        for rec in buf:
            try:
                repo.insert(rec)
            except Exception:
                pass


_INSTANCE: Optional[AgentActivityLog] = None


def get_activity_log() -> AgentActivityLog:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = AgentActivityLog()
    return _INSTANCE
