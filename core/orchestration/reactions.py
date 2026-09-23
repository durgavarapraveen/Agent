"""Reactive triggers — the event side of the shared blackboard.

Agents coordinate through the blackboard (shared state). Normally a consumer only
sees a post on its next turn. For a few HIGH-VALUE events we want an IMMEDIATE
reaction instead of waiting for the next phase — e.g. the moment an agent gains
access (`pivot`) or harvests credentials (`cred`), re-run the authenticated
battery so IDOR/BOLA/authz probes fire with the new session.

This module is intentionally tiny and SAFE: `blackboard.post()` only RECORDS a
pending reaction here (cheap, no work done inside the DB transaction). The
orchestrator drains it between phase iterations and runs the actual (bounded,
capped, flag-gated) re-test. Thread-safe, never raises.
"""
from __future__ import annotations

import os
import threading
from typing import Any, Dict, List

_LOCK = threading.Lock()
_PENDING: Dict[str, List[Dict[str, Any]]] = {}   # scan_id -> queued trigger entries
_REACTED: Dict[str, int] = {}                    # scan_id -> reactions already run


def enabled() -> bool:
    return (os.getenv("NEO_REACTIVE_RETEST", "1") or "1").strip().lower() not in ("0", "false", "no", "off")


def max_reactions() -> int:
    try:
        return int(os.getenv("NEO_REACTIVE_RETEST_MAX", "2"))
    except Exception:
        return 2


def request(scan_id: str, trigger: str, meta: Dict[str, Any] = None) -> None:
    """Record a pending reaction. Called from blackboard.post — must stay cheap."""
    if not scan_id or not enabled():
        return
    try:
        with _LOCK:
            q = _PENDING.setdefault(scan_id, [])
            # De-dup identical triggers so a burst of pivots enqueues once.
            if not any(e.get("trigger") == trigger for e in q):
                q.append({"trigger": trigger, "meta": meta or {}})
    except Exception:
        pass


def take(scan_id: str) -> List[Dict[str, Any]]:
    """Pop and return all pending reactions for a scan."""
    with _LOCK:
        return _PENDING.pop(scan_id, [])


def note_reacted(scan_id: str) -> int:
    with _LOCK:
        _REACTED[scan_id] = _REACTED.get(scan_id, 0) + 1
        return _REACTED[scan_id]


def reacted_count(scan_id: str) -> int:
    with _LOCK:
        return _REACTED.get(scan_id, 0)
