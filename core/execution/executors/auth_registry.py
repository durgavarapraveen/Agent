"""Process-wide handoff of the active scan's auth (headers + cookies + role map)
to executors that don't hold a reference to `shared_context`.

CentralBrain calls `set_active_auth(headers, cookies, sessions)` whenever the
session changes (after `_setup_auth_session`, after AgenticExecutor captures a
new JWT). Executors call `get_active_auth()` as a fallback when the
experiment's `input_parameters` doesn't carry an `auth_token`.

Kept intentionally global — the whole process runs one scan at a time — but
guarded by a lock so concurrent readers and the (rare) writer never observe a
half-updated dict.
"""
from __future__ import annotations

import threading
from typing import Any, Dict, Optional

_LOCK = threading.RLock()
_ACTIVE: Dict[str, Any] = {}


def set_active_auth(
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    sessions: Optional[Dict[str, Any]] = None,
) -> None:
    global _ACTIVE
    new = {
        "headers": dict(headers or {}),
        "cookies": dict(cookies or {}),
        "sessions": dict(sessions or {}),
    }
    with _LOCK:
        _ACTIVE = new


def get_active_auth() -> Dict[str, Any]:
    """Return a snapshot copy of the active auth. Readers get their own dict."""
    with _LOCK:
        return {
            "headers": dict(_ACTIVE.get("headers") or {}),
            "cookies": dict(_ACTIVE.get("cookies") or {}),
            "sessions": dict(_ACTIVE.get("sessions") or {}),
        }


def clear_active_auth() -> None:
    global _ACTIVE
    with _LOCK:
        _ACTIVE = {}
