"""Process-wide handoff of the active scan's auth (headers + cookies + role map)
to executors that don't hold a reference to `shared_context`.

CentralBrain calls `set_active_auth(headers, cookies, sessions)` whenever the
session changes (after `_setup_auth_session`, after AgenticExecutor captures a
new JWT). Executors call `get_active_auth()` as a fallback when the
experiment's `input_parameters` doesn't carry an `auth_token`.

Kept intentionally global — the whole process runs one scan at a time.
"""
from __future__ import annotations
from typing import Any, Dict, Optional

_ACTIVE: Dict[str, Any] = {}


def set_active_auth(
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    sessions: Optional[Dict[str, Any]] = None,
) -> None:
    global _ACTIVE
    _ACTIVE = {
        "headers": dict(headers or {}),
        "cookies": dict(cookies or {}),
        "sessions": dict(sessions or {}),
    }


def get_active_auth() -> Dict[str, Any]:
    return dict(_ACTIVE)


def clear_active_auth() -> None:
    global _ACTIVE
    _ACTIVE = {}
