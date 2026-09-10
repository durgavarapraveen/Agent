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
