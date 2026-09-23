"""Canonical extraction of the active session's auth headers from a scan ctx.

Single source of truth for "give me the headers that make an authenticated
request", so probes/miners/verifiers don't each re-derive it. Generic: reads
``ctx.auth_headers`` first, then falls back to ``ctx.get_active_auth()`` — no
scheme or target assumptions. Best-effort; returns {} on any failure.
"""
from __future__ import annotations

from typing import Any, Dict


def auth_headers_from_ctx(ctx: Any) -> Dict[str, str]:
    """Return the active auth headers for ``ctx`` as a str->str dict, or {}."""
    try:
        h = dict(getattr(ctx, "auth_headers", None) or {})
        if h:
            return {str(k): str(v) for k, v in h.items()}
        getter = getattr(ctx, "get_active_auth", None)
        sess = getter() if callable(getter) else None
        if not sess:
            return {}
        hdr = getattr(sess, "headers", None)
        if hdr is None and isinstance(sess, dict):
            hdr = sess.get("headers")
        return {str(k): str(v) for k, v in (hdr or {}).items()}
    except Exception:
        return {}
