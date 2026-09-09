"""P0.2 — explicit request identity; stops ambient auth contamination.

Root cause fixed: a JWT captured mid-scan was written to three ungated stores
(``agentic_executor._captured_tokens``, ``ctx.auth_headers``, and the process
global ``auth_registry.set_active_auth``) and then auto-attached to *every*
later same-host request that omitted its own Authorization header. An anonymous
or access-control probe therefore ran silently as the captured — possibly
admin — identity.

This module is the single deterministic authority for "what token, if any, may
this request use". It is independent of any LLM instruction.

Rule enforced:
  * explicit anonymous session  -> NO Authorization header, ever.
  * explicit named session       -> ONLY that session's own token (or nothing
    if the session is unknown — never another identity's token).
  * no session declared          -> ANONYMOUS by default (no token), UNLESS the
    operator opted into ambient reuse at scan start
    (``ALLOW_AMBIENT_AUTH=1``), which restores the legacy same-host token.
"""
from __future__ import annotations

import hashlib
import logging
from enum import Enum
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Aliases that all mean "send unauthenticated".
_ANON_ALIASES = {"anonymous", "anon", "none", "guest", "unauth", "unauthenticated"}


class RequestIdentity(str, Enum):
    ANONYMOUS = "anonymous"
    AUTHENTICATED_LOW = "authenticated_low"
    AUTHENTICATED_USER = "authenticated_user"
    AUTHENTICATED_ADMIN = "authenticated_admin"
    CUSTOM_SESSION = "custom_session"


def is_anonymous(session_id: Optional[str]) -> bool:
    """True for an explicitly-anonymous session id (case-insensitive)."""
    return (session_id or "").strip().lower() in _ANON_ALIASES


def _lookup_session_header(ctx, session_id: str) -> str:
    """Resolve the Authorization header for a named session/identity.

    Looks in ``ctx.sessions`` (Session objects or dicts), keyed by session_id,
    identity_id, or role. Returns "" when unknown so the caller never silently
    borrows another identity's token.
    """
    try:
        sessions = getattr(ctx, "sessions", None) or {}
        sess = sessions.get(session_id)
        if sess is None:
            for s in sessions.values():
                sid = getattr(s, "session_id", None) or (s.get("session_id") if isinstance(s, dict) else None)
                iid = getattr(s, "identity_id", None) or (s.get("identity_id") if isinstance(s, dict) else None)
                role = getattr(s, "role", None) or (s.get("role") if isinstance(s, dict) else None)
                if session_id in (sid, iid, role):
                    sess = s
                    break
        if sess is None:
            return ""
        hdrs = getattr(sess, "headers", None) or (sess.get("headers") if isinstance(sess, dict) else {}) or {}
        if hdrs.get("Authorization"):
            return hdrs["Authorization"]
        toks = getattr(sess, "tokens", None) or (sess.get("tokens") if isinstance(sess, dict) else {}) or {}
        bearer = toks.get("bearer") or toks.get("access") or toks.get("jwt")
        return f"Bearer {bearer}" if bearer else ""
    except Exception:
        return ""


def resolve_request_auth(ctx, session_id: Optional[str]) -> Tuple[str, str, str]:
    """Return ``(authorization_header, identity_label, auth_mode)`` for a request.

    Never raises. Never returns another identity's token for an unknown session.

    auth_mode is one of: ``explicit_anonymous``, ``explicit_session``,
    ``default_anonymous`` (ambient off), ``ambient`` (operator opted in).
    """
    sid = (session_id or "").strip()

    if is_anonymous(sid):
        return "", "anonymous", "explicit_anonymous"

    if sid:
        # Explicit, non-anonymous session -> only that session's own token.
        return _lookup_session_header(ctx, sid), sid, "explicit_session"

    # No session declared -> anonymous unless the operator opted into ambient.
    try:
        from core.utils.scan_flags import allow_ambient_auth
        if allow_ambient_auth():
            from core.execution.executors.auth_registry import get_active_auth
            active = get_active_auth() or {}
            hdr = (active.get("headers") or {}).get("Authorization", "")
            return hdr, "ambient", "ambient"
    except Exception as e:
        raise SystemError(f"Policy enforcement failed: {e}") from e
    return "", "anonymous", "default_anonymous"


def redact_auth(auth: str) -> str:
    """Render an Authorization value for logs without leaking the credential."""
    if not auth:
        return "(none)"
    parts = auth.split(None, 1)
    scheme = parts[0] if parts else "?"
    tail = parts[1] if len(parts) > 1 else ""
    fp = hashlib.sha256(tail.encode("utf-8", "ignore")).hexdigest()[:8] if tail else "--------"
    return f"{scheme} <redacted:{fp}>"


def log_request_identity(where: str, method: str, url: str,
                         session_id: Optional[str], auth: str, mode: str) -> None:
    """Structured, credential-safe request-identity log line."""
    logger.info("[SESSION] %s %s %s session=%s auth=%s mode=%s",
                where, method, url, session_id or "anonymous", redact_auth(auth), mode)
