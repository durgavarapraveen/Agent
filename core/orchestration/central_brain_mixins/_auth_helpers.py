"""Target-agnostic auth-response helpers shared by CentralBrain and its
AuthSessionMixin (kept here to avoid a mixin<->central_brain import cycle)."""
from __future__ import annotations


def _auth_is_spa_shell(r) -> bool:
    """A 200 that is really the SPA/static index.html served for an unknown route —
    not a real API response. Client-side-routed apps answer 200 with HTML for ANY
    path, so status alone is a false positive: an auth probe 'succeeds' on a decoy
    route and the real JSON API is never reached."""
    ctype = (r.headers.get("content-type") or "").lower()
    if "text/html" in ctype or "application/xhtml" in ctype:
        return True
    try:
        head = r.text.lstrip()[:200].lower()
    except Exception:
        head = ""
    return head.startswith(("<!doctype html", "<html")) or "<app-root" in head


def _auth_find_token(obj, _depth=0):
    """Target-agnostic recursive scan for a token-like value + its dotted path.
    A JWT (eyJ…) anywhere, or a long string under a token/jwt/access key. Lets login
    resolve even when a configured token path doesn't match the response shape."""
    if _depth > 6:
        return None
    if isinstance(obj, str):
        s = obj
        if s.startswith("eyJ") and s.count(".") >= 2 and len(s) > 20:
            return ("", s)
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            if isinstance(v, str) and len(v) > 20 and (
                    v.startswith("eyJ")
                    or any(t in kl for t in ("token", "jwt", "access", "id_token", "bearer"))):
                return (str(k), v)
        for k, v in obj.items():
            sub = _auth_find_token(v, _depth + 1)
            if sub:
                return ((str(k) + "." + sub[0]).strip("."), sub[1])
    elif isinstance(obj, list):
        for v in obj:
            sub = _auth_find_token(v, _depth + 1)
            if sub:
                return sub
    return None
