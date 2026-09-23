"""Token/session-shape agnostic auth helpers.

The scanner previously treated a login as successful ONLY when it received an
`eyJ`-prefixed JWT, silently dropping opaque bearer tokens, PASETO, and
cookie-only sessions — so the entire authenticated battery (IDOR / authz /
mass-assign / JWT) ran logged-out on any non-JWT target.

These helpers accept ANY credential material (JWT, opaque token, or session
cookie) and let callers confirm a session by an authenticated re-request rather
than by token shape. They also read role claims across the many modern shapes
(`roles[]`, `scope`, Keycloak `realm_access.roles`, Cognito `cognito:groups`,
Auth0 namespaced claims) instead of a single `"role"` key.
"""
from __future__ import annotations

import base64
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

_JWT_RE = re.compile(r'^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$')

# JSON keys that commonly carry a session/bearer token, most-specific first.
_TOKEN_KEYS = (
    "access_token", "accesstoken", "id_token", "idtoken", "session_token",
    "sessiontoken", "auth_token", "authtoken", "jwt", "token", "bearer",
    "ticket", "sid", "sessionid", "session_id", "session", "api_key", "apikey",
    "authentication",  # nested {"authentication": {"token": ...}}
)
# Operator override for non-standard token key names (e.g. NEO_TOKEN_KEYS=xsrf,sess2).
_TOKEN_KEYS = _TOKEN_KEYS + tuple(
    t.strip().lower() for t in re.split(r'[,\s]+', os.getenv("NEO_TOKEN_KEYS", "") or "")
    if t.strip())
# Any key whose NAME looks token-ish — catches custom conventions like
# "userSession", "apiSecret", "authKey2" that aren't in the list above, as long
# as the VALUE also looks like a token (guards against false positives).
_TOKENISH_KEY_RE = re.compile(
    r'(token|jwt|bearer|sess|sid|auth|ticket|access|credential|secret|apikey|api_key)',
    re.I)


def is_jwt(v: Any) -> bool:
    v = str(v or "")
    return bool(_JWT_RE.match(v)) and v.count(".") >= 2


def looks_like_token(v: Any) -> bool:
    """Accept a JWT or a plausible opaque token (long, tokenish charset, no
    spaces). Deliberately permissive: callers verify by an authed request."""
    v = str(v or "").strip()
    if is_jwt(v):
        return True
    if not (16 <= len(v) <= 4096) or " " in v:
        return False
    return bool(re.match(r'^[A-Za-z0-9._\-+/=:]+$', v))


def decode_jwt_claims(token: Any) -> Dict[str, Any]:
    """Best-effort decode of a JWT payload (no signature check). {} if not JWT."""
    try:
        parts = str(token or "").split(".")
        if len(parts) < 2:
            return {}
        seg = parts[1]
        seg += "=" * (-len(seg) % 4)
        data = json.loads(base64.urlsafe_b64decode(seg.encode()))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _walk_for_token_key(data: Any, depth: int = 0) -> Optional[str]:
    if depth > 6:
        return None
    if isinstance(data, dict):
        # exact/priority key hits first
        for k in _TOKEN_KEYS:
            for dk, dv in data.items():
                if isinstance(dk, str) and dk.lower() == k:
                    if isinstance(dv, str) and looks_like_token(dv):
                        return dv
                    if isinstance(dv, dict):
                        nested = _walk_for_token_key(dv, depth + 1)
                        if nested:
                            return nested
        # non-standard key names: accept a token-like value under any key whose
        # NAME reads as token-ish (booster for unknown conventions).
        for dk, dv in data.items():
            if isinstance(dk, str) and isinstance(dv, str) \
                    and _TOKENISH_KEY_RE.search(dk) and looks_like_token(dv):
                return dv
        for dv in data.values():
            found = _walk_for_token_key(dv, depth + 1)
            if found:
                return found
    elif isinstance(data, list):
        for item in data[:20]:
            found = _walk_for_token_key(item, depth + 1)
            if found:
                return found
    return None


def _walk_for_any_jwt(data: Any, depth: int = 0) -> Optional[str]:
    if depth > 6:
        return None
    if isinstance(data, str):
        return data if is_jwt(data) else None
    if isinstance(data, dict):
        for v in data.values():
            f = _walk_for_any_jwt(v, depth + 1)
            if f:
                return f
    elif isinstance(data, list):
        for v in data[:20]:
            f = _walk_for_any_jwt(v, depth + 1)
            if f:
                return f
    return None


def extract_token_from_json(data: Any) -> Optional[str]:
    """Find a session/bearer token in a parsed JSON login response: a value under
    a token-ish key, else any JWT-shaped value anywhere."""
    return _walk_for_token_key(data) or _walk_for_any_jwt(data)


def _setcookie_lines(headers: Any) -> List[str]:
    try:
        if hasattr(headers, "get_list"):
            return list(headers.get_list("set-cookie"))
        if hasattr(headers, "get"):
            v = headers.get("set-cookie") or headers.get("Set-Cookie") or ""
            return [v] if v else []
    except Exception:
        pass
    return []


def extract_session_cookie(headers: Any) -> Optional[Tuple[str, str]]:
    """Return (cookie_name, value) for the first Set-Cookie that carries a JWT or
    a long opaque token, or a clearly session-named cookie. None if absent."""
    for line in _setcookie_lines(headers):
        m = re.match(r'\s*([^=;\s]+)=([^;]+)', line or "")
        if not m:
            continue
        name, val = m.group(1), m.group(2)
        if looks_like_token(val) or re.search(r'(sess|sid|auth|token|jwt)', name, re.I):
            return name, val
    return None


def extract_session(resp_json: Any = None, headers: Any = None) -> Dict[str, Any]:
    """Unified extractor. Returns {} when nothing found, else:
        {token, transport: "bearer"|"cookie", is_jwt, cookie_name?}
    Prefers a body/bearer token; falls back to a session cookie."""
    tok = extract_token_from_json(resp_json) if resp_json is not None else None
    if tok:
        return {"token": tok, "transport": "bearer", "is_jwt": is_jwt(tok)}
    if headers is not None:
        ck = extract_session_cookie(headers)
        if ck:
            return {"token": ck[1], "transport": "cookie",
                    "cookie_name": ck[0], "is_jwt": is_jwt(ck[1])}
    return {}


# ── role claims across modern shapes ────────────────────────────────────────
_ROLE_KEYS = ("role", "roles", "scope", "scopes", "authorities", "groups",
              "cognito:groups", "user_type", "userType", "tier", "permissions",
              "perms", "grants")


def roles_from_claims(claims: Dict[str, Any]) -> List[str]:
    """Collect role/authority strings from a decoded token across the common
    shapes: string, space-delimited scope, arrays, Keycloak `realm_access.roles`,
    and namespaced `https://app/roles` claims."""
    out: List[str] = []
    if not isinstance(claims, dict):
        return out

    def _add(v):
        if isinstance(v, str):
            out.extend(v.split())
        elif isinstance(v, list):
            out.extend(str(x) for x in v)

    for k in _ROLE_KEYS:
        if k in claims:
            _add(claims[k])
    ra = claims.get("realm_access")
    if isinstance(ra, dict):
        _add(ra.get("roles"))
    ra2 = claims.get("resource_access")
    if isinstance(ra2, dict):
        for v in ra2.values():
            if isinstance(v, dict):
                _add(v.get("roles"))
    for k, v in claims.items():
        if isinstance(k, str) and (k.endswith("/roles") or k.endswith("/role")):
            _add(v)
    # de-dup, preserve order
    seen, uniq = set(), []
    for r in out:
        r = str(r).strip()
        if r and r.lower() not in seen:
            seen.add(r.lower())
            uniq.append(r)
    return uniq


def primary_role(claims_or_token: Any) -> str:
    """Highest-privilege role from a decoded-claims dict or a raw JWT string."""
    claims = claims_or_token if isinstance(claims_or_token, dict) \
        else decode_jwt_claims(claims_or_token)
    roles = roles_from_claims(claims)
    if not roles:
        # some apps put role on a user sub-object
        for k in ("user", "data", "principal"):
            sub = claims.get(k) if isinstance(claims, dict) else None
            if isinstance(sub, dict):
                roles = roles_from_claims(sub)
                if roles:
                    break
    if not roles:
        return ""
    from core.common.target_shape import role_rank
    return sorted(roles, key=role_rank, reverse=True)[0]


def auth_header_for(token: str, transport: str = "bearer",
                    scheme: str = "Bearer") -> Dict[str, str]:
    """Build the auth header for a captured session, honouring its transport.
    Cookie sessions return {} here (caller should set the Cookie separately)."""
    if not token or transport == "cookie":
        return {}
    return {"Authorization": f"{scheme} {token}"}
