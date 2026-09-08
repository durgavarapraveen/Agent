"""
AuthSessionManager — real authenticated session for post-auth testing.

Supported auth types (config AUTH_TYPE):
  form    : POST username/password form fields to AUTH_LOGIN_URL, keep Set-Cookie.
  json    : POST a JSON credential body to AUTH_LOGIN_URL, extract a token from the
            JSON response at AUTH_TOKEN_JSON_PATH, send it as a header.
  bearer  : use a static AUTH_TOKEN as `Authorization: Bearer <token>`.
  cookie  : use a static AUTH_COOKIE string as the Cookie header.

The manager exposes the live session as headers + cookies for injection into any
scanner or probe, transparently re-authenticates on 401, and proactively refreshes
before a known JWT expiry.

Credentials are read from config/env only (AUTH_USERNAME / AUTH_PASSWORD / AUTH_TOKEN)
— never hardcoded. The session is held in memory and never written to disk.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)


@dataclass
class AuthConfig:
    enabled: bool = False
    auth_type: str = "form"                 # form|json|bearer|cookie
    login_url: str = ""
    username: str = ""
    password: str = ""
    username_field: str = "username"
    password_field: str = "password"
    extra_fields: Dict[str, str] = field(default_factory=dict)
    token: str = ""                         # static bearer token
    cookie: str = ""                        # static cookie string
    token_json_path: str = "token"          # dotted path into JSON login response
    header_name: str = "Authorization"
    token_prefix: str = "Bearer "
    probe_url: str = ""                     # authenticated endpoint used to verify session
    timeout: int = 20

    role: str = ""                          # role label (user, admin, sales, marketing…)

    @classmethod
    def from_credential(cls, cred: Dict[str, Any]) -> "AuthConfig":
        """
        Build an AuthConfig from a UI-supplied credential dict, e.g.
          {"role": "admin", "username": "a", "password": "p", "login_url": "https://.../login"}
        Optional keys: auth_type, token, cookie, username_field, password_field,
        token_json_path, header_name, token_prefix, probe_url, extra_fields.
        The auth_type is inferred when not given: token->bearer, cookie->cookie,
        login_url+creds->form.
        """
        auth_type = str(cred.get("auth_type", "")).lower()
        if not auth_type:
            if cred.get("token"):
                auth_type = "bearer"
            elif cred.get("cookie"):
                auth_type = "cookie"
            else:
                auth_type = "form"
        return cls(
            enabled=True,
            auth_type=auth_type,
            role=str(cred.get("role", "") or ""),
            login_url=str(cred.get("login_url", "") or ""),
            username=str(cred.get("username", "") or ""),
            password=str(cred.get("password", "") or ""),
            username_field=str(cred.get("username_field", "username")),
            password_field=str(cred.get("password_field", "password")),
            extra_fields=cred.get("extra_fields", {}) or {},
            token=str(cred.get("token", "") or ""),
            cookie=str(cred.get("cookie", "") or ""),
            token_json_path=str(cred.get("token_json_path", "token")),
            header_name=str(cred.get("header_name", "Authorization")),
            token_prefix=str(cred.get("token_prefix", "Bearer ")),
            probe_url=str(cred.get("probe_url", "") or ""),
            timeout=int(cred.get("timeout", 20)),
        )

    @classmethod
    def from_config(cls, cfg=None) -> "AuthConfig":
        if cfg is None:
            try:
                from core.common.config import get_config
                cfg = get_config()
            except Exception:
                return cls()

        def g(key, default=""):
            return cfg.get(key, default) or default

        extra = {}
        raw_extra = g("AUTH_EXTRA_FIELDS", "")
        if raw_extra:
            try:
                extra = json.loads(raw_extra)
            except Exception:
                pass

        return cls(
            enabled=cfg.get_bool("AUTH_ENABLED", False),
            auth_type=g("AUTH_TYPE", "form").lower(),
            login_url=g("AUTH_LOGIN_URL"),
            username=g("AUTH_USERNAME"),
            password=g("AUTH_PASSWORD"),
            username_field=g("AUTH_USERNAME_FIELD", "username"),
            password_field=g("AUTH_PASSWORD_FIELD", "password"),
            extra_fields=extra,
            token=g("AUTH_TOKEN"),
            cookie=g("AUTH_COOKIE"),
            token_json_path=g("AUTH_TOKEN_JSON_PATH", "token"),
            header_name=g("AUTH_HEADER_NAME", "Authorization"),
            token_prefix=g("AUTH_TOKEN_PREFIX", "Bearer "),
            probe_url=g("AUTH_PROBE_URL"),
            timeout=int(cfg.get_int("AUTH_TIMEOUT", 20)),
        )


def _decode_jwt_exp(token: str) -> Optional[float]:
    """Return the JWT `exp` claim (unix seconds) without verifying the signature."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
        exp = data.get("exp")
        return float(exp) if exp else None
    except Exception:
        return None


class AuthSessionManager:
    """Owns a live authenticated session and injects it into outbound requests."""

    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config or AuthConfig.from_config()
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.csrf_tokens: Dict[str, str] = {}
        self._jwt_exp: Optional[float] = None
        self._authenticated = False
        self._last_login = 0.0

    # ------------------------------------------------------------------ status

    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled)

    @property
    def authenticated(self) -> bool:
        return self._authenticated

    def _jwt_expired(self, skew: int = 30) -> bool:
        return self._jwt_exp is not None and time.time() >= (self._jwt_exp - skew)

    # ------------------------------------------------------------ authenticate

    async def authenticate(self) -> bool:
        """Establish the session. Returns True on success."""
        if not self.config.enabled:
            return False
        t = self.config.auth_type
        try:
            if t == "bearer":
                ok = self._auth_static_bearer()
            elif t == "cookie":
                ok = self._auth_static_cookie()
            elif t == "json":
                ok = await self._auth_json_login()
            else:
                ok = await self._auth_form_login()
        except Exception as e:
            logger.error(f"[Auth] authentication error ({t}): {e}")
            ok = False

        self._authenticated = ok
        if ok:
            self._last_login = time.time()
            logger.info(f"[Auth] authenticated via {t} "
                        f"(cookies={len(self.cookies)}, headers={list(self.headers)})")
        else:
            logger.warning(f"[Auth] authentication failed via {t}")
        return ok

    def _auth_static_bearer(self) -> bool:
        if not self.config.token:
            return False
        self.headers[self.config.header_name] = f"{self.config.token_prefix}{self.config.token}"
        self._jwt_exp = _decode_jwt_exp(self.config.token)
        return True

    def _auth_static_cookie(self) -> bool:
        if not self.config.cookie:
            return False
        # store raw cookie string; parse into dict best-effort
        for part in self.config.cookie.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                self.cookies[k] = v
        return bool(self.cookies)

    async def _auth_form_login(self) -> bool:
        if not (self.config.login_url and self.config.username):
            return False
        data = {
            self.config.username_field: self.config.username,
            self.config.password_field: self.config.password,
            **self.config.extra_fields,
        }
        async with httpx.AsyncClient(timeout=self.config.timeout, follow_redirects=True) as client:
            resp = await client.post(self.config.login_url, data=data)
            for name, value in resp.cookies.items():
                self.cookies[name] = value
            # Capture CSRF token if echoed in a common header.
            for h in ("x-csrf-token", "csrf-token"):
                if h in {k.lower() for k in resp.headers}:
                    self.csrf_tokens[h] = resp.headers.get(h, "")
            return bool(self.cookies) and resp.status_code < 400

    async def _auth_json_login(self) -> bool:
        if not (self.config.login_url and self.config.username):
            return False
        body = {
            self.config.username_field: self.config.username,
            self.config.password_field: self.config.password,
            **self.config.extra_fields,
        }
        async with httpx.AsyncClient(timeout=self.config.timeout, follow_redirects=True) as client:
            resp = await client.post(self.config.login_url, json=body)
            for name, value in resp.cookies.items():
                self.cookies[name] = value
            token = None
            try:
                token = self._extract_json_path(resp.json(), self.config.token_json_path)
            except Exception:
                pass
            if token:
                self.headers[self.config.header_name] = f"{self.config.token_prefix}{token}"
                self._jwt_exp = _decode_jwt_exp(str(token))
                return True
            return bool(self.cookies) and resp.status_code < 400

    @staticmethod
    def _extract_json_path(data: Any, path: str) -> Optional[str]:
        cur = data
        for key in path.split("."):
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                return None
        return str(cur) if cur is not None else None

    # ------------------------------------------------------------- session use

    def auth_headers(self) -> Dict[str, str]:
        """Headers to attach to an authenticated request (includes Cookie)."""
        headers = dict(self.headers)
        headers.update({k: v for k, v in self.csrf_tokens.items() if v})
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        return headers

    async def is_authenticated(self, probe_url: Optional[str] = None) -> bool:
        """Probe an authenticated endpoint to confirm the session is live."""
        url = probe_url or self.config.probe_url
        if not url:
            return self._authenticated
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                resp = await client.get(url, headers=self.auth_headers())
                return resp.status_code not in (401, 403)
        except Exception:
            return False

    async def ensure_valid(self) -> bool:
        """Re-authenticate if the JWT is near expiry or the session went stale."""
        if not self.config.enabled:
            return False
        if not self._authenticated or self._jwt_expired():
            return await self.authenticate()
        return True

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """
        Perform an authenticated HTTP request, transparently re-authenticating
        once on 401/403.
        """
        await self.ensure_valid()
        headers = {**self.auth_headers(), **kwargs.pop("headers", {})}
        async with httpx.AsyncClient(timeout=self.config.timeout, follow_redirects=True) as client:
            resp = await client.request(method, url, headers=headers, **kwargs)
            if resp.status_code in (401, 403):
                logger.info("[Auth] got 401/403 — re-authenticating and retrying once")
                if await self.authenticate():
                    headers = {**self.auth_headers(), **kwargs.get("headers", {})}
                    resp = await client.request(method, url, headers=headers, **kwargs)
            return resp

    def summary(self) -> Dict[str, Any]:
        return {
            "enabled": self.config.enabled,
            "role": self.config.role,
            "type": self.config.auth_type,
            "authenticated": self._authenticated,
            "has_cookies": bool(self.cookies),
            "has_token": self.config.header_name in self.headers,
            "jwt_exp": self._jwt_exp,
        }


# Rough privilege ranking so single-session consumers can pick the most useful
# role by default. Higher = more privileged.
_ROLE_PRIORITY = {
    "superadmin": 100, "root": 100, "admin": 90, "administrator": 90,
    "manager": 70, "staff": 60, "sales": 50, "marketing": 50,
    "support": 45, "editor": 40, "user": 30, "customer": 25, "guest": 10,
}


def _role_rank(role: str) -> int:
    return _ROLE_PRIORITY.get(str(role or "").strip().lower(), 35)


class MultiIdentityAuthManager:
    """
    Establishes and maintains a REAL authenticated session per role.

    Fed the credential list the UI sends —
      [{"role": "admin", "username": "...", "password": "...", "login_url": "..."},
       {"role": "sales", ...}, ...] —
    it logs in each role concurrently. Roles that share the same login
    (same login_url + username + password) reuse a single session instead of
    authenticating twice. All live sessions are kept so cross-role tests
    (access control, IDOR, privilege escalation) can compare identities.
    """

    def __init__(self, credentials: List[Dict[str, Any]]):
        self.credentials = credentials or []
        self.sessions: Dict[str, AuthSessionManager] = {}   # role -> manager
        self._by_login: Dict[tuple, AuthSessionManager] = {}  # dedup identical logins

    @staticmethod
    def _login_key(cred: Dict[str, Any]) -> tuple:
        return (
            str(cred.get("login_url", "")).strip().lower(),
            str(cred.get("username", "")).strip(),
            str(cred.get("password", "")).strip(),
            str(cred.get("token", "")).strip(),
            str(cred.get("cookie", "")).strip(),
        )

    async def authenticate_all(self) -> Dict[str, Any]:
        """Authenticate every distinct login and map each role to its session."""
        # 1. Deduplicate identical logins so a shared login authenticates once.
        unique: Dict[tuple, List[Dict[str, Any]]] = {}
        for cred in self.credentials:
            if not (cred.get("username") or cred.get("token") or cred.get("cookie")):
                continue
            unique.setdefault(self._login_key(cred), []).append(cred)

        async def _login(cred: Dict[str, Any]) -> AuthSessionManager:
            mgr = AuthSessionManager(AuthConfig.from_credential(cred))
            await mgr.authenticate()
            return mgr

        # 2. Authenticate each distinct login concurrently.
        keys = list(unique.keys())
        managers = await asyncio.gather(
            *(_login(unique[k][0]) for k in keys), return_exceptions=True
        )

        # 3. Map roles to sessions (shared login -> shared manager).
        for key, mgr in zip(keys, managers):
            if isinstance(mgr, Exception):
                logger.warning(f"[MultiAuth] login failed for {key[:2]}: {mgr}")
                continue
            self._by_login[key] = mgr
            for cred in unique[key]:
                role = str(cred.get("role") or mgr.config.username or "identity")
                self.sessions[role] = mgr

        authed = [r for r, m in self.sessions.items() if m.authenticated]
        logger.info(f"[MultiAuth] {len(authed)}/{len(self.sessions)} role sessions authenticated: "
                    f"{', '.join(authed) or 'none'} "
                    f"({len(self._by_login)} distinct logins)")
        return self.summary()

    def session_for(self, role: str) -> Optional[AuthSessionManager]:
        return self.sessions.get(role)

    def headers_for(self, role: str) -> Dict[str, str]:
        mgr = self.sessions.get(role)
        return mgr.auth_headers() if mgr else {}

    def default_session(self) -> Optional[AuthSessionManager]:
        """Highest-privilege authenticated session (fallback for single-session consumers)."""
        authed = [(r, m) for r, m in self.sessions.items() if m.authenticated]
        if not authed:
            authed = list(self.sessions.items())
        if not authed:
            return None
        authed.sort(key=lambda rm: _role_rank(rm[0]), reverse=True)
        return authed[0][1]

    def sessions_map(self) -> Dict[str, Dict[str, Any]]:
        """Per-role headers/cookies for storage on the shared context."""
        out = {}
        for role, mgr in self.sessions.items():
            out[role] = {
                "authenticated": mgr.authenticated,
                "headers": mgr.auth_headers(),
                "cookies": dict(mgr.cookies),
                "type": mgr.config.auth_type,
            }
        return out

    def summary(self) -> Dict[str, Any]:
        return {
            "roles": list(self.sessions.keys()),
            "authenticated_roles": [r for r, m in self.sessions.items() if m.authenticated],
            "distinct_logins": len(self._by_login),
            "per_role": {r: m.summary() for r, m in self.sessions.items()},
        }
