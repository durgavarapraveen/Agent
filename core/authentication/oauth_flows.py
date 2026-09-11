"""Phase 4.3 — OAuth 2.0 / OIDC client flows for authenticated testing.

Lets the scanner obtain and maintain tokens the way a real client does, so it
can test APIs behind OAuth:

  * Authorization Code + PKCE (S256);
  * Client Credentials;
  * Refresh token, with automatic retry once on a 401;
  * Token exchange (RFC 8693);
  * ``.well-known/openid-configuration`` discovery.

Reuses ``OAuthMisconfigExecutor``'s well-known paths for endpoint discovery.
OAuth providers often live on a separate domain from the target, so this uses a
plain injectable httpx client (tests drive it with ``httpx.MockTransport``); it
is not routed through the scope-enforced client.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import httpx

logger = logging.getLogger(__name__)

WELL_KNOWN_PATHS = ("/.well-known/openid-configuration",
                    "/.well-known/oauth-authorization-server")

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


@dataclass
class OAuthConfig:
    token_url: str = ""
    authorize_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = "http://localhost/callback"
    scopes: List[str] = field(default_factory=list)
    issuer: str = ""

    @classmethod
    def from_env(cls) -> "OAuthConfig":
        return cls(
            token_url=os.getenv("OAUTH_TOKEN_URL", ""),
            authorize_url=os.getenv("OAUTH_AUTHORIZE_URL", ""),
            client_id=os.getenv("OAUTH_CLIENT_ID", ""),
            client_secret=os.getenv("OAUTH_CLIENT_SECRET", ""),
            redirect_uri=os.getenv("OAUTH_REDIRECT_URI", "http://localhost/callback"),
            scopes=[s for s in os.getenv("OAUTH_SCOPES", "").split() if s],
            issuer=os.getenv("OAUTH_ISSUER", ""),
        )


def pkce_pair() -> Tuple[str, str]:
    """Return (code_verifier, code_challenge) using S256."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


class OAuthClient:

    def __init__(self, config: OAuthConfig, client: Optional[httpx.Client] = None):
        self.config = config
        self._client = client
        self.tokens: Dict[str, Any] = {}

    @contextmanager
    def _session(self):
        if self._client is not None:
            yield self._client
        else:
            c = httpx.Client(timeout=20)
            try:
                yield c
            finally:
                c.close()

    # ── Discovery ────────────────────────────────────────────────────────────
    def discover(self, issuer: Optional[str] = None) -> Dict[str, Any]:
        base = (issuer or self.config.issuer).rstrip("/")
        with self._session() as c:
            for path in WELL_KNOWN_PATHS:
                try:
                    r = c.get(base + path)
                    if r.status_code == 200:
                        meta = r.json()
                        self.config.token_url = meta.get("token_endpoint", self.config.token_url)
                        self.config.authorize_url = meta.get("authorization_endpoint",
                                                             self.config.authorize_url)
                        self.config.issuer = meta.get("issuer", base)
                        return meta
                except Exception as e:
                    logger.debug("oauth discover %s failed: %s", base + path, e)
        return {}

    # ── Authorization Code + PKCE ─────────────────────────────────────────────
    def build_authorization_url(self, state: str, code_challenge: str) -> str:
        params = {
            "response_type": "code", "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri, "state": state,
            "code_challenge": code_challenge, "code_challenge_method": "S256",
        }
        if self.config.scopes:
            params["scope"] = " ".join(self.config.scopes)
        sep = "&" if "?" in self.config.authorize_url else "?"
        return f"{self.config.authorize_url}{sep}{urlencode(params)}"

    def exchange_code(self, code: str, code_verifier: str) -> Dict[str, Any]:
        return self._token_request({
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": self.config.redirect_uri, "code_verifier": code_verifier,
        })

    # ── Client Credentials ─────────────────────────────────────────────────────
    def client_credentials(self) -> Dict[str, Any]:
        data = {"grant_type": "client_credentials"}
        if self.config.scopes:
            data["scope"] = " ".join(self.config.scopes)
        return self._token_request(data)

    # ── Refresh ────────────────────────────────────────────────────────────────
    def refresh(self, refresh_token: Optional[str] = None) -> Dict[str, Any]:
        rt = refresh_token or self.tokens.get("refresh_token", "")
        if not rt:
            return {}
        return self._token_request({"grant_type": "refresh_token", "refresh_token": rt})

    # ── Token exchange (RFC 8693) ───────────────────────────────────────────────
    def token_exchange(self, subject_token: str,
                       subject_token_type: str = "urn:ietf:params:oauth:token-type:access_token",
                       audience: str = "") -> Dict[str, Any]:
        data = {"grant_type": TOKEN_EXCHANGE_GRANT, "subject_token": subject_token,
                "subject_token_type": subject_token_type}
        if audience:
            data["audience"] = audience
        return self._token_request(data)

    def _token_request(self, data: Dict[str, str]) -> Dict[str, Any]:
        data = dict(data)
        data.setdefault("client_id", self.config.client_id)
        if self.config.client_secret:
            data.setdefault("client_secret", self.config.client_secret)
        with self._session() as c:
            r = c.post(self.config.token_url, data=data,
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
            if r.status_code >= 400:
                logger.warning("oauth token request failed: %s %s", r.status_code, r.text[:200])
                return {}
            tokens = r.json()
        self.tokens.update(tokens)
        return tokens

    # ── Authenticated request with auto-refresh on 401 ──────────────────────────
    def authorized_headers(self) -> Dict[str, str]:
        at = self.tokens.get("access_token", "")
        ttype = self.tokens.get("token_type", "Bearer")
        return {"Authorization": f"{ttype} {at}"} if at else {}

    def request_with_refresh(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Send a request; on 401, refresh the token once and retry."""
        with self._session() as c:
            headers = {**self.authorized_headers(), **(kwargs.pop("headers", {}) or {})}
            r = c.request(method, url, headers=headers, **kwargs)
            if r.status_code == 401 and self.tokens.get("refresh_token"):
                logger.info("oauth: 401 — refreshing token and retrying once")
                if self.refresh():
                    headers = {**self.authorized_headers(), **(kwargs.get("headers", {}) or {})}
                    r = c.request(method, url, headers=headers, **kwargs)
            return r
