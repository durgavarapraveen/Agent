"""Phase 4.3 — OAuth client flows."""
from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import httpx

from core.authentication.oauth_flows import OAuthClient, OAuthConfig, pkce_pair


def test_pkce_pair_valid_s256():
    verifier, challenge = pkce_pair()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert challenge == expected
    assert "=" not in verifier and "=" not in challenge


def _oauth_client(handler):
    cfg = OAuthConfig(token_url="https://idp.test/token",
                      authorize_url="https://idp.test/authorize",
                      client_id="cid", client_secret="sec",
                      issuer="https://idp.test", scopes=["read"])
    return OAuthClient(cfg, client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_build_authorization_url_has_pkce():
    client = _oauth_client(lambda r: httpx.Response(404))
    _, challenge = pkce_pair()
    url = client.build_authorization_url(state="xyz", code_challenge=challenge)
    q = parse_qs(urlparse(url).query)
    assert q["response_type"] == ["code"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["code_challenge"] == [challenge]
    assert q["state"] == ["xyz"]


def test_client_credentials_flow():
    def handler(request):
        body = parse_qs(request.content.decode())
        assert body["grant_type"] == ["client_credentials"]
        assert body["client_id"] == ["cid"]
        return httpx.Response(200, json={"access_token": "AT1", "token_type": "Bearer",
                                         "expires_in": 3600})
    client = _oauth_client(handler)
    tokens = client.client_credentials()
    assert tokens["access_token"] == "AT1"
    assert client.authorized_headers() == {"Authorization": "Bearer AT1"}


def test_exchange_code_and_refresh():
    def handler(request):
        body = parse_qs(request.content.decode())
        gt = body["grant_type"][0]
        if gt == "authorization_code":
            assert body["code_verifier"]  # PKCE verifier sent
            return httpx.Response(200, json={"access_token": "AT", "refresh_token": "RT"})
        if gt == "refresh_token":
            assert body["refresh_token"] == ["RT"]
            return httpx.Response(200, json={"access_token": "AT2", "refresh_token": "RT2"})
        return httpx.Response(400)
    client = _oauth_client(handler)
    verifier, _ = pkce_pair()
    t1 = client.exchange_code("thecode", verifier)
    assert t1["access_token"] == "AT"
    t2 = client.refresh()
    assert t2["access_token"] == "AT2"


def test_token_exchange_rfc8693():
    def handler(request):
        body = parse_qs(request.content.decode())
        assert body["grant_type"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]
        assert body["subject_token"] == ["upstream-tok"]
        return httpx.Response(200, json={"access_token": "EXCH"})
    client = _oauth_client(handler)
    assert client.token_exchange("upstream-tok", audience="api")["access_token"] == "EXCH"


def test_discover_oidc():
    def handler(request):
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={
                "issuer": "https://idp.test",
                "token_endpoint": "https://idp.test/oauth/token",
                "authorization_endpoint": "https://idp.test/oauth/authorize"})
        return httpx.Response(404)
    client = _oauth_client(handler)
    meta = client.discover()
    assert meta["token_endpoint"] == "https://idp.test/oauth/token"
    assert client.config.token_url == "https://idp.test/oauth/token"


def test_request_with_refresh_retries_on_401():
    calls = {"api": 0, "refresh": 0}

    def handler(request):
        if request.url.path == "/token":
            calls["refresh"] += 1
            return httpx.Response(200, json={"access_token": "AT2", "refresh_token": "RT2"})
        # protected API: first call 401, second (after refresh) 200
        calls["api"] += 1
        return httpx.Response(401 if calls["api"] == 1 else 200, text="ok")

    client = _oauth_client(handler)
    client.tokens = {"access_token": "OLD", "refresh_token": "RT", "token_type": "Bearer"}
    r = client.request_with_refresh("GET", "https://idp.test/api/data")
    assert r.status_code == 200
    assert calls["refresh"] == 1 and calls["api"] == 2


def test_request_with_refresh_no_refresh_token_no_retry():
    calls = {"api": 0}

    def handler(request):
        calls["api"] += 1
        return httpx.Response(401)

    client = _oauth_client(handler)
    client.tokens = {"access_token": "OLD"}  # no refresh token
    r = client.request_with_refresh("GET", "https://idp.test/api/data")
    assert r.status_code == 401
    assert calls["api"] == 1  # no retry without a refresh token
