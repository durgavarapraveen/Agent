"""Phase 0.5: mandatory scope enforcement on outbound HTTP requests."""
from __future__ import annotations

import httpx
import pytest

from core.security.scoped_http import (
    OutOfScopeError,
    get_scoped_client,
    get_scoped_sync_client,
)


def _ok_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="ok")


def _in_scope_only(url: str) -> bool:
    return "in-scope.test" in url


async def test_in_scope_request_succeeds():
    transport = httpx.MockTransport(_ok_handler)
    async with get_scoped_client(authorizer=_in_scope_only, transport=transport) as c:
        r = await c.get("http://in-scope.test/path")
        assert r.status_code == 200


async def test_out_of_scope_request_raises():
    transport = httpx.MockTransport(_ok_handler)
    async with get_scoped_client(authorizer=_in_scope_only, transport=transport) as c:
        with pytest.raises(OutOfScopeError):
            await c.get("http://evil.test/steal")


async def test_redirect_to_out_of_scope_raises():
    """A redirect from an in-scope host to an out-of-scope host must be blocked
    on the redirected request, not silently followed."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "in-scope.test":
            return httpx.Response(302, headers={"Location": "http://evil.test/pwn"})
        return httpx.Response(200, text="should never be reached")

    transport = httpx.MockTransport(handler)
    async with get_scoped_client(
        authorizer=_in_scope_only, transport=transport, follow_redirects=True
    ) as c:
        with pytest.raises(OutOfScopeError):
            await c.get("http://in-scope.test/start")


def test_sync_client_out_of_scope_raises():
    transport = httpx.MockTransport(_ok_handler)
    with get_scoped_sync_client(authorizer=_in_scope_only, transport=transport) as c:
        with pytest.raises(OutOfScopeError):
            c.get("http://evil.test/x")


def test_sync_client_in_scope_succeeds():
    transport = httpx.MockTransport(_ok_handler)
    with get_scoped_sync_client(authorizer=_in_scope_only, transport=transport) as c:
        assert c.get("http://in-scope.test/x").status_code == 200


def test_default_authorizer_fails_closed_without_wired_scope():
    """With no scope wired, ScopeAuthority denies everything, so the default
    authorizer must block the request rather than allow it."""
    from core.security.scope_facade import ScopeAuthority

    ScopeAuthority.reset_for_tests()
    try:
        transport = httpx.MockTransport(_ok_handler)
        with get_scoped_sync_client(transport=transport) as c:
            with pytest.raises(OutOfScopeError):
                c.get("http://anything.test/x")
    finally:
        ScopeAuthority.reset_for_tests()


def test_authorizer_exception_fails_closed():
    def boom(url: str) -> bool:
        raise RuntimeError("authorizer blew up")

    transport = httpx.MockTransport(_ok_handler)
    with get_scoped_sync_client(authorizer=boom, transport=transport) as c:
        with pytest.raises(OutOfScopeError):
            c.get("http://in-scope.test/x")


def test_preexisting_request_hook_still_runs():
    calls = []

    def user_hook(request: httpx.Request) -> None:
        calls.append(str(request.url))

    transport = httpx.MockTransport(_ok_handler)
    with get_scoped_sync_client(
        authorizer=_in_scope_only,
        transport=transport,
        event_hooks={"request": [user_hook]},
    ) as c:
        c.get("http://in-scope.test/x")
    assert calls == ["http://in-scope.test/x"]
