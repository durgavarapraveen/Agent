"""Mandatory scope enforcement for every outbound HTTP request.

`ScopeManager.validate_url()` / `ScopeAuthority.is_authorized()` decide whether a
target is in the authorized pentest scope, but a validator is only useful if it
is actually consulted before each request. This module provides an httpx event
hook that runs that check on every request — including each hop of a redirect
chain — and a factory that returns a client with the hook pre-installed.

Usage (replaces `httpx.AsyncClient(...)` / `httpx.Client(...)`):

    from core.security.scoped_http import get_scoped_client, get_scoped_sync_client

    async with get_scoped_client(timeout=10, verify=False) as client:
        await client.get(url)            # raises OutOfScopeError if out of scope

The default authorizer is the global :class:`ScopeAuthority`, which fails closed
(denies) when no scope is wired. Pass ``authorizer=<callable[str]->bool>`` to
override (used in tests, or to bind a specific ScopeManager instance).
"""
from __future__ import annotations

import logging
from typing import Callable, Optional

import httpx

from core.common.exceptions import AuthorizationError
from core.security.scope_facade import get_scope_authority

logger = logging.getLogger(__name__)

Authorizer = Callable[[str], bool]


class OutOfScopeError(AuthorizationError):
    """Raised when an outbound HTTP request targets a URL outside the scope.

    Subclasses AuthorizationError so scope-aware handlers catch it, but is a
    distinct type so out-of-scope egress can be detected specifically. The
    request is never sent — the hook raises before the transport runs.
    """

    def __init__(self, url: str):
        self.url = url
        super().__init__(f"Blocked out-of-scope HTTP request: {url}")


def _default_authorizer(url: str) -> bool:
    return get_scope_authority().is_authorized(url)


def _enforce(url: str, authorizer: Optional[Authorizer]) -> None:
    check = authorizer or _default_authorizer
    try:
        allowed = bool(check(url))
    except Exception as e:  # authorizer bug → fail closed, never silently allow
        logger.warning("scoped_http: authorizer error for %s (%s); failing closed", url, e)
        allowed = False
    if not allowed:
        logger.warning("scoped_http: BLOCKED out-of-scope request to %s", url)
        raise OutOfScopeError(url)


def make_request_hook(authorizer: Optional[Authorizer] = None):
    """Async httpx 'request' event hook enforcing scope on each request."""

    async def _hook(request: "httpx.Request") -> None:
        _enforce(str(request.url), authorizer)

    return _hook


def make_sync_request_hook(authorizer: Optional[Authorizer] = None):
    """Sync httpx 'request' event hook enforcing scope on each request."""

    def _hook(request: "httpx.Request") -> None:
        _enforce(str(request.url), authorizer)

    return _hook


def _with_scope_hook(kwargs: dict, hook) -> dict:
    """Merge the scope hook into any caller-provided event_hooks, first in the
    'request' list so it blocks before any user hook can act on the request."""
    event_hooks = dict(kwargs.pop("event_hooks", None) or {})
    request_hooks = list(event_hooks.get("request", []) or [])
    event_hooks["request"] = [hook, *request_hooks]
    kwargs["event_hooks"] = event_hooks
    return kwargs


def get_scoped_client(*, authorizer: Optional[Authorizer] = None, **kwargs) -> httpx.AsyncClient:
    """Return an ``httpx.AsyncClient`` that raises OutOfScopeError on any
    out-of-scope request URL (including redirect targets). Accepts all the
    usual ``httpx.AsyncClient`` keyword arguments."""
    kwargs = _with_scope_hook(kwargs, make_request_hook(authorizer))
    return httpx.AsyncClient(**kwargs)


def get_scoped_sync_client(*, authorizer: Optional[Authorizer] = None, **kwargs) -> httpx.Client:
    """Synchronous counterpart of :func:`get_scoped_client`."""
    kwargs = _with_scope_hook(kwargs, make_sync_request_hook(authorizer))
    return httpx.Client(**kwargs)
