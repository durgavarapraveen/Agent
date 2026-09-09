"""P0.2 regression tests — session isolation / anonymous-by-default auth.

Proves:
  1. admin session cannot leak into an anonymous request
  2. low-priv session cannot become admin automatically
  3. a newly captured JWT does not change unrelated (undeclared) tests
  4. parallel tests do not share mutable auth state accidentally
"""
import os
import importlib

import pytest


class _Sess:
    def __init__(self, session_id, identity_id, role, auth):
        self.session_id = session_id
        self.identity_id = identity_id
        self.role = role
        self.headers = {"Authorization": auth} if auth else {}
        self.tokens = {}


class _Ctx:
    def __init__(self):
        self.sessions = {}


def _fresh_flags(monkeypatch, ambient: bool):
    monkeypatch.setenv("ALLOW_AMBIENT_AUTH", "1" if ambient else "0")
    import core.utils.scan_flags as sf
    importlib.reload(sf)
    return sf


def _resolver():
    import core.security.session_context as sc
    importlib.reload(sc)
    return sc


def test_explicit_anonymous_never_authenticated(monkeypatch):
    _fresh_flags(monkeypatch, ambient=True)  # even with ambient ON
    sc = _resolver()
    ctx = _Ctx()
    ctx.sessions["admin"] = _Sess("admin", "id-admin", "administrator", "Bearer ADMINJWT")
    auth, ident, mode = sc.resolve_request_auth(ctx, "anonymous")
    assert auth == ""
    assert mode == "explicit_anonymous"


def test_admin_session_does_not_leak_into_anonymous(monkeypatch):
    _fresh_flags(monkeypatch, ambient=False)
    sc = _resolver()
    ctx = _Ctx()
    ctx.sessions["admin"] = _Sess("admin", "id-admin", "administrator", "Bearer ADMINJWT")
    # Undeclared request while an admin token is present in active auth:
    from core.execution.executors.auth_registry import set_active_auth, clear_active_auth
    set_active_auth(headers={"Authorization": "Bearer ADMINJWT"})
    try:
        auth, ident, mode = sc.resolve_request_auth(ctx, None)
        assert auth == ""                 # anonymous by default
        assert mode == "default_anonymous"
    finally:
        clear_active_auth()


def test_low_priv_cannot_become_admin(monkeypatch):
    _fresh_flags(monkeypatch, ambient=False)
    sc = _resolver()
    ctx = _Ctx()
    ctx.sessions["low"] = _Sess("low", "id-low", "standard", "Bearer LOWJWT")
    ctx.sessions["admin"] = _Sess("admin", "id-admin", "administrator", "Bearer ADMINJWT")
    auth, ident, mode = sc.resolve_request_auth(ctx, "low")
    assert auth == "Bearer LOWJWT"        # only its own token
    assert mode == "explicit_session"


def test_unknown_session_borrows_no_token(monkeypatch):
    _fresh_flags(monkeypatch, ambient=False)
    sc = _resolver()
    ctx = _Ctx()
    ctx.sessions["admin"] = _Sess("admin", "id-admin", "administrator", "Bearer ADMINJWT")
    auth, ident, mode = sc.resolve_request_auth(ctx, "does-not-exist")
    assert auth == ""                     # never another identity's token


def test_captured_jwt_does_not_change_undeclared_test(monkeypatch):
    _fresh_flags(monkeypatch, ambient=False)
    sc = _resolver()
    ctx = _Ctx()
    from core.execution.executors.auth_registry import set_active_auth, clear_active_auth
    # Simulate a JWT captured mid-scan and globally published.
    set_active_auth(headers={"Authorization": "Bearer CAPTURED"})
    try:
        auth, _, mode = sc.resolve_request_auth(ctx, None)
        assert auth == ""                 # capture ignored for undeclared request
        assert mode == "default_anonymous"
    finally:
        clear_active_auth()


def test_ambient_opt_in_restores_reuse(monkeypatch):
    _fresh_flags(monkeypatch, ambient=True)
    sc = _resolver()
    ctx = _Ctx()
    from core.execution.executors.auth_registry import set_active_auth, clear_active_auth
    set_active_auth(headers={"Authorization": "Bearer CAPTURED"})
    try:
        auth, ident, mode = sc.resolve_request_auth(ctx, None)
        assert auth == "Bearer CAPTURED"
        assert mode == "ambient"
    finally:
        clear_active_auth()


def test_redaction_never_leaks_token(monkeypatch):
    sc = _resolver()
    out = sc.redact_auth("Bearer SUPERSECRETVALUE123")
    assert "SUPERSECRETVALUE123" not in out
    assert out.startswith("Bearer <redacted:")


def test_parallel_sessions_do_not_share_state(monkeypatch):
    _fresh_flags(monkeypatch, ambient=False)
    sc = _resolver()
    ctx = _Ctx()
    ctx.sessions["a"] = _Sess("a", "id-a", "standard", "Bearer A")
    ctx.sessions["b"] = _Sess("b", "id-b", "administrator", "Bearer B")
    auth_a, _, _ = sc.resolve_request_auth(ctx, "a")
    auth_b, _, _ = sc.resolve_request_auth(ctx, "b")
    assert auth_a == "Bearer A"
    assert auth_b == "Bearer B"
    assert auth_a != auth_b


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
