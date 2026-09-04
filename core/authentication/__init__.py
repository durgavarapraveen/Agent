"""
Authenticated & stateful testing (Feature #6).

Establishes a REAL authenticated session against the target (form login, JSON/JWT
API login, or a static bearer/cookie), maintains it across HTTP-based probes,
tracks JWT expiry, and transparently re-authenticates on 401 — unlocking the
post-auth attack surface that unauthenticated scanners miss.
"""

from core.authentication.auth_session import (
    AuthSessionManager,
    AuthConfig,
    MultiIdentityAuthManager,
)

__all__ = ["AuthSessionManager", "AuthConfig", "MultiIdentityAuthManager"]
