
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class SessionIdentity:
    identity_id: str
    role: str                     # plain string ("standard", "administrator", "sales"…)
    manager: Any = None           # the AuthSessionManager backing this role

    @property
    def id(self) -> str:          # some loops read `.id`
        return self.identity_id


# Map UI role labels onto the role strings the MatrixEngine compares against.
_ROLE_NORMALIZE = {
    "admin": "administrator", "administrator": "administrator", "superadmin": "administrator",
    "root": "administrator", "user": "standard", "customer": "standard", "member": "standard",
}


def normalize_role(role: str) -> str:
    r = str(role or "").strip().lower()
    return _ROLE_NORMALIZE.get(r, r or "standard")


def build_replay_sessions(
    multi_auth: Any,
    replay_session_manager: Any,
    identity_manager: Any,
    shared_context: Any = None,
) -> Dict[str, Any]:
    # Import here to avoid a hard dependency when the replay stack is absent.
    try:
        from core.domain.session import Session
    except Exception as e:  # pragma: no cover
        logger.warning(f"[IdentityBridge] domain Session unavailable: {e}")
        Session = None

    roles_loaded = []
    for role, mgr in getattr(multi_auth, "sessions", {}).items():
        if not getattr(mgr, "authenticated", False):
            continue
        norm_role = normalize_role(role)
        ident_id = role  # keep the UI's own label as the identity id

        # 1. Register a session-backed identity for the loops to iterate.
        identity = SessionIdentity(identity_id=ident_id, role=norm_role, manager=mgr)
        try:
            identity_manager.identities[ident_id] = identity
        except Exception as e:
            logger.debug(f"[IdentityBridge] identity register failed for {role}: {e}")

        # 2. Pre-load a REAL replay session so replay_request skips the mock login.
        if Session is not None:
            try:
                headers = dict(mgr.headers)                       # Authorization etc.
                headers.update({k: v for k, v in mgr.csrf_tokens.items() if v})
                sess = Session(
                    session_id=str(uuid.uuid4()),
                    identity_id=ident_id,
                    authentication_method=mgr.config.auth_type,
                    cookies=dict(mgr.cookies),
                    headers=headers,
                    tokens=headers,                              # replay_request injects tokens as headers
                    valid=True,
                    validation_method="live_auth",
                )
                replay_session_manager.sessions[ident_id] = sess
                roles_loaded.append(role)
            except Exception as e:
                logger.debug(f"[IdentityBridge] session preload failed for {role}: {e}")

    if shared_context is not None:
        try:
            shared_context.identities = identity_manager.identities
        except Exception as e:
            logger.warning("[IdentityBridge] failed to set shared_context.identities: %s", e)

    logger.info(f"[IdentityBridge] wired {len(roles_loaded)} real role sessions into "
                f"replay/access-control engine: {roles_loaded}")
    return {
        "roles": list(getattr(multi_auth, "sessions", {}).keys()),
        "identities": list(identity_manager.identities.keys()),
        "sessions_loaded": roles_loaded,
    }
