import logging
from core.identity.session_manager import SessionManager

logger = logging.getLogger(__name__)

class SessionRefreshRequired(Exception):
    pass

class SessionRefreshHandler:
    
    def __init__(self, session_manager: SessionManager):
        self.session_manager = session_manager
        
    def refresh(self, identity_id: str) -> bool:
        session = self.session_manager.get_session(identity_id)
        if not session:
            return False

        # A session that still holds any reusable credential material can be
        # reused; otherwise it must be re-established through a full login.
        # Covers bearer (Authorization), custom token headers, cookie sessions,
        # and refresh-token artifacts — not just the Authorization header.
        headers = dict(getattr(session, "headers", {}) or {})
        cookies = dict(getattr(session, "cookies", {}) or {})
        header_names = {k.lower() for k in headers.keys()}
        cookie_names = {k.lower() for k in cookies.keys()}

        has_auth_header = bool(headers.get("Authorization"))
        has_token_header = any(
            n in header_names for n in ("x-auth-token", "x-access-token", "authentication")
        )
        has_cookie_session = bool(cookies) or any(
            any(s in n for s in ("sess", "sid", "auth", "token", "jwt")) for n in cookie_names
        )
        has_refresh_artifact = bool(getattr(session, "refresh_token", None)) or any(
            "refresh" in n for n in (header_names | cookie_names)
        )

        if has_auth_header or has_token_header or has_cookie_session or has_refresh_artifact:
            self.session_manager.auth_health_metrics["session_refreshes"] += 1
            logger.info(f"SESSION_REFRESHED identity={identity_id}")
            print(f"SESSION_REFRESHED identity={identity_id}")
            return True
            
        logger.info(f"Session for {identity_id} cannot be refreshed. Full relogin required.")
        self.session_manager.revoke_session(identity_id)
        return False
