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

        # A session that still holds an Authorization header can be reused; otherwise
        # it must be re-established through a full login.
        if session.headers.get("Authorization"):
            self.session_manager.auth_health_metrics["session_refreshes"] += 1
            logger.info(f"SESSION_REFRESHED identity={identity_id}")
            print(f"SESSION_REFRESHED identity={identity_id}")
            return True
            
        logger.info(f"Session for {identity_id} cannot be refreshed. Full relogin required.")
        self.session_manager.revoke_session(identity_id)
        return False
