import logging
from core.identity.session_manager import SessionArtifact

logger = logging.getLogger(__name__)

class SessionValidator:
    """
    Validates if an active session is still authenticated.
    """
    
    def __init__(self, session_manager, validation_endpoint: str = "/api/me"):
        self.session_manager = session_manager
        self.validation_endpoint = validation_endpoint
        
    def is_valid(self, session: SessionArtifact) -> bool:
        """
        Simulates checking if a session is valid. 
        In real life, this would send an HTTP request to `validation_endpoint`
        using the cookies/headers inside `session` and check for 200 OK.
        """
        if not session or not session.is_valid:
            self.session_manager.auth_health_metrics["session_expirations"] += 1
            logger.info(f"SESSION_EXPIRED identity={session.identity_id if session else 'unknown'}")
            print(f"SESSION_EXPIRED identity={session.identity_id if session else 'unknown'}")
            return False
            
        # Mock logic: assume valid for now unless manually revoked
        self.session_manager.auth_health_metrics["session_validations"] += 1
        logger.info(f"SESSION_VALIDATED identity={session.identity_id}")
        print(f"SESSION_VALIDATED identity={session.identity_id}")
        return True
