import logging
from core.identity.identity_manager import Identity
from core.identity.credential_store import CredentialStore
from core.identity.session_manager import SessionManager, SessionArtifact
from core.identity.login_detector import LoginDetector, LoginType

logger = logging.getLogger(__name__)

class MFAInterventionRequired(Exception):
    """Raised when human intervention is needed for MFA."""
    pass

class LoginFlowEngine:
    """
    Executes the authentication sequence.
    """
    def __init__(self, credential_store: CredentialStore, session_manager: SessionManager):
        self.credential_store = credential_store
        self.session_manager = session_manager
        self.detector = LoginDetector()
        
    def authenticate(self, identity: Identity, target_url: str, page_content: str = "") -> bool:
        """
        Attempts to authenticate the identity using the determined login mechanism.
        """
        logger.info(f"LOGIN_ATTEMPT identity={identity.id}")
        print(f"LOGIN_ATTEMPT identity={identity.id}")
        self.session_manager.auth_health_metrics["login_attempts"] += 1
        
        login_type = self.detector.detect(page_content, target_url)
        
        # Resolve credentials securely in memory right before use
        username = self.credential_store.resolve(identity.username_ref)
        password = self.credential_store.resolve(identity.password_ref)
        
        if not username or not password:
            logger.error(f"Missing credentials for {identity.id}")
            return False
            
        try:
            # Dispatch to appropriate handler based on detection
            if login_type == LoginType.FORM:
                session_artifact = self._handle_form_login(username, password)
            elif login_type == LoginType.JWT_API:
                session_artifact = self._handle_jwt_login(username, password)
            elif login_type == LoginType.SPA:
                session_artifact = self._handle_spa_login(username, password)
            else:
                # Default generic fallback
                session_artifact = self._handle_generic_login(username, password)
                
            # Simulate a scenario where MFA is detected
            if "mfa_required" in session_artifact.headers:
                raise MFAInterventionRequired(f"MFA required for identity {identity.id}")
                
            session_artifact.identity_id = identity.id
            self.session_manager.store_session(identity.id, session_artifact)
            
            self.session_manager.auth_health_metrics["login_success"] += 1
            logger.info(f"LOGIN_SUCCESS identity={identity.id}")
            print(f"LOGIN_SUCCESS identity={identity.id}")
            return True
            
        except MFAInterventionRequired as e:
            self.session_manager.auth_health_metrics["login_failed"] += 1
            logger.warning(str(e))
            raise e
        except Exception as e:
            self.session_manager.auth_health_metrics["login_failed"] += 1
            logger.error(f"LOGIN_FAILED identity={identity.id}: {e}")
            print(f"LOGIN_FAILED identity={identity.id}: {e}")
            return False
            
    def _handle_form_login(self, username, password) -> SessionArtifact:
        # Mock HTTP POST returning a session cookie and CSRF
        if password == "wrong":
            raise Exception("Invalid credentials")
        return SessionArtifact(identity_id="", cookies={"session_id": "mock_cookie_123"}, csrf_tokens={"csrf_token": "mock_csrf_form_123"})
        
    def _handle_jwt_login(self, username, password) -> SessionArtifact:
        # Mock HTTP POST returning a Bearer token
        if password == "wrong":
            raise Exception("Invalid credentials")
        return SessionArtifact(identity_id="", headers={"Authorization": "Bearer mock_jwt_123"}, jwt_metadata={"expires": 3600, "alg": "RS256"})
        
    def _handle_spa_login(self, username, password) -> SessionArtifact:
        if password == "wrong":
            raise Exception("Invalid credentials")
        return SessionArtifact(identity_id="", headers={"X-Auth-Token": "mock_spa_123"}, csrf_tokens={"x-csrf-token": "mock_spa_csrf_123"})
        
    def _handle_generic_login(self, username, password) -> SessionArtifact:
        if password == "wrong":
            raise Exception("Invalid credentials")
        return SessionArtifact(identity_id="", cookies={"auth": "mock_generic_123"})
