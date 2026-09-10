import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class SessionArtifact:
    def __init__(self, identity_id: str, cookies: Dict[str, str] = None, headers: Dict[str, str] = None, 
                 jwt_metadata: Dict[str, Any] = None, csrf_tokens: Dict[str, str] = None):
        self.identity_id = identity_id
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.jwt_metadata = jwt_metadata or {}
        self.csrf_tokens = csrf_tokens or {}
        self.is_valid = True

class SessionManager:
    def __init__(self, shared_context=None):
        self._active_sessions: Dict[str, SessionArtifact] = {} # identity_id -> artifact
        self.shared_context = shared_context
        self.auth_health_metrics = {
            "login_attempts": 0,
            "login_success": 0,
            "login_failed": 0,
            "session_validations": 0,
            "session_expirations": 0,
            "session_refreshes": 0
        }

    def store_session(self, identity_id: str, artifact: SessionArtifact):
        self._active_sessions[identity_id] = artifact
        
        if self.shared_context:
            with self.shared_context._lock:
                self.shared_context.sessions = self._active_sessions
                self.shared_context.auth_health_metrics = self.auth_health_metrics
                
        logger.info(f"SESSION_CREATED count={len(self._active_sessions)}")
        print(f"SESSION_CREATED count={len(self._active_sessions)}")
        
    def get_session(self, identity_id: str) -> SessionArtifact:
        return self._active_sessions.get(identity_id)
        
    def revoke_session(self, identity_id: str):
        if identity_id in self._active_sessions:
            self._active_sessions[identity_id].is_valid = False
            del self._active_sessions[identity_id]
            
            if self.shared_context:
                with self.shared_context._lock:
                    self.shared_context.sessions = self._active_sessions
