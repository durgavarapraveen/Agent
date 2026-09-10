from typing import Dict, Optional
from core.domain.session import Session
from core.domain.identity import Identity, AuthenticationState
from core.replay.identity_store import IdentityStore
import logging
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)

class SessionManager:
    def __init__(self, identity_store: IdentityStore):
        self.identity_store = identity_store
        self.sessions: Dict[str, Session] = {} # Map identity_id -> Session

    def get_session(self, identity_id: str) -> Optional[Session]:
        return self.sessions.get(identity_id)

    def create_session(self, identity: Identity) -> Session:
        raise ValueError(
            f"No live session for identity '{identity.identity_id}'. "
            f"Provide credentials for this role so a real session is established "
            f"(credentials are turned into sessions by the auth layer)."
        )

    def validate_session(self, session: Session) -> bool:
        if not session.valid:
            return False
            
        # Real logic would check expiration times, or make a ping request
        return True

    def refresh_session(self, session: Session) -> Session:
        logger.info(f"Refreshing session for {session.identity_id}")
        identity = self.identity_store.get_identity(session.identity_id)
        if not identity:
            raise ValueError(f"Identity {session.identity_id} not found in store")
            
        return self.create_session(identity)
