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
        """
        In a real world, this would execute a login flow (auth endpoint)
        using the resolved credentials to get real cookies/JWTs.
        For this simulation, we mock the session creation.
        """
        cred = self.identity_store.resolve_credentials(identity.identity_id)
        if not cred:
            logger.error(f"Cannot create session, no credentials for {identity.identity_id}")
            raise ValueError(f"No credentials for {identity.identity_id}")

        # Mocking an auth flow
        sess = Session(
            session_id=str(uuid.uuid4()),
            identity_id=identity.identity_id,
            authentication_method="mock",
            cookies={"session_id": f"mock_cookie_{identity.identity_id}"},
            tokens={"Authorization": f"Bearer mock_token_{identity.identity_id}"},
            valid=True
        )
        
        self.sessions[identity.identity_id] = sess
        identity.authentication_state = AuthenticationState.AUTHENTICATED
        logger.info(f"Created session {sess.session_id} for identity {identity.identity_id}")
        return sess

    def validate_session(self, session: Session) -> bool:
        """
        Validates if the session is still active.
        """
        if not session.valid:
            return False
            
        # Real logic would check expiration times, or make a ping request
        return True

    def refresh_session(self, session: Session) -> Session:
        """
        Attempts to refresh an expired session.
        """
        logger.info(f"Refreshing session for {session.identity_id}")
        identity = self.identity_store.get_identity(session.identity_id)
        if not identity:
            raise ValueError(f"Identity {session.identity_id} not found in store")
            
        return self.create_session(identity)
