import os
import uuid
import logging

logger = logging.getLogger(__name__)

class CredentialRef:
    """A safe, opaque reference to a credential stored entirely in memory."""
    def __init__(self, ref_id: str):
        self.ref_id = ref_id

class CredentialStore:
    """
    Secure, in-memory credential storage.
    Never persists passwords, raw tokens, session secrets, or client secrets.
    """
    def __init__(self):
        self._vault = {} # ref_id -> actual_value

    def load_from_env(self, env_var: str) -> CredentialRef:
        """Loads a credential from the environment and returns a safe reference."""
        value = os.getenv(env_var)
        if not value:
            logger.warning(f"Environment variable {env_var} is not set.")
            value = ""
            
        ref_id = str(uuid.uuid4())
        self._vault[ref_id] = value
        return CredentialRef(ref_id)
        
    def resolve(self, ref: CredentialRef) -> str:
        """Resolves the safe reference back to the actual string value. For internal auth use only."""
        return self._vault.get(ref.ref_id, "")
