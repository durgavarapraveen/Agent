import os
import uuid
import logging

logger = logging.getLogger(__name__)

class CredentialRef:
    def __init__(self, ref_id: str):
        self.ref_id = ref_id

class CredentialStore:
    def __init__(self):
        self._vault = {} # ref_id -> actual_value

    def load_from_env(self, env_var: str) -> CredentialRef:
        value = os.getenv(env_var)
        if not value:
            logger.warning(f"Environment variable {env_var} is not set.")
            value = ""
            
        ref_id = str(uuid.uuid4())
        self._vault[ref_id] = value
        return CredentialRef(ref_id)
        
    def resolve(self, ref: CredentialRef) -> str:
        return self._vault.get(ref.ref_id, "")
