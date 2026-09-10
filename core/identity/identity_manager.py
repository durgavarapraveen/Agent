import logging
from typing import Dict, List
from core.identity.credential_store import CredentialStore, CredentialRef

logger = logging.getLogger(__name__)

class Identity:
    def __init__(self, id: str, role: str, username_ref: CredentialRef, password_ref: CredentialRef):
        self.id = id
        self.role = role
        self.username_ref = username_ref
        self.password_ref = password_ref

class IdentityManager:
    def __init__(self, credential_store: CredentialStore, shared_context=None):
        self.credential_store = credential_store
        self.identities: Dict[str, Identity] = {}
        self.shared_context = shared_context

    def load_identities(self, config_list: List[Dict]):
        for identity_conf in config_list:
            ident_id = identity_conf["id"]
            role = identity_conf["role"]
            username_env = identity_conf["username_env"]
            password_env = identity_conf["password_env"]
            
            user_ref = self.credential_store.load_from_env(username_env)
            pass_ref = self.credential_store.load_from_env(password_env)
            
            identity = Identity(
                id=ident_id,
                role=role,
                username_ref=user_ref,
                password_ref=pass_ref
            )
            self.identities[ident_id] = identity
            
        if self.shared_context:
            with self.shared_context._lock:
                self.shared_context.identities = self.identities
        
        logger.info(f"IDENTITY_DISCOVERY count={len(self.identities)}")
        print(f"IDENTITY_DISCOVERY count={len(self.identities)}")

    def get_identity(self, ident_id: str) -> Identity:
        return self.identities.get(ident_id)
