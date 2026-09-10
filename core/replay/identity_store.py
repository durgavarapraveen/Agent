import os
import logging
from typing import Dict, Optional
from core.domain.identity import Identity, Role, AuthenticationState

logger = logging.getLogger(__name__)

class IdentityStore:
    def __init__(self):
        self.identities: Dict[str, Identity] = {}
        
    def load_identities_from_env(self):
        # Very simple mock initialization for now, reading from explicit config or env
        # In a real scenario, this would parse os.environ for specific prefixes.
        
        # We will mock the load for testability:
        users_to_check = ["USER_A", "USER_B", "ADMIN"]
        
        for u in users_to_check:
            # We assume env vars like APP_USER_A_CREDENTIALS exist
            cred = os.getenv(f"APP_{u}_CREDENTIALS")
            role_str = os.getenv(f"APP_{u}_ROLE", "unknown")
            
            if cred:
                role = Role.UNKNOWN
                try:
                    role = Role(role_str.lower())
                except ValueError:
                    pass
                    
                identity = Identity(
                    identity_id=u.lower(),
                    label=f"Configured {u}",
                    username_reference=u,
                    role=role,
                    credential_source="env_var",
                    authentication_state=AuthenticationState.NOT_AUTHENTICATED
                )
                self.identities[identity.identity_id] = identity
                logger.info(f"Loaded identity from env: {identity.identity_id} with role {identity.role}")

    def add_identity(self, identity: Identity):
        self.identities[identity.identity_id] = identity

    def get_identity(self, identity_id: str) -> Optional[Identity]:
        return self.identities.get(identity_id)
        
    def resolve_credentials(self, identity_id: str) -> Optional[str]:
        # Maps identity to raw secret
        # For simplicity, we just map it back from env
        return os.getenv(f"APP_{identity_id.upper()}_CREDENTIALS")
