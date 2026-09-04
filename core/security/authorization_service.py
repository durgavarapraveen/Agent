from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class AuthorizationPolicy:
    target: str
    allowed_identities: List[str] = field(default_factory=list)
    allowed_actions: List[str] = field(default_factory=list)
    blocked_patterns: List[str] = field(default_factory=list)


class AuthorizationService:

    def __init__(self) -> None:
        self._policies: Dict[str, AuthorizationPolicy] = {}

    def register_policy(self, policy: AuthorizationPolicy) -> None:
        self._policies[policy.target] = policy

    def check_authorized(self, target: str, identity: str, action: str) -> bool:
        policy = self._policies.get(target)
        if policy is None:
            return False

        for pattern in policy.blocked_patterns:
            if re.search(pattern, action):
                return False

        if identity not in policy.allowed_identities:
            return False

        if policy.allowed_actions and action not in policy.allowed_actions:
            return False

        return True

    def get_allowed_identities(self, target: str) -> List[str]:
        policy = self._policies.get(target)
        return list(policy.allowed_identities) if policy else []
