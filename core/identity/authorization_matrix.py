import logging
import os
from typing import Dict, Any, List, Optional, Set, Tuple
from .session_model import IdentityManager

logger = logging.getLogger(__name__)

# Env-tunable floor for cross-identity test budget (was a hard 100 cap that
# silently dropped checks on large scopes). Callers may pass a larger,
# scope-proportional budget: max(_DEFAULT_AUTHZ_BUDGET, endpoints*identities*2).
_DEFAULT_AUTHZ_BUDGET = int(os.getenv("AUTHZ_SAFETY_BUDGET", "1000"))

class AuthorizationMatrix:
    def __init__(self, identity_manager: IdentityManager):
        self.identity_manager = identity_manager
        self._matrix: Dict[Tuple[str, str], Set[str]] = {}
        self._denials: Dict[Tuple[str, str], Set[str]] = {}

    def record_authorization(self, resource_id: str, action: str, identity_id: str, is_authorized: bool):
        key = (resource_id, action)
        if is_authorized:
            self._matrix.setdefault(key, set()).add(identity_id)
        else:
            self._denials.setdefault(key, set()).add(identity_id)

    def check_authorization(self, resource_id: str, action: str, identity_id: str) -> Optional[bool]:
        key = (resource_id, action)
        if key in self._denials and identity_id in self._denials[key]:
            return False
        if key in self._matrix and identity_id in self._matrix[key]:
            return True
        return None

    def get_matrix_snapshot(self) -> Dict[str, Any]:
        return {
            "authorized": {f"{r}|{a}": sorted(ids) for (r, a), ids in self._matrix.items()},
            "denied": {f"{r}|{a}": sorted(ids) for (r, a), ids in self._denials.items()},
        }

class AccessTester:
    def __init__(self, matrix: AuthorizationMatrix, safety_budget: int = None):
        self.matrix = matrix
        self.safety_budget = safety_budget if safety_budget is not None else _DEFAULT_AUTHZ_BUDGET
        self.tests_run = 0

    def orchestrate_cross_identity_experiment(self, resource_id: str, action: str,
                                              identities_to_test: List[str]) -> List[Dict[str, Any]]:
        import time
        results = []
        # Scope-proportional budget: never drop checks just because a static cap
        # was hit — scale with the number of identities under test (rate-limited).
        effective_budget = max(self.safety_budget, len(identities_to_test) * 3)
        rate_delay = 1.0 / float(int(__import__("os").getenv("AUTHZ_RATE_PER_SEC", "10")) or 10)
        for identity_id in identities_to_test:
            if self.tests_run >= effective_budget:
                logger.warning("Safety budget (%d) exceeded for cross-identity experiments.",
                               effective_budget)
                break

            session = self.matrix.identity_manager.get_session(identity_id)
            if not session:
                continue

            self.tests_run += 1
            time.sleep(rate_delay)  # rate-limit instead of silently capping
            status = self.matrix.check_authorization(resource_id, action, identity_id)
            results.append({
                "identity_id": identity_id,
                "role": session.identity.role,
                "resource_id": resource_id,
                "action": action,
                "known_status": status,
                "confidence_score": 0.9 if status is not None else 0.0,
            })
        return results
