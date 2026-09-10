import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from .session_model import IdentityManager, SessionModel

logger = logging.getLogger(__name__)

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
    def __init__(self, matrix: AuthorizationMatrix, safety_budget: int = 100):
        self.matrix = matrix
        self.safety_budget = safety_budget
        self.tests_run = 0

    def orchestrate_cross_identity_experiment(self, resource_id: str, action: str,
                                              identities_to_test: List[str]) -> List[Dict[str, Any]]:
        results = []
        for identity_id in identities_to_test:
            if self.tests_run >= self.safety_budget:
                logger.warning("Safety budget exceeded for cross-identity experiments.")
                break

            session = self.matrix.identity_manager.get_session(identity_id)
            if not session:
                continue

            self.tests_run += 1
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
