from core.domain.endpoint import Endpoint
from core.coverage.test_definition import ApplicabilityRule
from typing import Callable, Dict
import re

class ApplicabilityEngine:
    """
    Evaluates abstract applicability rules against tangible domain entities.
    """
    def __init__(self):
        self.registry: Dict[str, Callable[[Endpoint, ApplicabilityRule], bool]] = {
            "login_endpoint_exists": self._check_login_endpoint,
            "endpoint_has_object_id": self._check_object_id,
            "endpoint_has_multiple_identities": self._check_multiple_identities,
            "endpoint_accepts_input": self._check_accepts_input,
            "endpoint_reflects_input": self._check_reflects_input
        }
        
    def evaluate_rule(self, rule: ApplicabilityRule, endpoint: Endpoint) -> bool:
        if rule.condition not in self.registry:
            # If we don't know the rule, fail safe and assume it's NOT applicable
            return False
            
        evaluator = self.registry[rule.condition]
        return evaluator(endpoint, rule)
        
    def _check_login_endpoint(self, endpoint: Endpoint, rule: ApplicabilityRule) -> bool:
        path = endpoint.path.lower()
        return "login" in path or "auth" in path or "signin" in path
        
    def _check_object_id(self, endpoint: Endpoint, rule: ApplicabilityRule) -> bool:
        # Check if the path ends with an ID or has ID parameters
        if re.search(r'/\d+$', endpoint.path):
            return True
            
        for param in endpoint.parameters:
            if "id" in param.name.lower():
                return True
        return False
        
    def _check_multiple_identities(self, endpoint: Endpoint, rule: ApplicabilityRule) -> bool:
        # Assuming the endpoint maps authorized contexts
        return len(endpoint.auth_contexts) > 1
        
    def _check_accepts_input(self, endpoint: Endpoint, rule: ApplicabilityRule) -> bool:
        return len(endpoint.parameters) > 0
        
    def _check_reflects_input(self, endpoint: Endpoint, rule: ApplicabilityRule) -> bool:
        # Heuristically, GET requests with query params often reflect input
        if "GET" in endpoint.method_set and len(endpoint.parameters) > 0:
            return True
        return False
