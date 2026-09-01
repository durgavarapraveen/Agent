from typing import List, Dict, Any
from core.injection.models import InjectionTestMatrix, InjectionTest
from core.domain.endpoint import Endpoint
from core.injection.eligibility import InjectionEligibilityChecker

class InjectionMatrix:
    def __init__(self):
        self.checker = InjectionEligibilityChecker()
        
    def build_matrix(self, endpoints: List[Endpoint]) -> InjectionTestMatrix:
        matrix = InjectionTestMatrix(endpoints=len(endpoints))
        
        for ep in endpoints:
            # We mock the parameters and content_type extraction for matrix building.
            # In a full run, this would be tied to ParameterInventory and ContentType extraction.
            # We'll assume each endpoint has 1 parameter to test for this exercise, unless it has a specific path.
            params_to_test = [("q", "text/html"), ("file", "application/json")]
            
            for param_name, ctype in params_to_test:
                tests = self.checker.is_eligible(ep, param_name, ctype, None)
                if tests:
                    matrix.eligible_parameters += 1
                    
                for t in tests:
                    if t.test_type not in matrix.tests_by_type:
                        matrix.tests_by_type[t.test_type] = []
                        matrix.status_by_type[t.test_type] = {
                            "tested": 0, "confirmed": 0, "rejected": 0, "blocked": 0, "inconclusive": 0
                        }
                    matrix.tests_by_type[t.test_type].append(t)
                    
        return matrix
