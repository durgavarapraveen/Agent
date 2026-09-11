from typing import List
from core.injection.models import InjectionTestMatrix
from core.domain.endpoint import Endpoint
from core.injection.eligibility import InjectionEligibilityChecker

class InjectionMatrix:
    def __init__(self):
        self.checker = InjectionEligibilityChecker()
        
    def build_matrix(self, endpoints: List[Endpoint]) -> InjectionTestMatrix:
        matrix = InjectionTestMatrix(endpoints=len(endpoints))
        
        for ep in endpoints:
            # Use the endpoint's REAL discovered parameters. Body params are tested
            # as JSON, everything else as form/query — no fabricated parameters.
            params_to_test = []
            for p in getattr(ep, "parameters", []) or []:
                ptype = str(getattr(p, "parameter_type", "")).lower()
                ctype = "application/json" if "body" in ptype else "text/html"
                params_to_test.append((p.name, ctype))
            if not params_to_test:
                # No known parameters for this endpoint — nothing to test, don't invent any.
                continue

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
