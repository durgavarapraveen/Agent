from core.coverage.test_definition import SecurityTestDefinition, ApplicabilityRule
from typing import Dict, List

class SecurityTestCatalog:
    """
    Registry of all generic security tests.
    """
    def __init__(self):
        self.tests: Dict[str, SecurityTestDefinition] = {}
        self._load_defaults()
        
    def _load_defaults(self):
        # 1. Basic Authentication Test
        self.tests["authentication.basic"] = SecurityTestDefinition(
            test_id="authentication.basic",
            category="authentication",
            description="Tests if the login mechanism correctly handles valid and invalid credentials.",
            prerequisites=[],
            applicability_rules=[ApplicabilityRule(condition="login_endpoint_exists")],
            execution_strategies=["interactive_login", "brute_force_simulation"],
            required_evidence=["valid_login_response", "invalid_login_rejection"],
            oracle="login_flow_oracle",
            risk_level="high"
        )
        
        # 2. Insecure Direct Object Reference (IDOR)
        self.tests["authorization.idor"] = SecurityTestDefinition(
            test_id="authorization.idor",
            category="authorization",
            description="Tests if a user can access objects belonging to other users.",
            prerequisites=["authentication.basic"],
            applicability_rules=[
                ApplicabilityRule(condition="endpoint_has_object_id"),
                ApplicabilityRule(condition="endpoint_has_multiple_identities")
            ],
            execution_strategies=["cross_user_replay"],
            required_evidence=["cross_user_access_log", "baseline_comparison"],
            oracle="matrix_engine_oracle",
            risk_level="high"
        )
        
        # 3. SQL Injection (Basic)
        self.tests["input_validation.sqli"] = SecurityTestDefinition(
            test_id="input_validation.sqli",
            category="sql_injection",
            description="Tests for basic SQL injection payloads.",
            prerequisites=[],
            applicability_rules=[
                ApplicabilityRule(condition="endpoint_accepts_input")
            ],
            execution_strategies=["nuclei_sqli_fuzz", "dalfox"],
            required_evidence=["database_error", "time_delay", "boolean_inference"],
            oracle="sqli_heuristic_oracle",
            risk_level="critical"
        )
        
        # 4. Cross-Site Scripting (XSS)
        self.tests["xss.reflected"] = SecurityTestDefinition(
            test_id="xss.reflected",
            category="xss",
            description="Tests for reflected XSS in response bodies.",
            prerequisites=[],
            applicability_rules=[
                ApplicabilityRule(condition="endpoint_reflects_input")
            ],
            execution_strategies=["nuclei_xss", "dalfox"],
            required_evidence=["script_execution_context", "reflected_payload"],
            oracle="xss_heuristic_oracle",
            risk_level="high"
        )

    def get_test(self, test_id: str) -> SecurityTestDefinition:
        return self.tests.get(test_id)
        
    def get_all_tests(self) -> List[SecurityTestDefinition]:
        return list(self.tests.values())
