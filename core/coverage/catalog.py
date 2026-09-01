from typing import List, Dict
from core.coverage.test_definition import SecurityTestDefinition

class TestCatalog:
    """Registry of all deterministic coverage tests."""

    CATEGORIES = [
        "authentication", "authorization", "session", "identity", "access_control", 
        "input_validation", "sql_injection", "nosql_injection", "xss", "ssti", 
        "command_injection", "csrf", "cors", "ssrf", "xxe", "path_traversal", 
        "file_upload", "file_download", "jwt", "graphql", "api_security", 
        "business_logic", "race_condition", "secrets", "information_disclosure", 
        "misconfiguration", "cryptography", "client_side", "dependency", "websocket"
    ]

    def __init__(self):
        self.tests: Dict[str, SecurityTestDefinition] = {}
        self._seed_catalog()

    def _seed_catalog(self):
        """Seed initial tests for core categories."""
        # Baseline seed to initialize engine
        for category in self.CATEGORIES:
            test_id = f"{category}_baseline_01"
            self.tests[test_id] = SecurityTestDefinition(
                test_id=test_id,
                category=category,
                description=f"Baseline coverage test for {category}",
                prerequisites=[],
                applicability_rules=[{"rule_type": "always_applicable"}],
                execution_strategies=["default_scan", "targeted_fuzz"],
                required_evidence=["scan_result"],
                oracle="tool_output_parser",
                risk_level="high" if "injection" in category else "medium"
            )

    def get_test(self, test_id: str) -> SecurityTestDefinition:
        return self.tests.get(test_id)

    def get_tests_by_category(self, category: str) -> List[SecurityTestDefinition]:
        return [test for test in self.tests.values() if test.category == category]

    def get_all_tests(self) -> List[SecurityTestDefinition]:
        return list(self.tests.values())
