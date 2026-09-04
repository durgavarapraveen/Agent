import unittest
import io
import sys
from core.coverage.catalog import SecurityTestCatalog
from core.coverage.coverage_engine import CoverageEngine
from core.domain.endpoint import Endpoint
from core.domain.coverage import TestState
from core.domain.parameter import Parameter
from core.domain.identity import Identity

class TestCoverageEngine(unittest.TestCase):
    def setUp(self):
        self.catalog = SecurityTestCatalog()
        self.engine = CoverageEngine(self.catalog)
        
        # Build endpoints
        self.ep_login = Endpoint(
            endpoint_id="ep_1",
            url="http://app/login",
            path="/login",
            method_set=["POST"]
        )
        self.ep_api_users = Endpoint(
            endpoint_id="ep_2",
            url="http://app/api/users/1",
            path="/api/users/1",
            method_set=["GET"],
            auth_contexts=[Identity(identity_id="user_a", label="A", username_reference="A"), Identity(identity_id="user_b", label="B", username_reference="B")]
        )
        self.ep_api_search = Endpoint(
            endpoint_id="ep_3",
            url="http://app/api/search",
            path="/api/search",
            method_set=["GET"],
            parameters=[Parameter(name="q")]
        )
        
    def test_initialization_applicability(self):
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        endpoints = [self.ep_login, self.ep_api_users, self.ep_api_search]
        state = self.engine.initialize(endpoints)
        
        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        
        self.assertIn("COVERAGE_INITIALIZED", output)
        
        # Validate that login is applicable
        self.assertEqual(state.coverage_map["authentication.basic"].status, TestState.READY)
        
        # IDOR applicable on ep_2
        self.assertEqual(state.endpoint_coverage_map["ep_2"]["authorization.idor"].status, TestState.READY)
        # IDOR NOT applicable on ep_1
        self.assertEqual(state.endpoint_coverage_map["ep_1"]["authorization.idor"].status, TestState.NOT_APPLICABLE)
        
    def test_partial_coverage_does_not_mark_complete(self):
        # Suppose XSS (xss.reflected) applies to both ep_2 and ep_3
        endpoints = [self.ep_api_users, self.ep_api_search]
        self.engine.initialize(endpoints)
        
        # Force ep_2 to reflect input to make it applicable for xss.reflected
        self.ep_api_users.parameters.append(Parameter(name="filter"))
        self.engine.mark_applicable("xss.reflected", "ep_2", True)
        self.engine.mark_applicable("xss.reflected", "ep_3", True)
        
        # Run XSS tool on ep_3 only, found nothing
        self.engine.mark_tested("xss.reflected", "ep_3", TestState.REJECTED)
        
        # Global state should be INCONCLUSIVE because ep_2 is not tested yet
        self.assertEqual(self.engine.state.coverage_map["xss.reflected"].status, TestState.INCONCLUSIVE)
        
        # Now finish ep_2
        self.engine.mark_tested("xss.reflected", "ep_2", TestState.REJECTED)
        
        # NOW it should be globally rejected
        self.assertEqual(self.engine.state.coverage_map["xss.reflected"].status, TestState.REJECTED)
        
    def test_single_finding_marks_globally_confirmed(self):
        endpoints = [self.ep_api_users, self.ep_api_search]
        self.engine.initialize(endpoints)
        
        self.engine.mark_applicable("xss.reflected", "ep_2", True)
        self.engine.mark_applicable("xss.reflected", "ep_3", True)
        
        # Found XSS on ep_3!
        self.engine.mark_tested("xss.reflected", "ep_3", TestState.CONFIRMED)
        
        # Global state should immediately be CONFIRMED
        self.assertEqual(self.engine.state.coverage_map["xss.reflected"].status, TestState.CONFIRMED)

    def test_coverage_initialization(self):
        """Coverage engine initializes with correct applicable tests (V2 adaptation)"""
        engine = CoverageEngine(self.catalog)
        
        # Simulating TargetProfile with multiple endpoints
        engine.initialize([self.ep_login, self.ep_api_users])
        
        applicable = [t for t, s in engine.state.coverage_map.items() if s.status != TestState.NOT_APPLICABLE]
        self.assertTrue(len(applicable) > 0)
        
        # Check an unapplicable test (like IDOR on login endpoint only)
        # Wait, IDOR applies to ep_api_users, so it IS applicable globally.
        self.assertEqual(engine.state.coverage_map["authorization.idor"].status, TestState.READY)

    def test_mark_tested_sets_state(self):
        """Marking test tested updates state"""
        engine = CoverageEngine(self.catalog)
        engine.initialize([self.ep_api_users]) # IDOR applicable
        
        engine.mark_tested("authorization.idor", None, TestState.CONFIRMED, None)
        
        self.assertEqual(engine.state.coverage_map["authorization.idor"].status, TestState.CONFIRMED)

    def test_nuclei_zero_findings_not_auto_complete(self):
        """Nuclei zero findings does NOT mark XSS complete"""
        engine = CoverageEngine(self.catalog)
        
        # Mocking 87 endpoints would be tedious, we'll just test the principle:
        # XSS is applicable to 2 endpoints, we scan 1 and find nothing.
        self.ep_api_users.parameters.append(Parameter(name="test"))
        engine.initialize([self.ep_api_users, self.ep_api_search])
        
        # Mark tested on one endpoint with REJECTED
        engine.mark_tested("xss.reflected", "ep_3", TestState.REJECTED)
        
        # Framework should not auto-complete the global state
        self.assertEqual(engine.state.coverage_map["xss.reflected"].status, TestState.INCONCLUSIVE)

    def test_coverage_gap_detection(self):
        """Gaps correctly identified"""
        engine = CoverageEngine(self.catalog)
        engine.initialize([self.ep_login, self.ep_api_users])
        
        # Mock state
        engine.state.coverage_map["authentication.basic"].status = TestState.CONFIRMED
        engine.state.coverage_map["authorization.idor"].status = TestState.NOT_TESTED
        engine.state.coverage_map["xss.reflected"].status = TestState.INCONCLUSIVE
        
        gaps = engine.get_coverage_gaps()
        self.assertIn("authorization.idor", gaps)
        self.assertIn("xss.reflected", gaps)
        self.assertNotIn("authentication.basic", gaps)

    def test_coverage_calculation(self):
        """Coverage percentage calculated correctly"""
        engine = CoverageEngine(self.catalog)
        engine.initialize([self.ep_login, self.ep_api_users])
        
        # Force states
        # 4 applicable: auth.basic, idor, sqli, xss
        engine.state.coverage_map["authentication.basic"].status = TestState.CONFIRMED
        engine.state.coverage_map["authorization.idor"].status = TestState.CONFIRMED
        engine.state.coverage_map["input_validation.sqli"].status = TestState.NOT_TESTED
        engine.state.coverage_map["xss.reflected"].status = TestState.BLOCKED
        
        # 3 terminal (CONFIRMED, CONFIRMED, BLOCKED) / 4 applicable = 75.0%
        coverage = engine.calculate_coverage_pct()
        self.assertEqual(coverage, 75.0)

    def test_terminal_state_detection(self):
        """Terminal states correctly identified"""
        terminal = {TestState.CONFIRMED, TestState.REJECTED, 
                    TestState.BLOCKED, TestState.NOT_APPLICABLE}
        
        engine = CoverageEngine(self.catalog)
        engine.initialize([])
        
        for state in terminal:
            engine.state.coverage_map["test"] = type('obj', (object,), {'status': state})
            self.assertTrue(engine.is_test_terminal("test"))
        
        non_terminal = {TestState.NOT_TESTED, TestState.READY, TestState.RUNNING, TestState.INCONCLUSIVE}
        for state in non_terminal:
            engine.state.coverage_map["test"] = type('obj', (object,), {'status': state})
            self.assertFalse(engine.is_test_terminal("test"))

if __name__ == '__main__':
    unittest.main()
