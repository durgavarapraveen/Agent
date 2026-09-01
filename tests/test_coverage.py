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

if __name__ == '__main__':
    unittest.main()
