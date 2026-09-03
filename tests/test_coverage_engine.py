import unittest
import logging
import sys
import io
import os

from core.coverage.coverage_engine import CoverageEngine
from core.domain.coverage import TestState
from core.memory.shared_context_v2 import SharedContextV2

logging.basicConfig(level=logging.INFO)

class TestCoverageEnginePhase4(unittest.TestCase):
    
    def setUp(self):
        self.context = SharedContextV2(target="example.com")
        self.persistence_path = "test_coverage_state.json"
        self.engine = CoverageEngine(self.context, persistence_path=self.persistence_path)
        
    def tearDown(self):
        if os.path.exists(self.persistence_path):
            os.remove(self.persistence_path)

    def test_untested_sqli_remains_not_tested(self):
        """Test 1: Untested SQLi remains NOT_TESTED."""
        # Do not initialize coverage so it's NOT_TESTED, or init it but it remains READY
        # Actually, initialization puts it in READY. Let's verify it's NOT_TESTED before init.
        state = self.engine.state_store.get_test_state("sql_injection_baseline_01")
        self.assertEqual(state, TestState.NOT_TESTED)

    def test_nuclei_zero_results_do_not_mark_xss_complete(self):
        """Test 2: Nuclei zero results do not mark XSS complete."""
        self.engine.initialize_coverage()
        
        # Capability 'nuclei' runs but only covers sql_injection
        self.engine.report_capability_coverage(
            capability_name="nuclei", 
            covered_test_ids=["sql_injection_baseline_01"], 
            findings=[], 
            tool_success=True
        )
        
        # SQLi should be REJECTED (vulnerability not present)
        sqli_state = self.engine.state_store.get_test_state("sql_injection_baseline_01")
        self.assertEqual(sqli_state, TestState.REJECTED)
        
        # XSS should remain READY (not marked complete just because Nuclei returned 0 findings)
        xss_state = self.engine.state_store.get_test_state("xss_baseline_01")
        self.assertEqual(xss_state, TestState.READY)

    def test_failed_tools_produce_blocked_coverage(self):
        """Test 3: Failed tools produce BLOCKED coverage."""
        self.engine.initialize_coverage()
        
        # Tool fails to run
        self.engine.report_capability_coverage(
            capability_name="nmap", 
            covered_test_ids=["misconfiguration_baseline_01"], 
            findings=[], 
            tool_success=False
        )
        
        state = self.engine.state_store.get_test_state("misconfiguration_baseline_01")
        self.assertEqual(state, TestState.BLOCKED)

    def test_confirmed_findings_do_not_imply_unrelated_complete(self):
        """Test 4: Confirmed findings do not imply unrelated classes are complete."""
        self.engine.initialize_coverage()
        
        # Capability 'sqlmap' confirms SQLi
        self.engine.report_capability_coverage(
            capability_name="sqlmap", 
            covered_test_ids=["sql_injection_baseline_01"], 
            findings=[{"vuln": "sqli"}], 
            tool_success=True
        )
        
        # SQLi is CONFIRMED
        sqli_state = self.engine.state_store.get_test_state("sql_injection_baseline_01")
        self.assertEqual(sqli_state, TestState.CONFIRMED)
        
        # Auth is NOT complete
        auth_state = self.engine.state_store.get_test_state("authentication_baseline_01")
        self.assertEqual(auth_state, TestState.READY)

    def test_shared_context_and_persistence(self):
        self.engine.initialize_coverage()
        
        self.engine.report_capability_coverage(
            capability_name="mock_tool", 
            covered_test_ids=["xss_baseline_01"], 
            findings=[], 
            tool_success=True
        )
        
        # Verify Context Pushing
        # It was REJECTED so it's a terminal state and should NOT be in gaps.
        self.assertNotIn("xss_baseline_01", self.context.coverage_gaps)
        
        auth_gap = "authentication_baseline_01" in self.context.coverage_gaps
        self.assertTrue(auth_gap)
        
        # Verify persistence
        self.assertTrue(os.path.exists(self.persistence_path))
        
        new_engine = CoverageEngine(self.context, persistence_path=self.persistence_path)
        new_engine.load_coverage()
        
        loaded_xss_state = new_engine.state_store.get_test_state("xss_baseline_01")
        self.assertEqual(loaded_xss_state, TestState.REJECTED)


if __name__ == '__main__':
    unittest.main()
