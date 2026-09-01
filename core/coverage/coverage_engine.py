import logging
import json
import os
from typing import Dict, List, Optional

from core.coverage.catalog import TestCatalog
from core.coverage.applicability import ApplicabilityEngine
from core.coverage.coverage_state import CoverageStateStore
from core.coverage.test_definition import TestState, SecurityTestDefinition
from core.memory.shared_context_v2 import SharedContextV2

logger = logging.getLogger(__name__)


class CoverageEngine:
    """Orchestrates test state transitions, enforces deterministic coverage rules, and handles persistence."""

    def __init__(self, shared_context: SharedContextV2, persistence_path: str = "coverage_state.json"):
        self.shared_context = shared_context
        self.catalog = TestCatalog()
        self.applicability = ApplicabilityEngine(shared_context)
        self.state_store = CoverageStateStore()
        self.persistence_path = persistence_path
        
    def initialize_coverage(self):
        """Evaluate applicability and seed the initial state store."""
        category_counts: Dict[str, Dict[str, int]] = {}
        for cat in self.catalog.CATEGORIES:
            category_counts[cat] = {"applicable": 0, "total": 0}
            
        all_tests = self.catalog.get_all_tests()
        
        for test in all_tests:
            category_counts[test.category]["total"] += 1
            if self.applicability.is_applicable(test):
                self.state_store.init_test(test.test_id, TestState.READY)
                category_counts[test.category]["applicable"] += 1
            else:
                self.state_store.init_test(test.test_id, TestState.NOT_APPLICABLE)

        logger.info("COVERAGE_INITIALIZED")
        for cat in self.catalog.CATEGORIES:
            if category_counts[cat]["total"] > 0:
                msg = f"{cat.ljust(20)} {category_counts[cat]['applicable']}/{category_counts[cat]['total']}"
                print(msg)
                logger.info(msg)
                
        self._push_to_shared_context()
        self.save_coverage()

    def report_capability_coverage(self, capability_name: str, covered_test_ids: List[str], findings: List[Dict], tool_success: bool):
        """
        Each capability must report what security classes it actually covered.
        A generic tool returning 0 findings does not imply unrelated classes are complete.
        """
        for test_id in covered_test_ids:
            self.evaluate_test_result(test_id, findings, tool_success)
            
        self._detect_gaps()
        self._push_to_shared_context()
        self.save_coverage()
        
        # Check if complete
        self._check_completion()

    def evaluate_test_result(self, test_id: str, tool_findings: List[Dict], tool_success: bool):
        """
        Critical Rule: A scanner returning zero findings must never mark a vulnerability 
        class as complete unless the corresponding coverage rule says the class was actually tested.
        """
        test = self.catalog.get_test(test_id)
        if not test:
            logger.warning(f"Evaluating unknown test {test_id}")
            return
            
        current_state = self.state_store.get_test_state(test_id)
        if current_state in [TestState.NOT_APPLICABLE, TestState.CONFIRMED]:
            return
            
        previous_state = current_state
            
        if len(tool_findings) > 0:
            # We found something, the test is confirmed
            self.state_store.update_test_state(test_id, TestState.CONFIRMED)
            logger.info(f"COVERAGE_UPDATE: Test {test_id} marked CONFIRMED due to findings.")
        else:
            # Zero findings. Did the tool actually succeed and test it properly?
            if tool_success:
                # Based on our deterministic rule, a successful scan with zero findings 
                # means the test is REJECTED (as in, the vulnerability is rejected/not present)
                self.state_store.update_test_state(test_id, TestState.REJECTED)
                logger.info(f"COVERAGE_UPDATE: Test {test_id} marked REJECTED (no findings but tool succeeded).")
            else:
                self.state_store.update_test_state(test_id, TestState.BLOCKED)
                logger.info(f"COVERAGE_UPDATE: Test {test_id} marked BLOCKED (no findings, tool failed/unreliable).")
                
        if previous_state != self.state_store.get_test_state(test_id):
            self.save_coverage()

    def _detect_gaps(self):
        """Detect and log coverage gaps for the LLM to reason over."""
        states = self.state_store.get_all_states()
        gaps = []
        for test_id, state in states.items():
            if state in [TestState.NOT_TESTED, TestState.READY, TestState.BLOCKED, TestState.INCONCLUSIVE]:
                gaps.append(test_id)
                logger.info(f"COVERAGE_GAP_DETECTED: {test_id} is in non-terminal state {state}")
                
        self.shared_context.coverage_gaps = gaps

    def _push_to_shared_context(self):
        """Add current coverage to SharedContext so DeepSeek can reason over gaps."""
        states = self.state_store.get_all_states()
        
        # Build metrics mapping category -> total / confirmed / rejected etc
        metrics = {}
        for cat in self.catalog.CATEGORIES:
            cat_tests = self.catalog.get_tests_by_category(cat)
            cat_metrics = {state.value: 0 for state in TestState}
            for test in cat_tests:
                st = self.state_store.get_test_state(test.test_id)
                cat_metrics[st.value] += 1
            metrics[cat] = cat_metrics
            
        self.shared_context.coverage_metrics = metrics
        
    def _check_completion(self):
        """Check if coverage is fully complete."""
        states = self.state_store.get_all_states()
        if not states:
            return
            
        terminal_states = [TestState.CONFIRMED, TestState.REJECTED, TestState.BLOCKED, TestState.NOT_APPLICABLE]
        
        for state in states.values():
            if state not in terminal_states:
                return
                
        logger.info("COVERAGE_COMPLETE: All deterministic coverage tests reached terminal states.")

    def save_coverage(self):
        """Persist coverage state to disk."""
        try:
            states_str_keys = {k: v.value for k, v in self.state_store.get_all_states().items()}
            with open(self.persistence_path, "w") as f:
                json.dump(states_str_keys, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to persist coverage state: {e}")

    def load_coverage(self):
        """Load coverage state from disk."""
        if not os.path.exists(self.persistence_path):
            return
            
        try:
            with open(self.persistence_path, "r") as f:
                states_str_keys = json.load(f)
                
            for k, v in states_str_keys.items():
                self.state_store.update_test_state(k, TestState(v))
            self._push_to_shared_context()
        except Exception as e:
            logger.error(f"Failed to load coverage state: {e}")
