import logging
from core.coverage.catalog import SecurityTestCatalog
from core.coverage.applicability import ApplicabilityEngine
from core.coverage.coverage_state import CoverageStateV2, TestRunState
from core.domain.coverage import TestState
from core.domain.endpoint import Endpoint
from core.domain.evidence import SecurityEvidence
from typing import List, Dict, Optional
from datetime import datetime
import json
import os

logger = logging.getLogger(__name__)

class CoverageEngine:
    def __init__(self, test_catalog: SecurityTestCatalog):
        self.catalog = test_catalog
        self.state = CoverageStateV2()
        self.applicability_engine = ApplicabilityEngine()
        
    def initialize(self, target_endpoints: List[Endpoint]) -> CoverageStateV2:
        all_tests = self.catalog.get_all_tests()
        
        applicable_count = 0
        not_applicable_count = 0
        unknown_count = 0
        
        for test in all_tests:
            is_applicable_anywhere = False
            
            for endpoint in target_endpoints:
                if endpoint.endpoint_id not in self.state.endpoint_coverage_map:
                    self.state.endpoint_coverage_map[endpoint.endpoint_id] = {}
                    
                # Evaluate rules
                endpoint_applicable = True
                if not test.applicability_rules:
                    # If no rules, assume universally applicable
                    endpoint_applicable = True
                else:
                    # ALL rules must match (AND condition implicitly)
                    for rule in test.applicability_rules:
                        if not self.applicability_engine.evaluate_rule(rule, endpoint):
                            endpoint_applicable = False
                            break
                            
                if endpoint_applicable:
                    is_applicable_anywhere = True
                    self.state.endpoint_coverage_map[endpoint.endpoint_id][test.test_id] = TestRunState(
                        status=TestState.READY
                    )
                else:
                    self.state.endpoint_coverage_map[endpoint.endpoint_id][test.test_id] = TestRunState(
                        status=TestState.NOT_APPLICABLE
                    )
            
            # Global test state
            if is_applicable_anywhere:
                self.state.coverage_map[test.test_id] = TestRunState(status=TestState.READY)
                applicable_count += 1
                logger.info(f"COVERAGE_UPDATE test={test.test_id} status=READY")
                print(f"COVERAGE_UPDATE test={test.test_id} status=READY")
            else:
                self.state.coverage_map[test.test_id] = TestRunState(status=TestState.NOT_APPLICABLE)
                not_applicable_count += 1
                
        logger.info("COVERAGE_INITIALIZED")
        print("COVERAGE_INITIALIZED")
        logger.info(f"applicable_tests={applicable_count}")
        print(f"applicable_tests={applicable_count}")
        logger.info(f"not_applicable_tests={not_applicable_count}")
        print(f"not_applicable_tests={not_applicable_count}")
        logger.info(f"unknown_tests={unknown_count}")
        print(f"unknown_tests={unknown_count}")
        
        return self.state

    def mark_applicable(self, test_id: str, endpoint_id: str, applicable: bool):
        if endpoint_id not in self.state.endpoint_coverage_map:
            self.state.endpoint_coverage_map[endpoint_id] = {}
            
        status = TestState.READY if applicable else TestState.NOT_APPLICABLE
        if test_id not in self.state.endpoint_coverage_map[endpoint_id]:
            self.state.endpoint_coverage_map[endpoint_id][test_id] = TestRunState(status=status)
        else:
            self.state.endpoint_coverage_map[endpoint_id][test_id].status = status
            
        logger.info(f"COVERAGE_UPDATE test={test_id} endpoint={endpoint_id} status={status.value}")
        print(f"COVERAGE_UPDATE test={test_id} endpoint={endpoint_id} status={status.value}")

    def mark_tested(self, test_id: str, endpoint_id: Optional[str], status: TestState, evidence: SecurityEvidence = None):
        # Endpoint specific updates
        if endpoint_id:
            if endpoint_id in self.state.endpoint_coverage_map and test_id in self.state.endpoint_coverage_map[endpoint_id]:
                run_state = self.state.endpoint_coverage_map[endpoint_id][test_id]
                run_state.status = status
                run_state.last_executed = datetime.utcnow()
                if evidence:
                    run_state.evidence_collected.append(evidence)
                    
            # Re-evaluate Global State
            self._recalculate_global_state(test_id)
            
        else:
            # If applied globally
            if test_id in self.state.coverage_map:
                run_state = self.state.coverage_map[test_id]
                run_state.status = status
                run_state.last_executed = datetime.utcnow()
                if evidence:
                    run_state.evidence_collected.append(evidence)
                    
                logger.info(f"COVERAGE_UPDATE test={test_id} status={status.value}")
                print(f"COVERAGE_UPDATE test={test_id} status={status.value}")

    def _recalculate_global_state(self, test_id: str):
        applicable_endpoints = []
        for ep_id, test_map in self.state.endpoint_coverage_map.items():
            if test_id in test_map and test_map[test_id].status != TestState.NOT_APPLICABLE:
                applicable_endpoints.append(test_map[test_id])
                
        if not applicable_endpoints:
            return
            
        # If any endpoint is CONFIRMED, the whole class is practically CONFIRMED (we found the vuln!)
        if any(ts.status == TestState.CONFIRMED for ts in applicable_endpoints):
            self.state.coverage_map[test_id].status = TestState.CONFIRMED
            logger.info(f"COVERAGE_UPDATE test={test_id} status=CONFIRMED")
            print(f"COVERAGE_UPDATE test={test_id} status=CONFIRMED")
            return
            
        # Are all applicable endpoints explicitly tested and REJECTED?
        all_rejected = all(ts.status == TestState.REJECTED for ts in applicable_endpoints)
        if all_rejected:
            self.state.coverage_map[test_id].status = TestState.REJECTED
            logger.info(f"COVERAGE_UPDATE test={test_id} status=REJECTED result=REJECTED")
            print(f"COVERAGE_UPDATE test={test_id} status=REJECTED result=REJECTED")
            return
            
        # Otherwise, if some are RUNNING, INCONCLUSIVE, READY, it remains NOT finished.
        self.state.coverage_map[test_id].status = TestState.INCONCLUSIVE

    def get_coverage_gaps(self) -> List[str]:
        gaps = []
        for test_id, run_state in self.state.coverage_map.items():
            if run_state.status in {TestState.NOT_TESTED, TestState.INCONCLUSIVE, TestState.READY}:
                gaps.append(test_id)
        return gaps

    def get_coverage_status(self) -> Dict[str, int]:
        counts = {
            "tests_applicable": 0,
            "tests_not_applicable": 0,
            "tests_not_tested": 0,
            "tests_ready": 0,
            "tests_running": 0,
            "tests_confirmed": 0,
            "tests_rejected": 0,
            "tests_inconclusive": 0,
            "tests_blocked": 0
        }
        
        for test_id, run_state in self.state.coverage_map.items():
            s = run_state.status
            if s != TestState.NOT_APPLICABLE:
                counts["tests_applicable"] += 1
            else:
                counts["tests_not_applicable"] += 1
                
            counts[f"tests_{s.value.lower()}"] += 1
            
        return counts

    def calculate_coverage_pct(self) -> float:
        stats = self.get_coverage_status()
        applicable = stats["tests_applicable"]
        if applicable == 0:
            return 100.0
            
        finished = stats["tests_confirmed"] + stats["tests_rejected"] + stats["tests_blocked"]
        return (finished / applicable) * 100.0

    def is_test_terminal(self, test_id: str) -> bool:
        if test_id not in self.state.coverage_map:
            return False
        status = self.state.coverage_map[test_id].status
        return status in {TestState.CONFIRMED, TestState.REJECTED, TestState.BLOCKED, TestState.NOT_APPLICABLE}

    def get_blocked_tests(self) -> List[str]:
        blocked = []
        for test_id, run_state in self.state.coverage_map.items():
            if run_state.status == TestState.BLOCKED:
                blocked.append(test_id)
        return blocked
        
    def save_checkpoint(self, path: str = ".antigravity/coverage_state.json"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(self.state.model_dump_json(indent=2))
