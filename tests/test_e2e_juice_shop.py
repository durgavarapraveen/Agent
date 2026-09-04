import os
import tempfile
import unittest

from core.security.security_context import SecurityContext
from core.security.capability_registry import CapabilityRegistry, CapabilityDefinition
from core.coverage.security_test_catalog import build_default_catalog
from core.coverage.applicability_engine import ApplicabilityEngine
from core.coverage.coverage_matrix import CoverageMatrix, CoverageState
from core.coverage.convergence_engine_v2 import ConvergenceEngine
from core.domain.experiment_v2 import SecurityExperiment
from core.execution.executors.base import ExecutionResult, ExecutionStatus, ExecutorBase
from core.execution.execution_pipeline_v2 import ExecutionPipelineV2
from core.findings.finding import Finding, FindingState
from core.findings.finding_store import FindingStore
from core.tools.tool_portfolio import ToolPortfolio
from core.reasoning.hypothesis_engine import HypothesisEngine
from core.reporting.coverage_report import CoverageReport
from core.knowledge.knowledge_graph import KnowledgeGraph
from core.attack_surface.endpoint_inventory_v2 import EndpointInventoryV2


JUICE_SHOP_ENDPOINTS = [
    {"endpoint_id": "js-login", "url": "/rest/user/login", "method": "POST",
     "parameters": [{"name": "email", "location": "body"}, {"name": "password", "location": "body"}],
     "content_type": "application/json", "auth_required": False},
    {"endpoint_id": "js-search", "url": "/rest/products/search", "method": "GET",
     "parameters": [{"name": "q", "location": "query"}],
     "content_type": "text/html", "auth_required": False},
    {"endpoint_id": "js-basket", "url": "/rest/basket/{id}", "method": "GET",
     "parameters": [{"name": "id", "location": "path"}],
     "content_type": "application/json", "auth_required": True},
    {"endpoint_id": "js-feedback", "url": "/api/Feedbacks", "method": "POST",
     "parameters": [{"name": "comment", "location": "body"}, {"name": "rating", "location": "body"}],
     "content_type": "application/json", "auth_required": False},
    {"endpoint_id": "js-profile", "url": "/api/Users/{id}", "method": "GET",
     "parameters": [{"name": "id", "location": "path"}],
     "content_type": "application/json", "auth_required": True},
]

IDENTITIES = ["admin", "user1", "user2"]


class StubSQLiExecutor(ExecutorBase):
    def validate_inputs(self, inputs):
        return True, None
    def validate_target(self, endpoint, identity):
        return True, None
    def execute(self, experiment):
        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            evidence={"results": [{"payload": "' OR 1=1--", "error_detected": True, "status_code": 500, "response_body": "SQL syntax error"}]},
        )


class StubXSSExecutor(ExecutorBase):
    def validate_inputs(self, inputs):
        return True, None
    def validate_target(self, endpoint, identity):
        return True, None
    def execute(self, experiment):
        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            evidence={"results": [{"payload": "<script>alert(1)</script>", "reflection_detected": True, "status_code": 200, "response_body": "<script>alert(1)</script>"}]},
        )


class StubAuthzExecutor(ExecutorBase):
    def validate_inputs(self, inputs):
        return True, None
    def validate_target(self, endpoint, identity):
        return True, None
    def execute(self, experiment):
        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            evidence={"status_code": 200, "response_body": '{"id":42}', "response_length": 10},
        )


class StubRefusalExecutor(ExecutorBase):
    def validate_inputs(self, inputs):
        return True, None
    def validate_target(self, endpoint, identity):
        return True, None
    def execute(self, experiment):
        return ExecutionResult(
            status=ExecutionStatus.FAILURE,
            error_code="LLM_REFUSAL",
            error_message="I cannot assist with this request",
        )


class StubTimeoutExecutor(ExecutorBase):
    def validate_inputs(self, inputs):
        return True, None
    def validate_target(self, endpoint, identity):
        return True, None
    def execute(self, experiment):
        return ExecutionResult(
            status=ExecutionStatus.TIMEOUT,
            error_code="TIMEOUT",
            error_message="timed out after 30s",
        )


class TestJuiceShopE2E(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mktemp(suffix=".json")
        self.catalog = build_default_catalog()
        self.applicability = ApplicabilityEngine(self.catalog)
        self.inventory = EndpointInventoryV2()
        for ep in JUICE_SHOP_ENDPOINTS:
            self.inventory.add_endpoint(dict(ep))
        self.ctx = SecurityContext(target="localhost:3000", scope=["*.localhost"])

    def tearDown(self):
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def test_discover_juice_shop_endpoints(self):
        eps = self.inventory.list_endpoints()
        self.assertEqual(len(eps), 5)
        login = self.inventory.find_by_path("/rest/user/login")
        self.assertEqual(len(login), 1)

    def test_applicability_matrix(self):
        ep = JUICE_SHOP_ENDPOINTS[1]  # search - has query param + HTML
        applicable = self.applicability.get_applicable_tests(ep, identities=IDENTITIES)
        test_types = {t.attack_type for t in applicable}
        self.assertIn("sqli", test_types)
        self.assertIn("xss", test_types)

    def test_execute_sql_injection_tests(self):
        matrix = CoverageMatrix(["js-search"], ["sqli"])
        store = FindingStore(self.tmp)
        pipe = ExecutionPipelineV2({"sqli": StubSQLiExecutor()}, ToolPortfolio(), matrix, store)
        exp = SecurityExperiment(hypothesis_id="h1", endpoint_id="js-search", capability="sqli")
        result = pipe.execute(exp)
        self.assertTrue(result.success)
        self.assertIsNotNone(result.finding)

    def test_execute_xss_tests(self):
        matrix = CoverageMatrix(["js-search"], ["xss"])
        store = FindingStore(self.tmp)
        pipe = ExecutionPipelineV2({"xss": StubXSSExecutor()}, ToolPortfolio(), matrix, store)
        exp = SecurityExperiment(hypothesis_id="h1", endpoint_id="js-search", capability="xss")
        result = pipe.execute(exp)
        self.assertTrue(result.success)

    def test_execute_authorization_tests(self):
        matrix = CoverageMatrix(["js-basket"], ["authz"])
        store = FindingStore(self.tmp)
        pipe = ExecutionPipelineV2({"authz": StubAuthzExecutor()}, ToolPortfolio(), matrix, store)
        exp = SecurityExperiment(hypothesis_id="h1", endpoint_id="js-basket", capability="authz")
        result = pipe.execute(exp)
        self.assertTrue(result.success)

    def test_coverage_matrix_populated(self):
        tests = ["sqli", "xss", "authz"]
        endpoints = ["js-search", "js-basket"]
        matrix = CoverageMatrix(endpoints, tests)
        store = FindingStore(self.tmp)
        executors = {"sqli": StubSQLiExecutor(), "xss": StubXSSExecutor(), "authz": StubAuthzExecutor()}
        pipe = ExecutionPipelineV2(executors, ToolPortfolio(), matrix, store)

        for ep in endpoints:
            for t in tests:
                exp = SecurityExperiment(hypothesis_id="h1", endpoint_id=ep, capability=t)
                pipe.execute(exp)

        for ep in endpoints:
            for t in tests:
                state = matrix.get_state(ep, t)
                self.assertNotEqual(state, CoverageState.NOT_TESTED, f"{ep}/{t} still NOT_TESTED")

    def test_convergence_reached(self):
        tests = ["sqli", "xss"]
        matrix = CoverageMatrix(["js-search"], tests)
        store = FindingStore(self.tmp)
        executors = {"sqli": StubSQLiExecutor(), "xss": StubXSSExecutor()}
        pipe = ExecutionPipelineV2(executors, ToolPortfolio(), matrix, store)

        for t in tests:
            exp = SecurityExperiment(hypothesis_id="h1", endpoint_id="js-search", capability=t)
            pipe.execute(exp)

        eng = ConvergenceEngine(matrix)
        self.assertTrue(eng.is_converged())

    def test_report_generation(self):
        tests = ["sqli", "xss"]
        matrix = CoverageMatrix(["js-search"], tests)
        store = FindingStore(self.tmp)
        executors = {"sqli": StubSQLiExecutor(), "xss": StubXSSExecutor()}
        pipe = ExecutionPipelineV2(executors, ToolPortfolio(), matrix, store)

        for t in tests:
            exp = SecurityExperiment(hypothesis_id="h1", endpoint_id="js-search", capability=t)
            pipe.execute(exp)

        cat_map = {"sqli": "sqli", "xss": "xss"}
        report = CoverageReport(matrix, store, test_category_map=cat_map)
        text = report.generate()
        self.assertIn("COVERAGE ANALYSIS", text)
        self.assertIn("OVERALL COVERAGE: 100%", text)
        self.assertIn("Converged: YES", text)

        json_r = report.generate_json()
        self.assertTrue(json_r["converged"])
        self.assertEqual(json_r["total_findings"], 2)


class TestEdgeCases(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mktemp(suffix=".json")

    def tearDown(self):
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def test_deepseek_refusal_handled(self):
        matrix = CoverageMatrix(["ep1"], ["test1"])
        store = FindingStore(self.tmp)
        pipe = ExecutionPipelineV2({"test1": StubRefusalExecutor()}, ToolPortfolio(), matrix, store)
        exp = SecurityExperiment(hypothesis_id="h1", endpoint_id="ep1", capability="test1")
        result = pipe.execute(exp)
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)

    def test_timeout_handled(self):
        matrix = CoverageMatrix(["ep1"], ["test1"])
        store = FindingStore(self.tmp)
        pipe = ExecutionPipelineV2({"test1": StubTimeoutExecutor()}, ToolPortfolio(), matrix, store)
        exp = SecurityExperiment(hypothesis_id="h1", endpoint_id="ep1", capability="test1")
        result = pipe.execute(exp)
        # Timeout executor returns TIMEOUT status but pipeline still completes
        self.assertTrue(result.success)

    def test_duplicate_experiment_scheduler(self):
        from core.scheduling.experiment_scheduler_v2 import ExperimentScheduler
        sched = ExperimentScheduler()
        exp1 = SecurityExperiment(hypothesis_id="h1", endpoint_id="ep1", capability="sqli", identity_id="admin")
        exp2 = SecurityExperiment(hypothesis_id="h1", endpoint_id="ep1", capability="sqli", identity_id="admin")
        self.assertTrue(sched.queue(exp1))
        self.assertFalse(sched.queue(exp2))

    def test_findings_persisted(self):
        matrix = CoverageMatrix(["ep1"], ["sqli"])
        store = FindingStore(self.tmp)
        pipe = ExecutionPipelineV2({"sqli": StubSQLiExecutor()}, ToolPortfolio(), matrix, store)
        exp = SecurityExperiment(hypothesis_id="h1", endpoint_id="ep1", capability="sqli")
        pipe.execute(exp)
        store2 = FindingStore(self.tmp)
        findings = store2.list_all()
        self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
