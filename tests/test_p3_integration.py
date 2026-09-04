import os
import tempfile
import unittest
from unittest.mock import MagicMock

from core.domain.experiment_v2 import SecurityExperiment
from core.execution.executors.base import ExecutionResult, ExecutionStatus, ExecutorBase
from core.execution.execution_pipeline_v2 import ExecutionPipelineV2, PipelineStage
from core.evidence.evidence import Evidence
from core.evidence.validator import EvidenceValidator, ValidationResult
from core.coverage.coverage_matrix import CoverageMatrix, CoverageState
from core.coverage.convergence_engine_v2 import ConvergenceEngine
from core.coverage.security_test_catalog import build_default_catalog
from core.findings.finding import Finding, FindingState
from core.findings.finding_store import FindingStore
from core.tools.tool_portfolio import ToolPortfolio
from core.failure.failure_taxonomy import FailureClassifier, FailureType
from core.recovery.recovery_policy import RecoveryPolicy, RetryAction
from core.reasoning.hypothesis_engine import HypothesisEngine
from core.reporting.coverage_report import CoverageReport
from core.knowledge.knowledge_graph import KnowledgeGraph


class StubExecutor(ExecutorBase):
    def __init__(self, result: ExecutionResult = None):
        super().__init__()
        self._result = result or ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            evidence={"status_code": 200, "body": "OK"},
        )

    def validate_inputs(self, inputs):
        return True, None

    def validate_target(self, endpoint, identity):
        return True, None

    def execute(self, experiment):
        return self._result


class FailingExecutor(ExecutorBase):
    def __init__(self, error_msg="tool failed", error_code="EXECUTION_ERROR"):
        super().__init__()
        self._msg = error_msg
        self._code = error_code

    def validate_inputs(self, inputs):
        return True, None

    def validate_target(self, endpoint, identity):
        return True, None

    def execute(self, experiment):
        return ExecutionResult(
            status=ExecutionStatus.FAILURE,
            error_code=self._code,
            error_message=self._msg,
        )


def _make_pipeline(executor=None, finding_path=None):
    path = finding_path or tempfile.mktemp(suffix=".json")
    matrix = CoverageMatrix(["ep1"], ["sqli"])
    store = FindingStore(path)
    portfolio = ToolPortfolio()
    executors = {"sqli": executor or StubExecutor()}
    return ExecutionPipelineV2(executors, portfolio, matrix, store), matrix, store, path


def _make_experiment(capability="sqli", endpoint="ep1"):
    return SecurityExperiment(
        hypothesis_id="h1", endpoint_id=endpoint,
        capability=capability, priority=0.9,
    )


class TestExecutionPipelineSetup(unittest.TestCase):
    def test_execution_pipeline_setup_stage(self):
        pipe, _, _, path = _make_pipeline()
        exp = SecurityExperiment(hypothesis_id="h1", endpoint_id="", capability="sqli")
        result = pipe.execute(exp)
        self.assertEqual(result.stage_reached, PipelineStage.SETUP)
        self.assertFalse(result.success)
        os.unlink(path) if os.path.exists(path) else None


class TestExecutionPipelineExecute(unittest.TestCase):
    def test_execution_pipeline_execute_stage(self):
        pipe, _, _, path = _make_pipeline()
        result = pipe.execute(_make_experiment())
        self.assertIsNotNone(result.execution_result)
        self.assertEqual(result.execution_result.status, ExecutionStatus.SUCCESS)
        os.unlink(path) if os.path.exists(path) else None


class TestExecutionPipelineCollect(unittest.TestCase):
    def test_execution_pipeline_collect_evidence(self):
        pipe, _, _, path = _make_pipeline()
        result = pipe.execute(_make_experiment())
        self.assertIsNotNone(result.evidence)
        self.assertIsInstance(result.evidence, Evidence)
        os.unlink(path) if os.path.exists(path) else None


class TestExecutionPipelineValidate(unittest.TestCase):
    def test_execution_pipeline_validate_stage(self):
        pipe, _, _, path = _make_pipeline()
        result = pipe.execute(_make_experiment())
        self.assertIsNotNone(result.validation)
        self.assertIsInstance(result.validation, ValidationResult)
        os.unlink(path) if os.path.exists(path) else None


class TestExecutionPipelineRecord(unittest.TestCase):
    def test_execution_pipeline_record_stage(self):
        pipe, matrix, store, path = _make_pipeline()
        result = pipe.execute(_make_experiment())
        self.assertEqual(result.stage_reached, PipelineStage.RECORD)
        self.assertTrue(result.success)
        self.assertIsNotNone(result.finding)
        self.assertNotEqual(matrix.get_state("ep1", "sqli"), CoverageState.NOT_TESTED)
        stored = store.list_all()
        self.assertEqual(len(stored), 1)
        os.unlink(path) if os.path.exists(path) else None


class TestHypothesis(unittest.TestCase):
    def test_hypothesis_generation_from_gaps(self):
        catalog = build_default_catalog()
        engine = HypothesisEngine(catalog)
        gaps = [("ep1", "sqli_basic_01"), ("ep1", "xss_reflected_01")]
        hyps = engine.generate(gaps)
        self.assertEqual(len(hyps), 2)

    def test_hypothesis_ranking_by_priority(self):
        catalog = build_default_catalog()
        engine = HypothesisEngine(catalog)
        gaps = [("ep1", "sqli_basic_01"), ("ep1", "cors_misconfig_01"), ("ep1", "xss_reflected_01")]
        hyps = engine.generate(gaps)
        ranked = engine.rank(hyps)
        self.assertGreaterEqual(ranked[0].priority, ranked[1].priority)
        self.assertGreaterEqual(ranked[1].priority, ranked[2].priority)


class TestFailureRecovery(unittest.TestCase):
    def test_deepseek_refusal_not_terminal(self):
        classifier = FailureClassifier()
        ft = classifier.classify(Exception("I cannot assist with this request"))
        self.assertEqual(ft, FailureType.LLM_REFUSAL)
        policy = RecoveryPolicy()
        action = policy.get_action(ft)
        self.assertEqual(action, RetryAction.LOG_AND_CONTINUE)

    def test_tool_failure_triggers_fallback(self):
        classifier = FailureClassifier()
        ft = classifier.classify(Exception("command not found: sqlmap"))
        self.assertEqual(ft, FailureType.TOOL_NOT_FOUND)
        policy = RecoveryPolicy()
        action = policy.get_action(ft)
        self.assertEqual(action, RetryAction.FALLBACK)

    def test_duplicate_task_returns_cached(self):
        classifier = FailureClassifier()
        ft = classifier.classify(Exception("duplicate already exists"))
        self.assertEqual(ft, FailureType.DUPLICATE_TASK)
        policy = RecoveryPolicy()
        action = policy.get_action(ft)
        self.assertEqual(action, RetryAction.LOG_AND_CONTINUE)

    def test_network_error_retries(self):
        classifier = FailureClassifier()
        ft = classifier.classify(Exception("ConnectionRefused"))
        self.assertEqual(ft, FailureType.NETWORK_ERROR)
        policy = RecoveryPolicy()
        action = policy.get_action(ft)
        self.assertEqual(action, RetryAction.RETRY)
        self.assertEqual(policy.get_max_retries(ft), 3)

    def test_authorization_error_blocks(self):
        classifier = FailureClassifier()
        ft = classifier.classify(Exception("403 Forbidden"))
        self.assertEqual(ft, FailureType.AUTHORIZATION_ERROR)
        policy = RecoveryPolicy()
        self.assertEqual(policy.get_action(ft), RetryAction.BLOCK)


class TestCoverageReportHonest(unittest.TestCase):
    def test_coverage_report_honest(self):
        path = tempfile.mktemp(suffix=".json")
        matrix = CoverageMatrix(["ep1"], ["sqli_01", "xss_01", "idor_01"])
        store = FindingStore(path)
        matrix.update_state("ep1", "sqli_01", CoverageState.CONFIRMED)
        # xss_01 and idor_01 remain NOT_TESTED
        f = Finding(title="SQLi", description="Found SQLi", severity="HIGH", state="confirmed")
        store.store(f)
        report = CoverageReport(matrix, store, test_category_map={"sqli_01": "sqli", "xss_01": "xss", "idor_01": "authz"})
        text = report.generate()
        self.assertIn("OVERALL COVERAGE: 33%", text)
        self.assertIn("Converged: NO", text)
        self.assertIn("Remaining Gaps:", text)
        json_report = report.generate_json()
        self.assertFalse(json_report["converged"])
        self.assertEqual(json_report["confirmed_findings"], 1)
        os.unlink(path) if os.path.exists(path) else None


class TestConvergenceDetection(unittest.TestCase):
    def test_convergence_detection(self):
        matrix = CoverageMatrix(["ep1"], ["t1", "t2"])
        eng = ConvergenceEngine(matrix)
        self.assertFalse(eng.is_converged())
        matrix.update_state("ep1", "t1", CoverageState.CONFIRMED)
        matrix.update_state("ep1", "t2", CoverageState.REJECTED)
        self.assertTrue(eng.is_converged())


class TestEndToEnd(unittest.TestCase):
    def test_end_to_end_pipeline(self):
        path = tempfile.mktemp(suffix=".json")
        matrix = CoverageMatrix(["ep1"], ["sqli", "xss"])
        store = FindingStore(path)
        portfolio = ToolPortfolio()
        sqli_result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            evidence={"results": [{"payload": "'", "error_detected": True, "status_code": 500, "response_body": "SQL syntax error"}]},
        )
        xss_result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            evidence={"results": [{"payload": "<script>", "reflection_detected": False, "status_code": 200, "response_body": "safe"}]},
        )
        executors = {"sqli": StubExecutor(sqli_result), "xss": StubExecutor(xss_result)}
        pipe = ExecutionPipelineV2(executors, portfolio, matrix, store)

        exp_sqli = _make_experiment("sqli", "ep1")
        exp_xss = _make_experiment("xss", "ep1")
        r1 = pipe.execute(exp_sqli)
        r2 = pipe.execute(exp_xss)

        self.assertTrue(r1.success)
        self.assertTrue(r2.success)
        self.assertEqual(len(store.list_all()), 2)
        self.assertNotEqual(matrix.get_state("ep1", "sqli"), CoverageState.NOT_TESTED)
        self.assertNotEqual(matrix.get_state("ep1", "xss"), CoverageState.NOT_TESTED)

        eng = ConvergenceEngine(matrix)
        self.assertTrue(eng.is_converged())
        os.unlink(path) if os.path.exists(path) else None


if __name__ == "__main__":
    unittest.main()
