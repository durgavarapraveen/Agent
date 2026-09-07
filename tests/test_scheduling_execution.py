import pytest
from datetime import datetime, timedelta
from core.scheduling.experiment_scheduler import ExperimentScheduler
from core.execution.execution_pipeline import (
    ExecutionPipelineV2 as ExecutionPipeline, ExecutionResult, ExecutionStatus, PipelineStage
)
from core.coverage.coverage_engine import CoverageEngine
from core.coverage.catalog import SecurityTestCatalog
from core.coverage.test_definition import SecurityTestDefinition, ApplicabilityRule
from core.domain.experiment import SecurityExperiment
from core.domain.endpoint import Endpoint
from core.domain.parameter import Parameter, ParameterType
from core.domain.coverage import TestState
from core.common.schemas import ToolResult


def _make_endpoint(idx: int) -> Endpoint:
    return Endpoint(
        endpoint_id=f"ep_{idx}",
        url=f"https://example.com/api/r{idx}",
        path=f"/api/r{idx}",
        method_set=["GET", "POST"],
        parameters=[Parameter(
            name=f"p{idx}",
            parameter_type=ParameterType.QUERY,
            inferred_data_type="string",
            is_required=True,
        )],
    )


def _make_catalog():
    catalog = SecurityTestCatalog()
    catalog.tests["input_validation.cmdi"] = SecurityTestDefinition(
        test_id="input_validation.cmdi",
        category="command_injection",
        description="Command injection test",
        prerequisites=[],
        applicability_rules=[],
        execution_strategies=["commix"],
        required_evidence=["command_output"],
        oracle="cmdi_oracle",
        risk_level="critical",
    )
    return catalog


def _make_engine():
    catalog = _make_catalog()
    endpoints = [_make_endpoint(i) for i in range(3)]
    engine = CoverageEngine(catalog)
    engine.initialize(endpoints)
    return engine


def _make_experiment(hyp_id="h1", strategy="nuclei", endpoint="ep_0", priority=0.5):
    exp = SecurityExperiment(
        hypothesis_id=hyp_id,
        test_strategy=strategy,
        target_endpoint_id=endpoint,
    )
    exp.confidence = priority
    return exp


class SuccessToolRunner:
    def run(self, tool_name, command, timeout=120):
        return ToolResult(
            success=True, tool_name=tool_name, command=command,
            output="VULNERABLE: SQL injection found", stderr="", exit_code=0,
        )


class FailToolRunner:
    def run(self, tool_name, command, timeout=120):
        return ToolResult(
            success=False, tool_name=tool_name, command=command,
            output="", stderr="connection refused", exit_code=1,
        )


class TimeoutToolRunner:
    def run(self, tool_name, command, timeout=120):
        return ToolResult(
            success=False, tool_name=tool_name, command=command,
            output="", stderr="", exit_code=124, timed_out=True,
        )


class ExceptionToolRunner:
    def run(self, tool_name, command, timeout=120):
        raise RuntimeError("tool binary not found")


class TestExperimentScheduler:
    def test_queue_and_next_highest_priority(self):
        scheduler = ExperimentScheduler()
        exps = []
        priorities = [0.3, 0.9, 0.1, 0.7, 0.5]
        for i, p in enumerate(priorities):
            exp = _make_experiment(hyp_id=f"h{i}", priority=p)
            exps.append((exp, p))
            scheduler.queue(exp, priority=p)

        assert scheduler.size() == 5

        result = scheduler.next()
        assert result.confidence == 0.9

        result = scheduler.next()
        assert result.confidence == 0.7

    def test_same_priority_ordered_by_created_at(self):
        scheduler = ExperimentScheduler()
        exp1 = _make_experiment(hyp_id="h_first")
        exp1.created_at = datetime(2026, 1, 1, 0, 0, 0)

        exp2 = _make_experiment(hyp_id="h_second")
        exp2.created_at = datetime(2026, 1, 1, 0, 0, 1)

        scheduler.queue(exp1, priority=0.5)
        scheduler.queue(exp2, priority=0.5)

        result = scheduler.next()
        assert result.hypothesis_id == "h_first"

    def test_empty_queue_returns_none(self):
        scheduler = ExperimentScheduler()
        assert scheduler.next() is None
        assert scheduler.is_empty()

    def test_clear(self):
        scheduler = ExperimentScheduler()
        for i in range(5):
            scheduler.queue(_make_experiment(hyp_id=f"h{i}"))
        assert scheduler.size() == 5
        scheduler.clear()
        assert scheduler.size() == 0
        assert scheduler.is_empty()

    def test_max_queue_size(self):
        scheduler = ExperimentScheduler()
        for i in range(1005):
            scheduler.queue(_make_experiment(hyp_id=f"h{i}"))
        assert scheduler.size() == 1000

    def test_peek(self):
        scheduler = ExperimentScheduler()
        exp_low = _make_experiment(hyp_id="h1", priority=0.3)
        exp_high = _make_experiment(hyp_id="h2", priority=0.9)
        scheduler.queue(exp_low, priority=0.3)
        scheduler.queue(exp_high, priority=0.9)

        peeked = scheduler.peek()
        assert peeked.hypothesis_id == "h2"
        assert scheduler.size() == 2


class TestExecutionPipeline:
    def test_execute_success_updates_coverage(self):
        engine = _make_engine()
        pipeline = ExecutionPipeline(engine, tool_runner=SuccessToolRunner())

        exp = {"test_id": "input_validation.sqli", "test_strategy": "nuclei", "target_endpoint_id": "ep_0"}
        result = pipeline.execute(exp)

        assert result.status == ExecutionStatus.CONFIRMED
        assert result.evidence is not None
        assert result.finding is not None
        assert result.stage_reached == PipelineStage.RECORD
        assert result.coverage_update is not None
        assert result.coverage_update["state"] == "CONFIRMED"

        state = engine.state.coverage_map.get("input_validation.sqli")
        assert state is not None

    def test_execute_tool_failure_inconclusive(self):
        engine = _make_engine()
        pipeline = ExecutionPipeline(engine, tool_runner=FailToolRunner())

        exp = {"test_id": "input_validation.sqli", "test_strategy": "nuclei", "target_endpoint_id": "ep_0"}
        result = pipeline.execute(exp)

        assert result.status == ExecutionStatus.INCONCLUSIVE
        assert result.finding is None
        assert "failed" in result.error.lower() or "connection" in result.error.lower()

    def test_execute_timeout_inconclusive(self):
        engine = _make_engine()
        pipeline = ExecutionPipeline(engine, tool_runner=TimeoutToolRunner())

        exp = {"test_id": "input_validation.sqli", "test_strategy": "nuclei", "target_endpoint_id": "ep_0"}
        result = pipeline.execute(exp)

        assert result.status == ExecutionStatus.INCONCLUSIVE
        assert "timed out" in result.error.lower()
        assert result.stage_reached == PipelineStage.EXECUTE

    def test_execute_tool_exception_inconclusive(self):
        engine = _make_engine()
        pipeline = ExecutionPipeline(engine, tool_runner=ExceptionToolRunner())

        exp = {"test_id": "input_validation.sqli", "test_strategy": "nuclei", "target_endpoint_id": "ep_0"}
        result = pipeline.execute(exp)

        assert result.status == ExecutionStatus.INCONCLUSIVE

    def test_setup_fails_no_test_def(self):
        engine = _make_engine()
        pipeline = ExecutionPipeline(engine, tool_runner=SuccessToolRunner())

        exp = {"test_id": "nonexistent.test", "test_strategy": "nuclei", "target_endpoint_id": "ep_0"}
        result = pipeline.execute(exp)

        assert result.status == ExecutionStatus.BLOCKED
        assert result.stage_reached == PipelineStage.SETUP

    def test_evidence_collected_for_all_findings(self):
        engine = _make_engine()
        pipeline = ExecutionPipeline(engine, tool_runner=SuccessToolRunner())

        tests = ["input_validation.sqli", "xss.reflected", "input_validation.cmdi"]
        for tid in tests:
            exp = {"test_id": tid, "test_strategy": "nuclei", "target_endpoint_id": "ep_0"}
            result = pipeline.execute(exp)
            assert result.evidence is not None

        findings = pipeline.get_findings()
        evidence = pipeline.get_evidence()
        assert len(findings) == 3
        assert len(evidence) == 3

        for f in findings:
            assert len(f.evidence_ids) == 1
            matching_ev = [e for e in evidence if e.id == f.evidence_ids[0]]
            assert len(matching_ev) == 1

    def test_execute_with_domain_object(self):
        engine = _make_engine()
        pipeline = ExecutionPipeline(engine, tool_runner=SuccessToolRunner())

        exp = SecurityExperiment(
            hypothesis_id="hyp_1",
            test_strategy="nuclei",
            target_endpoint_id="ep_0",
        )
        result = pipeline.execute(exp)
        assert result.status in (ExecutionStatus.CONFIRMED, ExecutionStatus.BLOCKED)

    def test_rejected_when_tool_finds_nothing(self):
        engine = _make_engine()

        class NoFindingsToolRunner:
            def run(self, tool_name, command, timeout=120):
                return ToolResult(
                    success=False, tool_name=tool_name, command=command,
                    output="Scan complete, 0 findings", stderr="", exit_code=0,
                )

        pipeline = ExecutionPipeline(engine, tool_runner=NoFindingsToolRunner())
        exp = {"test_id": "input_validation.sqli", "test_strategy": "nuclei", "target_endpoint_id": "ep_0"}
        result = pipeline.execute(exp)
        assert result.status == ExecutionStatus.INCONCLUSIVE
        assert result.finding is None


class TestIntegration:
    def test_scheduler_feeds_pipeline(self):
        engine = _make_engine()
        scheduler = ExperimentScheduler()
        pipeline = ExecutionPipeline(engine, tool_runner=SuccessToolRunner())

        for i, tid in enumerate(["input_validation.sqli", "xss.reflected"]):
            exp = {"test_id": tid, "test_strategy": "nuclei", "target_endpoint_id": f"ep_{i}",
                   "id": f"exp_{i}", "created_at": datetime(2026, 1, 1)}
            scheduler.queue(type("E", (), {**exp, "confidence": 0.5 + i * 0.2})(), priority=0.5 + i * 0.2)

        results = []
        while not scheduler.is_empty():
            exp = scheduler.next()
            result = pipeline.execute(exp)
            results.append(result)

        assert len(results) == 2
        assert all(r.evidence is not None for r in results)
