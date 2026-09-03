import pytest
from core.learning.experience_learner import ExperienceLearner, InMemoryStorage
from core.decisions.decision_guard import DecisionGuardV2
from core.coverage.coverage_engine import CoverageEngine
from core.coverage.catalog import SecurityTestCatalog
from core.coverage.test_definition import SecurityTestDefinition, ApplicabilityRule
from core.domain.endpoint import Endpoint
from core.domain.parameter import Parameter, ParameterType
from core.domain.coverage import TestState
from core.tools.capability_mapper import CapabilityMapper


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
        execution_strategies=["nuclei_cmdi", "commix"],
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
    return engine, catalog


class TestExperienceLearner:
    def test_record_and_detect_failure_pattern(self):
        learner = ExperienceLearner()
        learner.record_failure("sqlmap", "input_validation.sqli", "read-only endpoint")
        learner.record_failure("sqlmap", "input_validation.sqli", "read-only endpoint")

        patterns = learner.detect_patterns()
        assert len(patterns) == 1
        assert "sqlmap" in patterns[0]
        assert "input_validation.sqli" in patterns[0]
        assert "read-only endpoint" in patterns[0]

    def test_no_pattern_below_threshold(self):
        learner = ExperienceLearner()
        learner.record_failure("sqlmap", "input_validation.sqli", "timeout")

        patterns = learner.detect_patterns()
        assert len(patterns) == 0

    def test_multiple_patterns(self):
        learner = ExperienceLearner()
        learner.record_failure("sqlmap", "input_validation.sqli", "timeout")
        learner.record_failure("sqlmap", "input_validation.sqli", "timeout")
        learner.record_failure("dalfox", "xss.reflected", "waf blocked")
        learner.record_failure("dalfox", "xss.reflected", "waf blocked")

        patterns = learner.detect_patterns()
        assert len(patterns) == 2

    def test_success_rate_tracking(self):
        learner = ExperienceLearner()
        for _ in range(8):
            learner.record_success("nuclei", "input_validation.sqli", "CONFIRMED")
        for _ in range(2):
            learner.record_failure("nuclei", "input_validation.sqli", "timeout")

        rate = learner.get_success_rate("nuclei", "input_validation.sqli")
        assert rate == 0.8

    def test_preferred_strategy_high_success(self):
        learner = ExperienceLearner()
        for _ in range(9):
            learner.record_success("nuclei", "input_validation.sqli", "CONFIRMED")
        learner.record_failure("nuclei", "input_validation.sqli", "timeout")

        for _ in range(3):
            learner.record_success("sqlmap", "input_validation.sqli", "CONFIRMED")
        for _ in range(7):
            learner.record_failure("sqlmap", "input_validation.sqli", "timeout")

        preferred = learner.get_preferred_strategy(
            "input_validation.sqli", ["nuclei", "sqlmap"]
        )
        assert preferred == "nuclei"

    def test_persistence(self):
        storage = InMemoryStorage()
        learner1 = ExperienceLearner(storage)
        learner1.record_failure("sqlmap", "sqli", "timeout")
        learner1.record_success("nuclei", "sqli", "CONFIRMED")

        learner2 = ExperienceLearner(storage)
        assert learner2.get_failure_count("sqlmap", "sqli") == 1
        assert learner2.get_success_rate("nuclei", "sqli") == 1.0

    def test_failure_count(self):
        learner = ExperienceLearner()
        assert learner.get_failure_count("sqlmap", "sqli") == 0
        learner.record_failure("sqlmap", "sqli", "err")
        learner.record_failure("sqlmap", "sqli", "err")
        assert learner.get_failure_count("sqlmap", "sqli") == 2


class TestDecisionGuardV2:
    def test_rejects_repeated_failure_suggests_alternative(self):
        engine, _ = _make_engine()
        learner = ExperienceLearner()
        learner.record_failure("sqlmap", "input_validation.sqli", "timeout")
        learner.record_failure("sqlmap", "input_validation.sqli", "timeout")

        mapper = CapabilityMapper()
        guard = DecisionGuardV2(engine, learner, mapper)

        experiment = {
            "test_id": "input_validation.sqli",
            "test_strategy": "sqlmap",
            "target_endpoint_id": "ep_0",
        }
        valid, reason, alt = guard.validate(experiment)
        assert not valid
        assert "sqlmap" in reason
        assert "failed" in reason
        assert alt is not None
        assert alt in ("nuclei_sqli_fuzz", "dalfox", "nuclei")

    def test_accepts_valid_experiment(self):
        engine, _ = _make_engine()
        learner = ExperienceLearner()
        guard = DecisionGuardV2(engine, learner)

        experiment = {
            "test_id": "input_validation.sqli",
            "test_strategy": "nuclei",
            "target_endpoint_id": "ep_0",
        }
        valid, reason, alt = guard.validate(experiment)
        assert valid
        assert reason == "accepted"

    def test_rejects_terminal_test(self):
        engine, _ = _make_engine()
        engine.mark_tested("input_validation.sqli", None, TestState.CONFIRMED)

        learner = ExperienceLearner()
        guard = DecisionGuardV2(engine, learner)

        experiment = {
            "test_id": "input_validation.sqli",
            "test_strategy": "nuclei",
            "target_endpoint_id": "ep_0",
        }
        valid, reason, alt = guard.validate(experiment)
        assert not valid
        assert "terminal" in reason

    def test_rejects_duplicate_queued(self):
        engine, _ = _make_engine()
        learner = ExperienceLearner()
        guard = DecisionGuardV2(engine, learner)

        experiment = {
            "test_id": "input_validation.sqli",
            "test_strategy": "nuclei",
            "target_endpoint_id": "ep_0",
        }
        valid1, _, _ = guard.validate(experiment)
        assert valid1

        valid2, reason, _ = guard.validate(experiment)
        assert not valid2
        assert "Duplicate" in reason

    def test_rejects_missing_test_definition(self):
        engine, _ = _make_engine()
        learner = ExperienceLearner()
        guard = DecisionGuardV2(engine, learner)

        experiment = {
            "test_id": "nonexistent.test",
            "test_strategy": "nuclei",
            "target_endpoint_id": "ep_0",
        }
        valid, reason, _ = guard.validate(experiment)
        assert not valid
        assert "No test definition" in reason

    def test_rejects_unavailable_tool(self):
        engine, _ = _make_engine()
        learner = ExperienceLearner()
        guard = DecisionGuardV2(engine, learner, available_tools={"nmap", "nuclei"})

        experiment = {
            "test_id": "input_validation.sqli",
            "test_strategy": "sqlmap",
            "target_endpoint_id": "ep_0",
        }
        valid, reason, alt = guard.validate(experiment)
        assert not valid
        assert "not available" in reason
        assert alt is not None

    def test_rejects_time_budget_exceeded(self):
        engine, _ = _make_engine()
        learner = ExperienceLearner()
        guard = DecisionGuardV2(engine, learner, time_budget_seconds=100)
        guard.time_spent_seconds = 90

        experiment = {
            "test_id": "input_validation.sqli",
            "test_strategy": "nuclei",
            "target_endpoint_id": "ep_0",
            "estimated_seconds": 60,
        }
        valid, reason, _ = guard.validate(experiment)
        assert not valid
        assert "budget" in reason.lower()

    def test_skip_loop_prevention(self):
        engine, _ = _make_engine()
        learner = ExperienceLearner()
        guard = DecisionGuardV2(engine, learner)

        experiment = {
            "test_id": "input_validation.sqli",
            "test_strategy": "nuclei",
            "target_endpoint_id": "ep_0",
        }
        guard.mark_failed(experiment)

        valid, reason, _ = guard.validate(experiment)
        assert not valid
        assert "blocked" in reason.lower()

    def test_alternative_from_execution_strategies(self):
        engine, _ = _make_engine()
        learner = ExperienceLearner()
        learner.record_failure("nuclei_cmdi", "input_validation.cmdi", "timeout")
        learner.record_failure("nuclei_cmdi", "input_validation.cmdi", "timeout")

        guard = DecisionGuardV2(engine, learner)
        experiment = {
            "test_id": "input_validation.cmdi",
            "test_strategy": "nuclei_cmdi",
            "target_endpoint_id": "ep_0",
        }
        valid, reason, alt = guard.validate(experiment)
        assert not valid
        assert alt == "commix"

    def test_works_with_domain_objects(self):
        from core.domain.experiment_v2 import SecurityExperiment

        engine, _ = _make_engine()
        learner = ExperienceLearner()
        guard = DecisionGuardV2(engine, learner)

        exp = SecurityExperiment(
            hypothesis_id="h1",
            test_strategy="nuclei_sqli_fuzz",
            target_endpoint_id="ep_0",
        )
        # SecurityExperiment doesn't have test_id — defaults to ""
        # which isn't in catalog, so should be rejected
        valid, reason, _ = guard.validate(exp)
        assert not valid
