import pytest
from core.convergence.convergence_engine import ConvergenceEngine, ConvergenceState, MINIMUM_COVERAGE_PCT
from core.convergence.completion_validator import CompletionValidator
from core.coverage.coverage_engine import CoverageEngine
from core.coverage.catalog import SecurityTestCatalog
from core.coverage.test_definition import SecurityTestDefinition, ApplicabilityRule
from core.domain.endpoint import Endpoint
from core.domain.parameter import Parameter, ParameterType
from core.domain.coverage import TestState


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


def _make_catalog_12():
    catalog = SecurityTestCatalog()
    extras = {
        "input_validation.cmdi": ("command_injection", "critical"),
        "csrf.basic": ("csrf", "medium"),
        "ssrf.basic": ("ssrf", "high"),
        "jwt.manipulation": ("jwt", "high"),
        "path_traversal.basic": ("path_traversal", "high"),
        "cors.misconfiguration": ("cors", "medium"),
        "secrets.exposure": ("secrets", "high"),
        "xxe.basic": ("xxe", "critical"),
    }
    for tid, (cat, risk) in extras.items():
        catalog.tests[tid] = SecurityTestDefinition(
            test_id=tid,
            category=cat,
            description=f"{cat} test",
            prerequisites=[],
            applicability_rules=[],
            execution_strategies=[f"{cat}_strategy"],
            required_evidence=[f"{cat}_evidence"],
            oracle=f"{cat}_oracle",
            risk_level=risk,
        )
    return catalog


def _setup_engine_with_gaps():
    catalog = _make_catalog_12()
    endpoints = [_make_endpoint(i) for i in range(3)]
    engine = CoverageEngine(catalog)
    engine.initialize(endpoints)
    return engine, catalog


class TestConvergenceEngine:
    def test_coverage_85_with_gaps_not_converged(self):
        engine, catalog = _setup_engine_with_gaps()
        all_tests = list(catalog.tests.keys())

        # Mark 11 of 12 as terminal (91.6%) — still has 1 gap so not converged
        for tid in all_tests[:11]:
            engine.mark_tested(tid, None, TestState.REJECTED)

        conv = ConvergenceEngine(engine)
        score = conv.calculate_convergence()
        assert score >= 85.0

        gaps = conv.get_remaining_gaps()
        assert len(gaps) == 1
        assert not conv.is_converged()

    def test_all_gaps_blocked_converged(self):
        engine, catalog = _setup_engine_with_gaps()
        all_tests = list(catalog.tests.keys())

        for tid in all_tests:
            engine.mark_tested(tid, None, TestState.BLOCKED)

        conv = ConvergenceEngine(engine)
        assert conv.calculate_convergence() == 100.0
        assert conv.is_converged()
        assert conv.get_state() == ConvergenceState.CONVERGED

    def test_all_confirmed_converged(self):
        engine, catalog = _setup_engine_with_gaps()
        for tid in catalog.tests:
            engine.mark_tested(tid, None, TestState.CONFIRMED)

        conv = ConvergenceEngine(engine)
        assert conv.is_converged()

    def test_mixed_terminal_converged(self):
        engine, catalog = _setup_engine_with_gaps()
        all_tests = list(catalog.tests.keys())

        for i, tid in enumerate(all_tests):
            if i % 3 == 0:
                engine.mark_tested(tid, None, TestState.CONFIRMED)
            elif i % 3 == 1:
                engine.mark_tested(tid, None, TestState.REJECTED)
            else:
                engine.mark_tested(tid, None, TestState.BLOCKED)

        conv = ConvergenceEngine(engine)
        assert conv.is_converged()

    def test_stall_detection(self):
        engine, catalog = _setup_engine_with_gaps()
        all_tests = list(catalog.tests.keys())

        # Mark 11 of 12 as terminal (91.6%) — above 85% but 1 gap remains
        for tid in all_tests[:11]:
            engine.mark_tested(tid, None, TestState.REJECTED)

        conv = ConvergenceEngine(engine)
        score = conv.calculate_convergence()
        assert score >= 85.0

        assert conv.get_state() == ConvergenceState.CONVERGING

        conv.force_stall_for_testing()
        assert conv.get_state() == ConvergenceState.STALLED

    def test_zero_applicable_returns_100(self):
        catalog = SecurityTestCatalog()
        catalog.tests.clear()
        engine = CoverageEngine(catalog)
        engine.initialize([])

        conv = ConvergenceEngine(engine)
        assert conv.calculate_convergence() == 100.0

    def test_get_remaining_gaps_returns_test_defs(self):
        engine, catalog = _setup_engine_with_gaps()
        conv = ConvergenceEngine(engine)

        gaps = conv.get_remaining_gaps()
        assert len(gaps) > 0
        for g in gaps:
            assert isinstance(g, SecurityTestDefinition)
            assert g.test_id in catalog.tests

    def test_metrics(self):
        engine, catalog = _setup_engine_with_gaps()
        all_tests = list(catalog.tests.keys())

        engine.mark_tested(all_tests[0], None, TestState.CONFIRMED)
        engine.mark_tested(all_tests[1], None, TestState.REJECTED)
        engine.mark_tested(all_tests[2], None, TestState.BLOCKED)

        conv = ConvergenceEngine(engine)
        m = conv.get_metrics()
        assert m.confirmed_count == 1
        assert m.rejected_count == 1
        assert m.blocked_count == 1
        assert m.gap_count > 0
        assert m.convergence_score > 0


class TestCompletionValidator:
    def test_incomplete_coverage(self):
        engine, _ = _setup_engine_with_gaps()
        conv = ConvergenceEngine(engine)
        validator = CompletionValidator(engine, conv)

        valid, reasons = validator.validate_completion()
        assert not valid
        assert any("Coverage" in r or "gaps" in r for r in reasons)

    def test_complete_after_all_tested(self):
        engine, catalog = _setup_engine_with_gaps()
        for tid in catalog.tests:
            engine.mark_tested(tid, None, TestState.REJECTED)

        conv = ConvergenceEngine(engine)
        validator = CompletionValidator(engine, conv)

        valid, reasons = validator.validate_completion()
        assert valid
        assert reasons == []

    def test_blocked_tests_reported(self):
        engine, catalog = _setup_engine_with_gaps()
        all_tests = list(catalog.tests.keys())

        for tid in all_tests:
            engine.mark_tested(tid, None, TestState.BLOCKED)

        conv = ConvergenceEngine(engine)
        validator = CompletionValidator(engine, conv)

        valid, reasons = validator.validate_completion()
        assert not valid
        assert any("blocked" in r for r in reasons)

    def test_stalled_reported(self):
        engine, catalog = _setup_engine_with_gaps()
        all_tests = list(catalog.tests.keys())

        # Mark 11 of 12 as terminal — above 85% but 1 gap remains
        for tid in all_tests[:11]:
            engine.mark_tested(tid, None, TestState.REJECTED)

        conv = ConvergenceEngine(engine)
        conv.force_stall_for_testing()

        validator = CompletionValidator(engine, conv)
        valid, reasons = validator.validate_completion()
        assert not valid
        assert any("stalled" in r.lower() for r in reasons)
