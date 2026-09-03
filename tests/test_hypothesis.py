import pytest
import uuid
from unittest.mock import MagicMock, patch
from core.hypothesis.hypothesis_generator import HypothesisGenerator
from core.hypothesis.hypothesis_ranker import HypothesisRanker, StrategyEffectivenessScorer
from core.coverage.coverage_engine import CoverageEngine
from core.coverage.catalog import SecurityTestCatalog
from core.coverage.test_definition import SecurityTestDefinition, ApplicabilityRule
from core.attack_surface.graph import AttackSurfaceGraph
from core.domain.endpoint import Endpoint
from core.domain.parameter import Parameter, ParameterType
from core.domain.coverage import TestState
from core.llm.schemas import LLMResponse


def _make_endpoint(idx: int, has_params: bool = True, auth: bool = False) -> Endpoint:
    params = []
    if has_params:
        params.append(Parameter(
            name=f"param_{idx}",
            parameter_type=ParameterType.QUERY,
            inferred_data_type="string",
            is_required=True,
        ))
    return Endpoint(
        endpoint_id=f"ep_{idx}",
        url=f"https://example.com/api/resource{idx}",
        path=f"/api/resource{idx}",
        method_set=["GET", "POST"],
        parameters=params,
        auth_required=auth,
    )


def _make_catalog_with_tests(test_ids):
    catalog = SecurityTestCatalog()
    extra_tests = {
        "input_validation.cmdi": SecurityTestDefinition(
            test_id="input_validation.cmdi",
            category="command_injection",
            description="Command injection test",
            prerequisites=[],
            applicability_rules=[ApplicabilityRule(condition="endpoint_accepts_input")],
            execution_strategies=["nuclei_cmdi"],
            required_evidence=["command_output"],
            oracle="cmdi_oracle",
            risk_level="critical",
        ),
        "csrf.basic": SecurityTestDefinition(
            test_id="csrf.basic",
            category="csrf",
            description="CSRF test",
            prerequisites=[],
            applicability_rules=[],
            execution_strategies=["csrf_check"],
            required_evidence=["csrf_token_missing"],
            oracle="csrf_oracle",
            risk_level="medium",
        ),
        "ssrf.basic": SecurityTestDefinition(
            test_id="ssrf.basic",
            category="ssrf",
            description="SSRF test",
            prerequisites=[],
            applicability_rules=[ApplicabilityRule(condition="endpoint_accepts_input")],
            execution_strategies=["ssrf_probe"],
            required_evidence=["internal_response"],
            oracle="ssrf_oracle",
            risk_level="high",
        ),
        "jwt.manipulation": SecurityTestDefinition(
            test_id="jwt.manipulation",
            category="jwt",
            description="JWT manipulation",
            prerequisites=[],
            applicability_rules=[],
            execution_strategies=["jwt_forge"],
            required_evidence=["forged_jwt_accepted"],
            oracle="jwt_oracle",
            risk_level="high",
        ),
        "path_traversal.basic": SecurityTestDefinition(
            test_id="path_traversal.basic",
            category="path_traversal",
            description="Path traversal test",
            prerequisites=[],
            applicability_rules=[ApplicabilityRule(condition="endpoint_accepts_input")],
            execution_strategies=["path_traversal_fuzz"],
            required_evidence=["file_content_leaked"],
            oracle="path_traversal_oracle",
            risk_level="high",
        ),
        "cors.misconfiguration": SecurityTestDefinition(
            test_id="cors.misconfiguration",
            category="cors",
            description="CORS misconfiguration",
            prerequisites=[],
            applicability_rules=[],
            execution_strategies=["cors_check"],
            required_evidence=["wildcard_origin"],
            oracle="cors_oracle",
            risk_level="medium",
        ),
        "secrets.exposure": SecurityTestDefinition(
            test_id="secrets.exposure",
            category="secrets",
            description="Secrets exposure",
            prerequisites=[],
            applicability_rules=[],
            execution_strategies=["secret_scan"],
            required_evidence=["api_key_in_response"],
            oracle="secrets_oracle",
            risk_level="high",
        ),
        "xxe.basic": SecurityTestDefinition(
            test_id="xxe.basic",
            category="xxe",
            description="XXE injection",
            prerequisites=[],
            applicability_rules=[ApplicabilityRule(condition="endpoint_accepts_input")],
            execution_strategies=["xxe_payload"],
            required_evidence=["external_entity_loaded"],
            oracle="xxe_oracle",
            risk_level="critical",
        ),
    }
    for tid in test_ids:
        if tid not in catalog.tests and tid in extra_tests:
            catalog.tests[tid] = extra_tests[tid]
    return catalog


def _build_surface(endpoints):
    surface = AttackSurfaceGraph()
    for ep in endpoints:
        surface.add_endpoint(ep)
    return surface


class TestHypothesisGenerator:
    def test_generate_from_coverage_gaps(self):
        test_ids = [
            "authentication.basic", "authorization.idor",
            "input_validation.sqli", "xss.reflected",
            "input_validation.cmdi", "csrf.basic",
            "ssrf.basic", "jwt.manipulation",
            "path_traversal.basic", "cors.misconfiguration",
            "secrets.exposure", "xxe.basic",
        ]
        catalog = _make_catalog_with_tests(test_ids)
        endpoints = [_make_endpoint(i) for i in range(4)]
        surface = _build_surface(endpoints)

        engine = CoverageEngine(catalog)
        engine.initialize(endpoints)

        gaps = engine.get_coverage_gaps()
        assert len(gaps) >= len(test_ids) - 2  # some may be NOT_APPLICABLE

        generator = HypothesisGenerator(engine, surface)
        hypotheses = generator.generate(gaps)

        assert len(hypotheses) > 0
        for h in hypotheses:
            assert h.test_id in test_ids
            assert h.endpoint_id is not None
            assert h.status == "PROPOSED"
            assert h.rationale
            assert h.title

    def test_all_hypotheses_map_to_gaps(self):
        test_ids = [
            "authentication.basic", "authorization.idor",
            "input_validation.sqli", "xss.reflected",
            "input_validation.cmdi", "csrf.basic",
            "ssrf.basic", "jwt.manipulation",
            "path_traversal.basic", "cors.misconfiguration",
            "secrets.exposure", "xxe.basic",
        ]
        catalog = _make_catalog_with_tests(test_ids)
        endpoints = [_make_endpoint(i) for i in range(4)]
        surface = _build_surface(endpoints)

        engine = CoverageEngine(catalog)
        engine.initialize(endpoints)
        gaps = engine.get_coverage_gaps()

        generator = HypothesisGenerator(engine, surface)
        hypotheses = generator.generate(gaps)

        for h in hypotheses:
            assert h.test_id in gaps, f"Hypothesis test_id {h.test_id} not in coverage gaps"

    def test_hypothesis_fields(self):
        catalog = _make_catalog_with_tests(["input_validation.sqli"])
        endpoints = [_make_endpoint(0)]
        surface = _build_surface(endpoints)

        engine = CoverageEngine(catalog)
        engine.initialize(endpoints)
        gaps = engine.get_coverage_gaps()

        generator = HypothesisGenerator(engine, surface)
        hypotheses = generator.generate(gaps)

        sqli = [h for h in hypotheses if h.test_id == "input_validation.sqli"]
        assert len(sqli) > 0
        h = sqli[0]
        assert h.id  # UUID
        assert h.test_id == "input_validation.sqli"
        assert h.endpoint_id == "ep_0"
        assert "sql_injection" in h.title
        assert len(h.expected_signals) > 0


class TestHypothesisRanker:
    def _mock_router(self, hypotheses):
        router = MagicMock()
        candidates_resp = []
        for i, h in enumerate(hypotheses):
            score = max(0.0, 1.0 - (i * 0.1))
            candidates_resp.append({"id": h.id, "score": score, "justification": "test"})
        router.route_task.return_value = LLMResponse(
            reasoning_trace="Ranked by likelihood",
            structured_data={"candidates": candidates_resp},
            raw_response="{}",
        )
        return router

    def test_rank_by_priority_descending(self):
        catalog = _make_catalog_with_tests([
            "input_validation.sqli", "xss.reflected",
            "csrf.basic", "ssrf.basic",
            "input_validation.cmdi", "jwt.manipulation",
            "path_traversal.basic", "cors.misconfiguration",
            "secrets.exposure", "xxe.basic",
            "authentication.basic", "authorization.idor",
        ])
        endpoints = [_make_endpoint(i) for i in range(3)]
        surface = _build_surface(endpoints)

        engine = CoverageEngine(catalog)
        engine.initialize(endpoints)
        gaps = engine.get_coverage_gaps()

        generator = HypothesisGenerator(engine, surface)
        hypotheses = generator.generate(gaps)
        assert len(hypotheses) >= 10

        router = self._mock_router(hypotheses)
        ranker = HypothesisRanker(router)
        ranked = ranker.rank(hypotheses)

        for i in range(len(ranked) - 1):
            assert ranked[i].confidence >= ranked[i + 1].confidence

    def test_rank_calls_llm(self):
        catalog = _make_catalog_with_tests(["input_validation.sqli"])
        endpoints = [_make_endpoint(0)]
        surface = _build_surface(endpoints)

        engine = CoverageEngine(catalog)
        engine.initialize(endpoints)
        gaps = engine.get_coverage_gaps()

        generator = HypothesisGenerator(engine, surface)
        hypotheses = generator.generate(gaps)

        router = self._mock_router(hypotheses)
        ranker = HypothesisRanker(router)
        ranker.rank(hypotheses)

        router.route_task.assert_called_once()
        call_args = router.route_task.call_args
        assert call_args[0][0] == "hypothesis_ranking"

    def test_rank_fallback_on_llm_failure(self):
        catalog = _make_catalog_with_tests(["input_validation.sqli", "xss.reflected"])
        endpoints = [_make_endpoint(0)]
        surface = _build_surface(endpoints)

        engine = CoverageEngine(catalog)
        engine.initialize(endpoints)
        gaps = engine.get_coverage_gaps()

        generator = HypothesisGenerator(engine, surface)
        hypotheses = generator.generate(gaps)

        router = MagicMock()
        router.route_task.side_effect = Exception("LLM down")

        ranker = HypothesisRanker(router)
        ranked = ranker.rank(hypotheses)

        assert len(ranked) == len(hypotheses)
        for h in ranked:
            assert 0.0 <= h.confidence <= 1.0


class TestStrategyEffectivenessScorer:
    def test_known_success_higher_score(self):
        scorer = StrategyEffectivenessScorer()

        high_score = scorer.score("sqli_fuzz", "api", historical_success=0.8, recent_success=0.9)
        low_score = scorer.score("sqli_fuzz", "api", historical_success=0.1, recent_success=0.2)

        assert high_score > low_score

    def test_recent_weighted_higher(self):
        scorer = StrategyEffectivenessScorer()

        recent_high = scorer.score("xss", "web", historical_success=0.2, recent_success=0.9)
        historical_high = scorer.score("xss", "web", historical_success=0.9, recent_success=0.2)

        assert recent_high > historical_high

    def test_score_clamped_0_1(self):
        scorer = StrategyEffectivenessScorer()

        assert scorer.score("x", "", 0.0, 0.0) == 0.0
        assert scorer.score("x", "", 1.0, 1.0) == 1.0
        assert 0.0 <= scorer.score("x", "", 0.5, 0.5) <= 1.0

    def test_score_via_ranker(self):
        router = MagicMock()
        ranker = HypothesisRanker(router)

        score = ranker.score_strategy("sqli_fuzz", "api", historical_success=0.7, recent_success=0.9)
        assert 0.0 <= score <= 1.0
        assert score > 0.5
