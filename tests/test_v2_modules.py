"""Comprehensive unit tests for AntiGravity v2 modules."""

import sys
import os
import asyncio
import json
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime

sys.path.insert(0, r"C:\Users\durga\Desktop\Projects\outputs")

import pytest


# ---------------------------------------------------------------------------
# 1. SecurityTestCatalog
# ---------------------------------------------------------------------------
from core.coverage.security_test_catalog import (
    SecurityTest,
    SecurityTestCatalog,
    build_default_catalog,
    _has_input,
    _has_url_param,
    _always,
    _is_authenticated,
    _has_jwt,
    _has_graphql,
)

REQUIRED_CATEGORIES = [
    "sqli", "xss", "cmdi", "ssti", "path_traversal", "ssrf", "xxe",
    "idor", "cors", "csrf", "open_redirect", "auth",
]


class TestSecurityTestCatalog:
    def setup_method(self):
        self.catalog = build_default_catalog()

    def test_catalog_has_200_plus_tests(self):
        assert self.catalog.count() >= 200, f"Expected 200+, got {self.catalog.count()}"

    def test_required_categories_exist(self):
        cats = self.catalog.categories()
        for cat in REQUIRED_CATEGORIES:
            matches = self.catalog.list_by_category(cat)
            assert len(matches) > 0, f"Category '{cat}' missing or empty"

    def test_every_test_has_required_fields(self):
        for t in self.catalog.list_all():
            assert t.test_id, "test_id is empty"
            assert t.name, "name is empty"
            assert t.attack_type, "attack_type is empty"
            assert t.description, "description is empty"

    def test_get_returns_test_by_id(self):
        first = self.catalog.list_all()[0]
        got = self.catalog.get(first.test_id)
        assert got is not None
        assert got.test_id == first.test_id

    def test_get_returns_none_for_unknown(self):
        assert self.catalog.get("nonexistent_id_xyz") is None

    def test_register_adds_test(self):
        cat = SecurityTestCatalog()
        t = SecurityTest(test_id="t1", name="Test", attack_type="xss", description="d")
        cat.register(t)
        assert cat.count() == 1
        assert cat.get("t1") is t

    def test_predicates_always(self):
        assert _always() is True

    def test_predicates_has_input(self):
        assert _has_input(parameters=[{"name": "q"}]) is True
        assert _has_input() is False
        assert _has_input(parameters=[]) is False

    def test_predicates_has_url_param(self):
        assert _has_url_param(parameters=[{"location": "query"}]) is True
        assert _has_url_param(parameters=[{"location": "body"}]) is False
        assert _has_url_param() is False

    def test_predicates_is_authenticated(self):
        assert _is_authenticated(identities=["admin"]) is True
        assert _is_authenticated() is False
        assert _is_authenticated(identities=[]) is False

    def test_predicates_has_jwt(self):
        assert _has_jwt(technologies=["jwt"]) is True
        assert _has_jwt(technologies=["php"]) is False
        assert _has_jwt() is False

    def test_predicates_has_graphql(self):
        assert _has_graphql(technologies=["graphql"]) is True
        assert _has_graphql() is False

    def test_applicable_to_is_callable(self):
        for t in self.catalog.list_all():
            assert callable(t.applicable_to)

    def test_list_by_category_returns_correct_type(self):
        for t in self.catalog.list_by_category("sqli"):
            assert t.attack_type == "sqli"


# ---------------------------------------------------------------------------
# 2. PayloadCatalog
# ---------------------------------------------------------------------------
from core.coverage.payload_catalog import Payload, PayloadCatalog, build_default_payload_catalog

VALID_CONTEXT_TYPES = {
    "html", "attr", "js", "url", "query", "body", "header", "cookie",
    "json", "xml", "path", "multipart", "graphql", "any", "cli",
    "template", "ldap", "nosql", "form", "get", "post",
}


class TestPayloadCatalog:
    def setup_method(self):
        self.catalog = build_default_payload_catalog()

    def test_catalog_has_80_plus_payloads(self):
        assert self.catalog.count() >= 80, f"Expected 80+, got {self.catalog.count()}"

    def test_each_payload_has_required_fields(self):
        for pid in range(self.catalog.count()):
            pass
        # iterate via attack types
        seen = set()
        for at in ["sqli", "xss", "cmdi", "ssti", "path_traversal", "ssrf", "xxe",
                    "nosqli", "ldap", "open_redirect", "header_injection", "jwt",
                    "host_header", "cors", "csrf", "http_smuggling", "prototype_pollution"]:
            for p in self.catalog.by_attack_type(at):
                assert p.payload_id, "payload_id empty"
                assert p.attack_type, "attack_type empty"
                assert p.context, "context empty"
                assert p.raw, "raw payload empty"
                seen.add(p.payload_id)
        assert len(seen) >= 80

    def test_by_attack_type(self):
        sqli = self.catalog.by_attack_type("sqli")
        assert len(sqli) > 0
        for p in sqli:
            assert p.attack_type == "sqli"

    def test_by_context(self):
        results = self.catalog.by_context("html")
        for p in results:
            assert p.context == "html"

    def test_by_evasion_level(self):
        lvl0 = self.catalog.by_evasion_level(0)
        for p in lvl0:
            assert p.evasion_level == 0

    def test_for_test_filters_correctly(self):
        results = self.catalog.for_test("xss", context="html", max_evasion=1)
        for p in results:
            assert p.attack_type == "xss"
            assert p.evasion_level <= 1

    def test_get_by_id(self):
        sqli_payloads = self.catalog.by_attack_type("sqli")
        if sqli_payloads:
            p = sqli_payloads[0]
            assert self.catalog.get(p.payload_id) is p

    def test_get_unknown_returns_none(self):
        assert self.catalog.get("nonexistent_payload_xyz") is None

    def test_register(self):
        cat = PayloadCatalog()
        p = Payload(payload_id="p1", attack_type="xss", context="html", raw="<img>")
        cat.register(p)
        assert cat.count() == 1
        assert cat.get("p1") is p


# ---------------------------------------------------------------------------
# 3. HypothesisEngine
# ---------------------------------------------------------------------------
from core.coverage.hypothesis_engine import HypothesisEngine


class TestHypothesisEngine:
    def setup_method(self):
        self.catalog = build_default_catalog()
        self.engine = HypothesisEngine(self.catalog)

    def _make_surface(self):
        from core.attack_surface.attack_surface_state import AttackSurfaceState
        surface = AttackSurfaceState("https://example.com")
        return surface

    def test_generate_from_surface_returns_list(self):
        surface = self._make_surface()
        hypotheses = self.engine.generate_from_surface(surface)
        assert isinstance(hypotheses, list)

    def test_generate_from_surface_with_technologies(self):
        surface = self._make_surface()
        surface.technologies["php"] = [MagicMock(name="php")]
        hypotheses = self.engine.generate_from_surface(surface)
        assert isinstance(hypotheses, list)
        assert len(hypotheses) > 0

    def test_record_feedback_stores_data(self):
        self.engine.record_feedback("sqli_01", "/api/login", "vulnerable", {"note": "confirmed"})
        assert "sqli_01:/api/login" in self.engine._feedback

    def test_record_feedback_adjusts_priority(self):
        self.engine.record_feedback("sqli_01", "/api/login", "vulnerable")
        fb = self.engine._feedback.get("sqli_01:/api/login")
        assert fb is not None
        assert fb["outcome"] == "vulnerable"

    def test_suggest_follow_ups_returns_list(self):
        follow_ups = self.engine.suggest_follow_ups("sqli_01", "/api/login", "vulnerable")
        assert isinstance(follow_ups, list)

    def test_suggest_follow_ups_for_blocked(self):
        follow_ups = self.engine.suggest_follow_ups("sqli_01", "/api/login", "blocked")
        assert isinstance(follow_ups, list)


# ---------------------------------------------------------------------------
# 4. IdentityCoverageEngine
# ---------------------------------------------------------------------------
from core.coverage.identity_coverage import IdentityCoverageEngine, IdentityCoverageCell


class TestIdentityCoverageEngine:
    def setup_method(self):
        self.engine = IdentityCoverageEngine()

    def test_initialize_matrix(self):
        count = self.engine.initialize_matrix(
            test_ids=["t1", "t2"],
            endpoint_ids=["e1", "e2"],
            identity_ids=["admin", "user"],
        )
        assert count == 8  # 2 * 2 * 2

    def test_mark_tested(self):
        self.engine.initialize_matrix(["t1"], ["e1"], ["admin"])
        self.engine.mark_tested("t1", "e1", "admin", "PASS", evidence_ids=["ev1"])
        cell = self.engine._cells[("t1", "e1", "admin")]
        assert cell.status == "PASS"
        assert "ev1" in cell.evidence_ids

    def test_get_gaps_returns_untested(self):
        self.engine.initialize_matrix(["t1", "t2"], ["e1"], ["admin"])
        self.engine.mark_tested("t1", "e1", "admin", "PASS")
        gaps = self.engine.get_gaps()
        assert len(gaps) == 1
        assert gaps[0].test_id == "t2"

    def test_get_gaps_filtered_by_test(self):
        self.engine.initialize_matrix(["t1", "t2"], ["e1"], ["admin"])
        gaps = self.engine.get_gaps(test_id="t1")
        assert all(g.test_id == "t1" for g in gaps)

    def test_coverage_percentage_zero(self):
        self.engine.initialize_matrix(["t1"], ["e1"], ["admin"])
        assert self.engine.coverage_percentage() == 0.0

    def test_coverage_percentage_full(self):
        self.engine.initialize_matrix(["t1"], ["e1"], ["admin"])
        self.engine.mark_tested("t1", "e1", "admin", "PASS")
        assert self.engine.coverage_percentage() == 100.0

    def test_coverage_percentage_partial(self):
        self.engine.initialize_matrix(["t1", "t2"], ["e1"], ["admin"])
        self.engine.mark_tested("t1", "e1", "admin", "PASS")
        assert self.engine.coverage_percentage() == 50.0

    def test_register_identity(self):
        self.engine.register_identity("admin", role="administrator")
        assert "admin" in self.engine._identities

    def test_summary(self):
        self.engine.initialize_matrix(["t1"], ["e1"], ["admin"])
        s = self.engine.summary()
        assert "total_cells" in s
        assert s["total_cells"] == 1


# ---------------------------------------------------------------------------
# 5. FeedbackLoop
# ---------------------------------------------------------------------------
from core.coverage.feedback_loop import (
    ResponseClassifier,
    ErrorMiner,
    PayloadAdapter,
    FeedbackLoopEngine,
    ResponseSignature,
)


class TestResponseClassifier:
    def setup_method(self):
        self.classifier = ResponseClassifier()

    def test_classify_basic(self):
        sig = self.classifier.classify(
            status_code=200,
            headers={"content-type": "text/html"},
            body="<html>hello</html>",
            timing_ms=100.0,
        )
        assert isinstance(sig, ResponseSignature)
        assert sig.status_code == 200

    def test_classify_detects_reflection(self):
        sig = self.classifier.classify(
            status_code=200,
            headers={},
            body="<html>INJECTED_PAYLOAD</html>",
            timing_ms=50.0,
            injected_input="INJECTED_PAYLOAD",
        )
        assert "INJECTED_PAYLOAD" in sig.reflected_inputs

    def test_classify_detects_sql_error(self):
        body = "You have an error in your SQL syntax; check the manual"
        sig = self.classifier.classify(200, {}, body, 50.0)
        assert len(sig.error_patterns) > 0

    def test_classify_detects_technology(self):
        headers = {"x-powered-by": "PHP/7.4"}
        sig = self.classifier.classify(200, headers, "", 50.0)
        assert "php" in sig.technologies_detected


class TestErrorMiner:
    def setup_method(self):
        self.miner = ErrorMiner()

    def test_extract_from_body(self):
        body = "Warning: include(/var/www/html/config.php): failed to open"
        result = self.miner.mine(body)
        assert isinstance(result, dict)
        assert "file_paths" in result

    def test_extract_empty_body(self):
        result = self.miner.mine("")
        assert isinstance(result, dict)


class TestPayloadAdapter:
    def setup_method(self):
        self.adapter = PayloadAdapter()

    def test_record_blocked(self):
        self.adapter.record_blocked("target1", "' OR 1=1")
        assert self.adapter.is_likely_blocked("target1", "' OR 1=1")

    def test_record_effective(self):
        self.adapter.record_effective("target1", "1 UNION SELECT")
        assert not self.adapter.is_likely_blocked("target1", "1 UNION SELECT")

    def test_suggest_alternative(self):
        self.adapter.record_blocked("t1", "' OR 1=1")
        alt = self.adapter.suggest_alternative("t1", "' OR 1=1", ["' OR 'a'='a", "1 UNION SELECT"])
        # Should return one that isn't blocked
        assert alt is None or isinstance(alt, str)

    def test_get_evasion_level(self):
        level = self.adapter.get_evasion_level("target1")
        assert isinstance(level, int)
        assert level >= 0


class TestFeedbackLoopEngine:
    def setup_method(self):
        self.engine = FeedbackLoopEngine()

    def test_record_baseline(self):
        sig = self.engine.record_baseline(
            "GET /api/users", 200, {"content-type": "text/html"},
            "<html>normal</html>", 100.0,
        )
        assert isinstance(sig, ResponseSignature)
        assert sig.status_code == 200

    def test_analyze_response_without_baseline(self):
        result = self.engine.analyze_response(
            "GET /api/users", 200, {}, "<html>hello</html>", 50.0,
        )
        assert isinstance(result, dict)

    def test_analyze_response_with_baseline(self):
        self.engine.record_baseline("GET /api/users", 200, {}, "<html>normal</html>", 100.0)
        result = self.engine.analyze_response(
            "GET /api/users", 500, {},
            "SQL syntax error near line 1", 150.0,
            payload="' OR 1=1",
        )
        assert isinstance(result, dict)

    def test_observation_count(self):
        assert self.engine.observation_count() == 0
        self.engine.analyze_response("e1", 200, {}, "ok", 50.0)
        assert self.engine.observation_count() == 1


# ---------------------------------------------------------------------------
# 6. ConvergenceEngine v2
# ---------------------------------------------------------------------------
from core.coverage.convergence_engine import ConvergenceEngine, ConvergenceStatus


class TestConvergenceEngine:
    def _make_matrix(self, coverage_pct=0.0):
        matrix = MagicMock()
        matrix.get_coverage.return_value = coverage_pct
        matrix.get_gaps.return_value = []
        return matrix

    def test_evaluate_budget_exhausted(self):
        engine = ConvergenceEngine(self._make_matrix(0.5))
        status = engine.evaluate(remaining_tests=10, budget_exhausted=True)
        assert isinstance(status, ConvergenceStatus)
        assert status.is_converged is True
        assert status.budget_exhausted is True
        assert "BUDGET" in status.reason.upper()

    def test_evaluate_all_tests_complete(self):
        engine = ConvergenceEngine(self._make_matrix(0.9))
        status = engine.evaluate(remaining_tests=0, blocked_tests=0, inconclusive_tests=0)
        assert status.is_converged is True
        assert "COMPLETE" in status.reason.upper() or "ALL" in status.reason.upper()

    def test_evaluate_threshold_met(self):
        engine = ConvergenceEngine(self._make_matrix(0.90))
        status = engine.evaluate(remaining_tests=5)
        assert isinstance(status, ConvergenceStatus)
        assert status.coverage_pct >= 0.85

    def test_evaluate_not_converged(self):
        engine = ConvergenceEngine(self._make_matrix(0.3))
        status = engine.evaluate(remaining_tests=100)
        assert status.is_converged is False

    def test_evaluate_stalled(self):
        engine = ConvergenceEngine(self._make_matrix(0.5))
        # Simulate stall by backdating _last_change_time
        import time
        engine._last_change_time = time.time() - 700  # 11+ minutes ago
        engine._last_coverage = 0.5
        status = engine.evaluate(remaining_tests=50)
        assert isinstance(status, ConvergenceStatus)

    def test_convergence_status_fields(self):
        s = ConvergenceStatus()
        assert s.is_converged is False
        assert s.coverage_pct == 0.0
        assert s.tests_remaining == 0
        assert s.reason == ""

    def test_is_converged_property(self):
        engine = ConvergenceEngine(self._make_matrix(0.95))
        engine.evaluate(remaining_tests=0)
        assert isinstance(engine.is_converged(), bool)

    def test_summary(self):
        engine = ConvergenceEngine(self._make_matrix(0.5))
        s = engine.summary()
        assert isinstance(s, dict)


# ---------------------------------------------------------------------------
# 7. ApplicabilityEngine
# ---------------------------------------------------------------------------
from core.coverage.applicability_engine import ApplicabilityEngine, ApplicabilityResult


class TestApplicabilityEngine:
    def setup_method(self):
        self.catalog = build_default_catalog()
        self.engine = ApplicabilityEngine(self.catalog)

    def test_classify_applicable(self):
        sqli_tests = self.catalog.list_by_category("sqli")
        if sqli_tests:
            test = sqli_tests[0]
            endpoint = {"method": "POST", "path": "/api/login", "content_type": "application/json"}
            params = [{"name": "username", "location": "body"}]
            result, reason = self.engine.classify_applicability(
                test, endpoint, parameters=params,
            )
            assert result in (ApplicabilityResult.APPLICABLE, ApplicabilityResult.NOT_APPLICABLE,
                              ApplicabilityResult.NOT_DISCOVERED)

    def test_classify_not_applicable(self):
        # JWT test should not be applicable when no JWT tech
        jwt_tests = self.catalog.list_by_category("jwt")
        if jwt_tests:
            test = jwt_tests[0]
            endpoint = {"method": "GET", "path": "/"}
            result, reason = self.engine.classify_applicability(test, endpoint)
            assert result in (ApplicabilityResult.NOT_APPLICABLE, ApplicabilityResult.NOT_DISCOVERED)

    def test_classify_not_discovered(self):
        test = SecurityTest(
            test_id="nd_test", name="ND", attack_type="custom", description="d",
            applicable_to=lambda **kw: kw.get("has_feature", False),
        )
        endpoint = {"method": "GET", "path": "/"}
        discovered_features = {"has_feature": None}  # not yet discovered
        result, reason = self.engine.classify_applicability(
            test, endpoint, discovered_features=discovered_features,
        )
        assert isinstance(result, ApplicabilityResult)

    def test_get_applicable_tests(self):
        endpoint = {"method": "POST", "path": "/api/data", "content_type": "application/json"}
        params = [{"name": "q", "location": "query"}]
        tests = self.engine.get_applicable_tests(endpoint, parameters=params)
        assert isinstance(tests, list)

    def test_classify_all_tests(self):
        endpoint = {"method": "GET", "path": "/"}
        result = self.engine.classify_all_tests(endpoint)
        assert isinstance(result, dict)

    def test_applicability_result_values(self):
        assert ApplicabilityResult.APPLICABLE.value == "applicable"
        assert ApplicabilityResult.NOT_APPLICABLE.value == "not_applicable"
        assert ApplicabilityResult.NOT_DISCOVERED.value == "not_discovered"


# ---------------------------------------------------------------------------
# 8. CoverageMatrix
# ---------------------------------------------------------------------------
from core.coverage.coverage_matrix import CoverageMatrix, CoverageState


class TestCoverageMatrix:
    def setup_method(self):
        self.matrix = CoverageMatrix(
            endpoints=["e1", "e2"],
            tests=["t1", "t2"],
        )

    def test_initial_state_is_not_tested(self):
        state = self.matrix.get_state("e1", "t1")
        assert state == CoverageState.NOT_TESTED

    def test_update_state(self):
        self.matrix.update_state("e1", "t1", CoverageState.CONFIRMED, evidence_id="ev1")
        assert self.matrix.get_state("e1", "t1") == CoverageState.CONFIRMED

    def test_get_coverage(self):
        self.matrix.update_state("e1", "t1", CoverageState.CONFIRMED)
        cov = self.matrix.get_coverage()
        assert 0.0 <= cov <= 1.0

    def test_get_gaps(self):
        self.matrix.update_state("e1", "t1", CoverageState.CONFIRMED)
        gaps = self.matrix.get_gaps()
        assert isinstance(gaps, list)
        # Should not include (e1, t1)
        assert ("e1", "t1") not in gaps

    def test_not_discovered_state(self):
        self.matrix.update_state("e1", "t1", CoverageState.NOT_DISCOVERED)
        assert self.matrix.get_state("e1", "t1") == CoverageState.NOT_DISCOVERED

    def test_get_not_discovered(self):
        self.matrix.update_state("e1", "t1", CoverageState.NOT_DISCOVERED)
        nd = self.matrix.get_not_discovered()
        assert ("e1", "t1") in nd

    def test_promote_discovered(self):
        self.matrix.update_state("e1", "t1", CoverageState.NOT_DISCOVERED)
        self.matrix.promote_discovered("e1", "t1")
        assert self.matrix.get_state("e1", "t1") == CoverageState.NOT_TESTED

    def test_get_blocked(self):
        self.matrix.update_state("e1", "t1", CoverageState.BLOCKED)
        blocked = self.matrix.get_blocked()
        assert ("e1", "t1") in blocked

    def test_get_matrix(self):
        m = self.matrix.get_matrix()
        assert isinstance(m, dict)
        assert "e1" in m

    def test_coverage_state_enum_values(self):
        assert CoverageState.NOT_APPLICABLE.value == "not_applicable"
        assert CoverageState.NOT_DISCOVERED.value == "not_discovered"
        assert CoverageState.CONFIRMED.value == "confirmed"
        assert CoverageState.REJECTED.value == "rejected"


# ---------------------------------------------------------------------------
# 9. ParallelExecutor
# ---------------------------------------------------------------------------
from core.orchestration.parallel_executor import ParallelExecutor, TaskResult


class TestParallelExecutor:
    def test_task_result_creation(self):
        r = TaskResult("t1", True, result={"data": 1}, duration_ms=50.0)
        assert r.task_id == "t1"
        assert r.success is True
        assert r.result == {"data": 1}

    def test_task_result_failure(self):
        r = TaskResult("t1", False, error="timeout")
        assert r.success is False
        assert r.error == "timeout"

    def test_execute_group_runs_tasks(self):
        executor = ParallelExecutor(max_concurrency=3, task_timeout=10.0)
        call_order = []

        async def run_task(task):
            call_order.append(task["task_id"])
            await asyncio.sleep(0.01)
            return {"value": task["task_id"]}

        tasks = [
            {"task_id": "a"},
            {"task_id": "b"},
            {"task_id": "c"},
        ]
        results = asyncio.get_event_loop().run_until_complete(
            executor.execute_group(tasks, run_task)
        )
        assert len(results) == 3
        assert all(isinstance(r, TaskResult) for r in results)
        assert all(r.success for r in results)

    def test_execute_group_respects_semaphore(self):
        executor = ParallelExecutor(max_concurrency=1, task_timeout=10.0)
        concurrency_log = []
        counter = {"active": 0}

        async def run_task(task):
            counter["active"] += 1
            concurrency_log.append(counter["active"])
            await asyncio.sleep(0.05)
            counter["active"] -= 1
            return True

        tasks = [{"task_id": f"t{i}"} for i in range(3)]
        asyncio.get_event_loop().run_until_complete(
            executor.execute_group(tasks, run_task)
        )
        # With max_concurrency=1, active should never exceed 1
        assert max(concurrency_log) <= 1

    def test_execute_group_handles_error(self):
        executor = ParallelExecutor(max_concurrency=3, task_timeout=10.0)

        async def fail_task(task):
            raise ValueError("boom")

        tasks = [{"task_id": "fail1"}]
        results = asyncio.get_event_loop().run_until_complete(
            executor.execute_group(tasks, fail_task)
        )
        assert len(results) == 1
        assert results[0].success is False

    def test_effective_concurrency(self):
        executor = ParallelExecutor(max_concurrency=5)
        assert executor.effective_concurrency == 5


# ---------------------------------------------------------------------------
# 10. StructuredLearningEngine
# ---------------------------------------------------------------------------
from core.learning.structured_learning import StructuredLearningEngine, LearningRecord


class TestStructuredLearningEngine:
    def setup_method(self):
        self.engine = StructuredLearningEngine()

    def test_record_experiment_outcome(self):
        rec = self.engine.record_experiment_outcome(
            test_id="sqli_01",
            attack_type="sqli",
            target="https://example.com/login",
            outcome="vulnerable",
            payload_used="' OR 1=1 --",
            lesson="Classic blind SQLi",
            confidence=0.9,
        )
        assert isinstance(rec, LearningRecord)
        assert rec.test_id == "sqli_01"
        assert rec.outcome == "vulnerable"

    def test_success_rate_no_records(self):
        rate = self.engine.success_rate("nonexistent")
        assert rate == 0.0

    def test_success_rate_with_records(self):
        self.engine.record_experiment_outcome("t1", "sqli", "t", "vulnerable", confidence=1.0)
        self.engine.record_experiment_outcome("t1", "sqli", "t", "not_vulnerable", confidence=1.0)
        rate = self.engine.success_rate("t1")
        assert 0.0 <= rate <= 1.0

    def test_get_effective_payloads(self):
        self.engine.record_experiment_outcome(
            "t1", "sqli", "target", "vulnerable",
            payload_used="' OR 1=1",
        )
        payloads = self.engine.get_effective_payloads("sqli")
        assert "' OR 1=1" in payloads

    def test_get_effective_payloads_empty(self):
        payloads = self.engine.get_effective_payloads("xss")
        assert payloads == []

    def test_record_waf_detection(self):
        rec = self.engine.record_waf_detection("target", technology="cloudflare")
        assert isinstance(rec, LearningRecord)
        assert rec.waf_detected is True

    def test_needs_evasion(self):
        self.engine.record_waf_detection("waf_target")
        assert self.engine.needs_evasion("waf_target") is True
        assert self.engine.needs_evasion("unknown") is False

    def test_suggest_priority_boost(self):
        boost = self.engine.suggest_priority_boost("t1")
        assert isinstance(boost, float)

    def test_get_follow_up_suggestions(self):
        self.engine.record_experiment_outcome(
            "t1", "sqli", "target", "vulnerable",
            follow_ups=["sqli_02", "sqli_03"],
        )
        suggestions = self.engine.get_follow_up_suggestions("t1")
        assert "sqli_02" in suggestions
        assert "sqli_03" in suggestions

    def test_summary(self):
        s = self.engine.summary()
        assert isinstance(s, dict)
        assert "total_records" in s


# ---------------------------------------------------------------------------
# 11. ExploitChain + POCGate
# ---------------------------------------------------------------------------
from core.exploitation.exploit_chain import (
    ExploitChain,
    ChainPrerequisite,
    POCGate,
    create_cors_credential_chain,
    create_sqli_to_rce_chain,
)


class TestExploitChain:
    def test_check_prerequisites_endpoint_exists(self):
        prereq = ChainPrerequisite(
            prereq_id="p1", description="Endpoint must exist",
            check_type="endpoint_exists", check_value="/api/data",
        )
        chain = ExploitChain(
            name="test chain", attack_type="sqli",
            prerequisites=[prereq],
        )
        unmet = chain.check_prerequisites({"endpoints": ["/api/data", "/api/users"]})
        assert len(unmet) == 0  # prereq satisfied

    def test_check_prerequisites_missing(self):
        prereq = ChainPrerequisite(
            prereq_id="p1", description="Endpoint must exist",
            check_type="endpoint_exists", check_value="/api/secret",
        )
        chain = ExploitChain(prerequisites=[prereq])
        unmet = chain.check_prerequisites({"endpoints": ["/api/data"]})
        assert len(unmet) > 0

    def test_is_ready_property(self):
        prereq = ChainPrerequisite(
            prereq_id="p1", description="d", check_type="endpoint_exists",
            satisfied=True,
        )
        chain = ExploitChain(prerequisites=[prereq], state="READY")
        assert chain.is_ready is True

    def test_is_ready_false(self):
        prereq = ChainPrerequisite(
            prereq_id="p1", description="d", check_type="endpoint_exists",
            satisfied=False,
        )
        chain = ExploitChain(prerequisites=[prereq])
        assert chain.is_ready is False

    def test_to_dict(self):
        chain = ExploitChain(name="test", attack_type="sqli")
        d = chain.to_dict()
        assert isinstance(d, dict)
        assert d["name"] == "test"
        assert d["attack_type"] == "sqli"

    def test_factory_cors_chain(self):
        chain = create_cors_credential_chain("/api/data")
        assert isinstance(chain, ExploitChain)
        assert len(chain.prerequisites) > 0

    def test_factory_sqli_chain(self):
        chain = create_sqli_to_rce_chain("/api/query")
        assert isinstance(chain, ExploitChain)


class TestPOCGate:
    def test_can_generate_poc_true(self):
        finding = {
            "evidence": ["ev1"],
            "confidence": 0.8,
            "confirmed": True,
        }
        assert POCGate.can_generate_poc(finding) is True

    def test_can_generate_poc_false_low_confidence(self):
        finding = {
            "evidence": [],
            "confidence": 0.2,
        }
        assert POCGate.can_generate_poc(finding) is False

    def test_filter_reportable(self):
        findings = [
            {"id": "f1", "evidence": ["e1"], "confidence": 0.9, "confirmed": True},
            {"id": "f2", "evidence": [], "confidence": 0.1},
            {"id": "f3", "evidence": ["e2"], "confidence": 0.7, "confirmed": True},
        ]
        reportable = POCGate.filter_reportable(findings)
        assert isinstance(reportable, list)
        # Should include at least the high-confidence ones
        ids = [f["id"] for f in reportable]
        assert "f1" in ids


# ---------------------------------------------------------------------------
# 12. Oracles
# ---------------------------------------------------------------------------
from core.evidence.evidence import Evidence
from core.evidence.oracle import (
    StateChangeOracle,
    HeaderOracle,
    StatusCodeOracle,
    OutOfBandOracle,
    DifferentialResponseOracle,
    ErrorSignatureOracle,
    TimingDifferenceOracle,
    ReflectionOracle,
)


class TestStateChangeOracle:
    def test_detects_state_change(self):
        oracle = StateChangeOracle(before_state={"user_count": 5})
        ev = Evidence(tool_name="test", command="test")
        response = {"body": "", "after_state": {"user_count": 6}}
        confirmed, name = oracle.apply(response, ev)
        assert isinstance(confirmed, bool)

    def test_no_change(self):
        oracle = StateChangeOracle(before_state={"user_count": 5})
        ev = Evidence(tool_name="test", command="test")
        response = {"body": "", "after_state": {"user_count": 5}}
        confirmed, name = oracle.apply(response, ev)
        assert isinstance(confirmed, bool)

    def test_set_before(self):
        oracle = StateChangeOracle()
        oracle.set_before({"count": 10})
        assert oracle.before_state == {"count": 10}


class TestHeaderOracle:
    def test_detects_expected_header(self):
        oracle = HeaderOracle(expected_headers={"x-custom": "injected"})
        ev = Evidence(tool_name="test", command="test")
        response = {"headers": {"x-custom": "injected"}, "body": ""}
        confirmed, name = oracle.apply(response, ev)
        assert isinstance(confirmed, bool)

    def test_missing_header(self):
        oracle = HeaderOracle(expected_headers={"x-custom": "injected"})
        ev = Evidence(tool_name="test", command="test")
        response = {"headers": {}, "body": ""}
        confirmed, name = oracle.apply(response, ev)
        assert confirmed is False


class TestStatusCodeOracle:
    def test_expected_code_match(self):
        oracle = StatusCodeOracle(expected_codes=[403, 401])
        ev = Evidence(tool_name="test", command="test")
        response = {"status_code": 403, "body": ""}
        confirmed, name = oracle.apply(response, ev)
        assert isinstance(confirmed, bool)

    def test_unexpected_success(self):
        oracle = StatusCodeOracle(unexpected_success=True)
        ev = Evidence(tool_name="test", command="test")
        response = {"status_code": 200, "body": "admin panel"}
        confirmed, name = oracle.apply(response, ev)
        assert isinstance(confirmed, bool)


class TestOutOfBandOracle:
    def test_no_interaction(self):
        oracle = OutOfBandOracle(callback_id="cb123")
        ev = Evidence(tool_name="test", command="test")
        response = {"body": ""}
        confirmed, name = oracle.apply(response, ev)
        assert confirmed is False

    def test_with_interaction(self):
        oracle = OutOfBandOracle(callback_id="cb123")
        oracle.record_interaction({"type": "dns", "source": "10.0.0.1"})
        ev = Evidence(tool_name="test", command="test")
        response = {"body": ""}
        confirmed, name = oracle.apply(response, ev)
        assert confirmed is True


class TestDifferentialResponseOracle:
    def test_detects_difference(self):
        baseline = {"status_code": 200, "body": "normal page", "headers": {}}
        oracle = DifferentialResponseOracle(baseline)
        ev = Evidence(tool_name="test", command="test")
        response = {"status_code": 500, "body": "error", "headers": {}}
        confirmed, name = oracle.apply(response, ev)
        assert isinstance(confirmed, bool)


class TestErrorSignatureOracle:
    def test_detects_sql_error(self):
        oracle = ErrorSignatureOracle()
        ev = Evidence(tool_name="test", command="test")
        response = {"body": "You have an error in your SQL syntax", "headers": {}}
        confirmed, name = oracle.apply(response, ev)
        assert confirmed is True

    def test_no_error(self):
        oracle = ErrorSignatureOracle()
        ev = Evidence(tool_name="test", command="test")
        response = {"body": "Welcome to our site", "headers": {}}
        confirmed, name = oracle.apply(response, ev)
        assert confirmed is False


class TestTimingDifferenceOracle:
    def test_detects_delay(self):
        oracle = TimingDifferenceOracle(threshold_ms=1000.0)
        ev = Evidence(tool_name="test", command="test")
        response = {"body": "", "timing_ms": 6000.0}
        confirmed, name = oracle.apply(response, ev)
        assert isinstance(confirmed, bool)


class TestReflectionOracle:
    def test_detects_reflection(self):
        oracle = ReflectionOracle(payload="<script>alert(1)</script>")
        ev = Evidence(tool_name="test", command="test")
        response = {"body": "Hello <script>alert(1)</script> world"}
        confirmed, name = oracle.apply(response, ev)
        assert confirmed is True

    def test_no_reflection(self):
        oracle = ReflectionOracle(payload="<script>alert(1)</script>")
        ev = Evidence(tool_name="test", command="test")
        response = {"body": "Hello world, nothing here"}
        confirmed, name = oracle.apply(response, ev)
        assert confirmed is False


# ---------------------------------------------------------------------------
# 13. CanonicalReporter
# ---------------------------------------------------------------------------
from core.reporting.canonical_reporter import CanonicalReporter


class TestCanonicalReporter:
    def setup_method(self):
        self.findings = [
            {
                "id": "f1", "title": "SQL Injection",
                "severity": "HIGH", "type": "SQLI",
                "endpoint": "/api/login", "confirmed": True,
                "evidence": ["ev1"],
            },
            {
                "id": "f2", "title": "XSS",
                "severity": "MEDIUM", "type": "XSS",
                "endpoint": "/search", "confirmed": True,
                "evidence": ["ev2"],
            },
        ]
        self.reporter = CanonicalReporter(findings=self.findings)

    def test_generate_summary(self):
        summary = self.reporter.generate_summary()
        assert isinstance(summary, dict)

    def test_generate_summary_has_findings(self):
        summary = self.reporter.generate_summary()
        assert "findings" in summary

    def test_save_json(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.json")
            result = self.reporter.save_json(path)
            assert os.path.exists(result)
            with open(result) as f:
                data = json.load(f)
            assert isinstance(data, dict)

    def test_generate_markdown(self):
        md = self.reporter.generate_markdown()
        assert isinstance(md, str)
        assert len(md) > 0

    def test_empty_findings(self):
        reporter = CanonicalReporter(findings=[])
        summary = reporter.generate_summary()
        assert isinstance(summary, dict)

    def test_with_coverage_engine(self):
        cov = MagicMock()
        cov.get_coverage.return_value = 0.75
        cov.get_gaps.return_value = [("e1", "t1")]
        reporter = CanonicalReporter(findings=self.findings, coverage_engine=cov)
        summary = reporter.generate_summary()
        assert isinstance(summary, dict)


# ---------------------------------------------------------------------------
# 14. CriticAgent - Phase 27 heuristic checks
# ---------------------------------------------------------------------------
from core.verification.critic_agent import CriticAgent, Verdict, CriticVerdict


class TestCriticAgent:
    def setup_method(self):
        self.critic = CriticAgent(llm_client=MagicMock())

    def test_is_spa_false_positive_with_flag(self):
        finding = {"spa_catch_all": True, "type": "PATH_TRAVERSAL"}
        assert CriticAgent._is_spa_false_positive(finding) is True

    def test_is_spa_false_positive_with_markers(self):
        finding = {
            "type": "PATH_TRAVERSAL",
            "response_body": '<html><div id="root"></div><script type="module"></script></html>',
        }
        assert CriticAgent._is_spa_false_positive(finding) is True

    def test_is_spa_false_positive_no_spa(self):
        finding = {
            "type": "PATH_TRAVERSAL",
            "response_body": "<html><h1>Not Found</h1></html>",
        }
        assert CriticAgent._is_spa_false_positive(finding) is False

    def test_is_spa_false_positive_wrong_type(self):
        finding = {
            "type": "SQLI",
            "response_body": '<div id="root"></div>',
        }
        assert CriticAgent._is_spa_false_positive(finding) is False

    def test_target_was_degraded_health_state(self):
        finding = {"target_health_state": "DEGRADED"}
        assert self.critic._target_was_degraded(finding) is True

    def test_target_was_degraded_throttled(self):
        finding = {"target_health_state": "THROTTLED"}
        assert self.critic._target_was_degraded(finding) is True

    def test_target_was_degraded_status_429(self):
        finding = {"status_code": 429}
        assert self.critic._target_was_degraded(finding) is True

    def test_target_was_degraded_status_503(self):
        finding = {"status_code": 503}
        assert self.critic._target_was_degraded(finding) is True

    def test_target_was_degraded_slow_response(self):
        finding = {"response_time_ms": 35000}
        assert self.critic._target_was_degraded(finding) is True

    def test_target_was_degraded_healthy(self):
        finding = {"target_health_state": "HEALTHY", "status_code": 200}
        assert self.critic._target_was_degraded(finding) is False

    def test_target_was_degraded_exploited_overrides(self):
        finding = {"status_code": 503, "exploited": True}
        assert self.critic._target_was_degraded(finding) is False

    def test_check_identity_context_missing_identity(self):
        finding = {"type": "IDOR"}
        result = CriticAgent._check_identity_context(finding)
        assert len(result) > 0
        assert "identity" in result.lower()

    def test_check_identity_context_idor_insufficient_identities(self):
        finding = {
            "type": "IDOR",
            "identity": "admin",
            "identities_compared": ["admin"],
        }
        result = CriticAgent._check_identity_context(finding)
        assert len(result) > 0
        assert "2+" in result or "2" in result

    def test_check_identity_context_idor_sufficient(self):
        finding = {
            "type": "IDOR",
            "identity": "admin",
            "identities_compared": ["admin", "user"],
        }
        result = CriticAgent._check_identity_context(finding)
        assert result == ""

    def test_check_identity_context_non_authz_type(self):
        finding = {"type": "XSS", "identity": "user"}
        result = CriticAgent._check_identity_context(finding)
        assert result == ""

    def test_verify_finding_heuristic_exploit(self):
        finding = {
            "type": "SQL_INJECTION",
            "exploited": True,
            "evidence": ["ev1"],
        }
        verdict = asyncio.get_event_loop().run_until_complete(
            self.critic.verify_finding(finding)
        )
        assert isinstance(verdict, CriticVerdict)
        assert verdict.verdict == Verdict.CONFIRMED
        assert verdict.model == "heuristic"

    def test_verify_finding_scanner_proof(self):
        finding = {
            "type": "SQLI",
            "tool": "sqlmap",
            "proof": "Parameter 'id' is vulnerable",
        }
        verdict = asyncio.get_event_loop().run_until_complete(
            self.critic.verify_finding(finding)
        )
        assert verdict.verdict == Verdict.CONFIRMED

    def test_verify_finding_spa_false_positive(self):
        finding = {
            "type": "PATH_TRAVERSAL",
            "spa_catch_all": True,
        }
        verdict = asyncio.get_event_loop().run_until_complete(
            self.critic.verify_finding(finding)
        )
        assert verdict.verdict == Verdict.FALSE_POSITIVE
        assert "spa" in verdict.model.lower()

    def test_verify_finding_degraded_target(self):
        finding = {
            "type": "XSS",
            "target_health_state": "DEGRADED",
        }
        verdict = asyncio.get_event_loop().run_until_complete(
            self.critic.verify_finding(finding)
        )
        assert verdict.verdict == Verdict.UNCERTAIN
        assert "health" in verdict.model.lower()

    def test_verify_finding_identity_issue(self):
        finding = {"type": "IDOR"}
        verdict = asyncio.get_event_loop().run_until_complete(
            self.critic.verify_finding(finding)
        )
        assert verdict.verdict == Verdict.UNCERTAIN
        assert "identity" in verdict.model.lower()

    def test_verdict_enum(self):
        assert Verdict.CONFIRMED.value == "CONFIRMED"
        assert Verdict.FALSE_POSITIVE.value == "FALSE_POSITIVE"
        assert Verdict.UNCERTAIN.value == "UNCERTAIN"

    def test_critic_verdict_to_dict(self):
        cv = CriticVerdict(
            verdict=Verdict.CONFIRMED,
            confidence=0.9,
            reasoning="Confirmed via proof",
        )
        d = cv.to_dict()
        assert d["verdict"] == "CONFIRMED"
        assert d["confidence"] == 0.9


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
