import pytest
from typing import Dict, Any
from core.benchmarking.juice_shop_mapper import (
    JuiceShopChallengeMapper, JUICE_SHOP_CHALLENGES, CATEGORY_TO_TEST_ID,
)
from core.benchmarking.benchmark_runner import (
    JuiceShopBenchmarkRunner, BenchmarkResult, ChallengeResult,
)


EXPECTED_CHALLENGE_COUNT = len(JUICE_SHOP_CHALLENGES)


class TestJuiceShopChallengeMapper:
    def test_all_challenges_have_test_ids(self):
        mapper = JuiceShopChallengeMapper()
        mapping = mapper.map_challenges_to_tests()

        assert len(mapping) == EXPECTED_CHALLENGE_COUNT
        for name, test_id in mapping.items():
            assert test_id, f"Challenge '{name}' has no test_id"
            assert "." in test_id, f"Test ID '{test_id}' for '{name}' missing category separator"

    def test_challenge_count(self):
        mapper = JuiceShopChallengeMapper()
        assert mapper.get_challenge_count() == EXPECTED_CHALLENGE_COUNT

    def test_sql_injection_challenges_mapped(self):
        mapper = JuiceShopChallengeMapper()
        mapping = mapper.map_challenges_to_tests()

        sqli_challenges = ["SQL Injection Login", "SQL Injection Schema", "SQL Injection Search"]
        for name in sqli_challenges:
            assert name in mapping
            assert "sqli" in mapping[name]

    def test_xss_challenges_mapped(self):
        mapper = JuiceShopChallengeMapper()
        mapping = mapper.map_challenges_to_tests()

        xss_challenges = ["DOM XSS", "Reflected XSS", "Stored XSS"]
        for name in xss_challenges:
            assert name in mapping
            assert "xss" in mapping[name]

    def test_unique_test_ids(self):
        mapper = JuiceShopChallengeMapper()
        unique = mapper.get_unique_test_ids()
        assert len(unique) > 10

    def test_get_challenges_for_test(self):
        mapper = JuiceShopChallengeMapper()
        sqli_challenges = mapper.get_challenges_for_test("input_validation.sqli")
        assert len(sqli_challenges) >= 3
        assert "SQL Injection Login" in sqli_challenges

    def test_all_categories_mapped(self):
        mapper = JuiceShopChallengeMapper()
        mapping = mapper.map_challenges_to_tests()

        categories_seen = set()
        for _, cat, _ in JUICE_SHOP_CHALLENGES:
            categories_seen.add(cat)

        for cat in categories_seen:
            assert cat in CATEGORY_TO_TEST_ID, f"Category '{cat}' has no default test_id mapping"

    def test_no_duplicate_challenge_names(self):
        names = [name for name, _, _ in JUICE_SHOP_CHALLENGES]
        assert len(names) == len(set(names)), "Duplicate challenge names found"

    def test_difficulty_lookup(self):
        mapper = JuiceShopChallengeMapper()
        assert mapper.get_challenge_difficulty("SQL Injection Login") == 1
        assert mapper.get_challenge_difficulty("SSTi") == 6
        assert mapper.get_challenge_difficulty("nonexistent") == 0

    def test_mapping_is_cached(self):
        mapper = JuiceShopChallengeMapper()
        m1 = mapper.map_challenges_to_tests()
        m2 = mapper.map_challenges_to_tests()
        assert m1 == m2


class PartialSuccessExecutor:
    """Simulates a test executor that confirms some test types."""
    CONFIRMED_TESTS = {
        "input_validation.sqli", "xss.reflected", "xss.dom", "xss.stored",
        "authorization.idor", "information_disclosure.error_messages",
        "misconfiguration.encoding",
    }

    def execute_test(self, test_id: str, target_url: str) -> Dict[str, Any]:
        if test_id in self.CONFIRMED_TESTS:
            return {"success": True, "tool": "nuclei", "error": ""}
        return {"success": False, "tool": "nuclei", "error": "not vulnerable"}


class AllFailExecutor:
    def execute_test(self, test_id: str, target_url: str) -> Dict[str, Any]:
        return {"success": False, "tool": "nuclei", "error": "scan clean"}


class ExceptionExecutor:
    def execute_test(self, test_id: str, target_url: str) -> Dict[str, Any]:
        raise ConnectionError("target unreachable")


class TestBenchmarkRunner:
    def test_run_benchmark_partial_success(self):
        runner = JuiceShopBenchmarkRunner(
            target_url="http://localhost:3000",
            test_executor=PartialSuccessExecutor(),
        )
        result = runner.run_benchmark()

        assert result.expected == EXPECTED_CHALLENGE_COUNT
        assert result.tested == EXPECTED_CHALLENGE_COUNT
        assert result.confirmed > 0
        assert result.coverage > 0
        assert result.coverage == (result.confirmed / result.expected * 100.0)

    def test_run_benchmark_all_fail(self):
        runner = JuiceShopBenchmarkRunner(
            target_url="http://localhost:3000",
            test_executor=AllFailExecutor(),
        )
        result = runner.run_benchmark()

        assert result.expected == EXPECTED_CHALLENGE_COUNT
        assert result.tested == EXPECTED_CHALLENGE_COUNT
        assert result.confirmed == 0
        assert result.coverage == 0.0

    def test_run_benchmark_with_exceptions(self):
        runner = JuiceShopBenchmarkRunner(
            target_url="http://localhost:3000",
            test_executor=ExceptionExecutor(),
        )
        result = runner.run_benchmark()

        assert result.expected == EXPECTED_CHALLENGE_COUNT
        assert result.tested == EXPECTED_CHALLENGE_COUNT
        assert result.confirmed == 0

    def test_report_format(self):
        runner = JuiceShopBenchmarkRunner(
            target_url="http://localhost:3000",
            test_executor=PartialSuccessExecutor(),
        )
        result = runner.run_benchmark()
        report = result.report()

        assert "Juice Shop Benchmark Report" in report
        assert f"Expected challenges : {EXPECTED_CHALLENGE_COUNT}" in report
        assert f"Tested              : {result.tested}" in report
        assert f"Confirmed           : {result.confirmed}" in report
        assert "Coverage" in report

    def test_generate_report(self):
        runner = JuiceShopBenchmarkRunner(
            target_url="http://localhost:3000",
            test_executor=PartialSuccessExecutor(),
        )
        report = runner.generate_report()
        assert "expected" in report.lower() or "Expected" in report

    def test_report_shows_expected_tested_confirmed(self):
        runner = JuiceShopBenchmarkRunner(
            target_url="http://localhost:3000",
            test_executor=PartialSuccessExecutor(),
        )
        result = runner.run_benchmark()
        report = result.report()

        assert f"expected={EXPECTED_CHALLENGE_COUNT}" in report.replace(" ", "").replace(":", "=").lower() or \
               str(EXPECTED_CHALLENGE_COUNT) in report

    def test_challenge_results_populated(self):
        runner = JuiceShopBenchmarkRunner(
            target_url="http://localhost:3000",
            test_executor=PartialSuccessExecutor(),
        )
        result = runner.run_benchmark()

        assert len(result.challenge_results) == EXPECTED_CHALLENGE_COUNT
        for cr in result.challenge_results:
            assert cr.challenge_name
            assert cr.test_id
            assert cr.tested

    def test_deduplicates_test_execution(self):
        call_count = {"n": 0}

        class CountingExecutor:
            def execute_test(self, test_id, target_url):
                call_count["n"] += 1
                return {"success": False, "tool": "nuclei", "error": ""}

        runner = JuiceShopBenchmarkRunner(
            target_url="http://localhost:3000",
            test_executor=CountingExecutor(),
        )
        mapper = runner.mapper
        unique_tests = len(mapper.get_unique_test_ids())

        runner.run_benchmark()
        assert call_count["n"] == unique_tests
        assert call_count["n"] < EXPECTED_CHALLENGE_COUNT
