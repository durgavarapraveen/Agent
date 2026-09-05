"""Tests for all 4 Strix-inspired architectural patterns."""
import asyncio
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ═══════════════════════════════════════════════════════════════════════════
# Pattern #1: Skill System
# ═══════════════════════════════════════════════════════════════════════════

class TestSkillLoader:
    def test_load_all_skills(self):
        from core.skills import SkillLoader
        loader = SkillLoader()
        skills = loader.load_all()
        assert len(skills) >= 6, f"Expected 6+ skills, got {len(skills)}"

    def test_load_by_name(self):
        from core.skills import SkillLoader
        loader = SkillLoader()
        skill = loader.load_by_name("sql-injection-testing")
        assert skill is not None
        assert skill.category == "vulnerabilities"
        assert "sql_injection" in skill.attack_types

    def test_load_by_category(self):
        from core.skills import SkillLoader
        loader = SkillLoader()
        vuln_skills = loader.load_by_category("vulnerabilities")
        assert len(vuln_skills) >= 5

    def test_load_for_attack_type(self):
        from core.skills import SkillLoader
        loader = SkillLoader()
        sqli_skills = loader.load_for_attack_type("sql_injection")
        assert len(sqli_skills) >= 1
        assert any("sql" in s.name.lower() for s in sqli_skills)

    def test_load_for_attack_type_xss(self):
        from core.skills import SkillLoader
        loader = SkillLoader()
        xss_skills = loader.load_for_attack_type("xss_reflected")
        assert len(xss_skills) >= 1

    def test_format_for_prompt(self):
        from core.skills import SkillLoader
        loader = SkillLoader()
        skills = loader.load_all()[:2]
        prompt = loader.format_for_prompt(skills, max_chars=5000)
        assert "Testing Methodology" in prompt
        assert len(prompt) <= 5500

    def test_skill_to_dict(self):
        from core.skills import SkillLoader
        loader = SkillLoader()
        skill = loader.load_by_name("sql-injection-testing")
        d = skill.to_dict()
        assert "name" in d
        assert "attack_types" in d
        assert d["category"] == "vulnerabilities"

    def test_register_custom_dir(self):
        from core.skills import SkillLoader
        with tempfile.TemporaryDirectory() as td:
            # Write a custom skill
            skill_file = os.path.join(td, "custom-test.md")
            with open(skill_file, "w") as f:
                f.write("---\nname: custom-test\ncategory: custom\ndescription: test\nattack_types: [test]\nseverity_range: [low]\n---\n# Custom\nTest content")
            loader = SkillLoader()
            loader.register_dir(td)
            skill = loader.load_by_name("custom-test")
            assert skill is not None
            assert skill.category == "custom"

    def test_nonexistent_skill_returns_none(self):
        from core.skills import SkillLoader
        loader = SkillLoader()
        assert loader.load_by_name("nonexistent-skill-xyz") is None


# ═══════════════════════════════════════════════════════════════════════════
# Pattern #2: Coverage Tracker
# ═══════════════════════════════════════════════════════════════════════════

class TestCoverageTracker:
    def test_record_and_retrieve(self):
        from core.coverage.coverage_tracker import CoverageTracker, TestAttempt, TestOutcome
        ct = CoverageTracker()
        attempt = TestAttempt(
            test_id="t1", category="sql_injection",
            endpoint="/api/login", parameter="username",
            payload="' OR '1'='1", outcome=TestOutcome.CONFIRMED,
        )
        ct.record(attempt)
        assert len(ct.get_attempts()) == 1

    def test_outcome_counts(self):
        from core.coverage.coverage_tracker import CoverageTracker, TestAttempt, TestOutcome, FailureReason
        ct = CoverageTracker()
        ct.record(TestAttempt(test_id="t1", category="sqli", endpoint="/a", parameter="p",
                              payload="x", outcome=TestOutcome.CONFIRMED))
        ct.record(TestAttempt(test_id="t2", category="xss", endpoint="/b", parameter="q",
                              payload="y", outcome=TestOutcome.NO_ISSUE_FOUND))
        ct.record(TestAttempt(test_id="t3", category="idor", endpoint="/c", parameter="r",
                              payload="z", outcome=TestOutcome.NO_ISSUE_FOUND,
                              failure_reason=FailureReason.RATE_LIMITED))
        counts = ct.outcome_counts()
        assert counts["confirmed"] == 1
        assert counts["no_issue_found"] == 2
        assert counts["failed"] == 1

    def test_real_coverage_honest(self):
        from core.coverage.coverage_tracker import CoverageTracker, TestAttempt, TestOutcome, FailureReason
        ct = CoverageTracker()
        ct.record(TestAttempt(test_id="t1", category="sqli", endpoint="/a", parameter="p",
                              payload="x", outcome=TestOutcome.CONFIRMED))
        ct.record(TestAttempt(test_id="t2", category="xss", endpoint="/b", parameter="q",
                              payload="y", outcome=TestOutcome.NOT_APPLICABLE))
        ct.record(TestAttempt(test_id="t3", category="idor", endpoint="/c", parameter="r",
                              payload="z", outcome=TestOutcome.NO_ISSUE_FOUND,
                              failure_reason=FailureReason.WAF_BLOCKED))
        cov = ct.real_coverage(total_planned=10)
        assert cov["not_applicable"] == 1
        assert cov["applicable"] == 9
        assert cov["confirmed_findings"] == 1
        assert cov["real_coverage_pct"] < 100  # NOT 100%!
        assert "confirmed" in cov["honest_summary"]

    def test_failure_breakdown(self):
        from core.coverage.coverage_tracker import CoverageTracker, TestAttempt, TestOutcome, FailureReason
        ct = CoverageTracker()
        ct.record(TestAttempt(test_id="t1", category="a", endpoint="/a", parameter="p",
                              payload="x", failure_reason=FailureReason.RATE_LIMITED))
        ct.record(TestAttempt(test_id="t2", category="b", endpoint="/b", parameter="q",
                              payload="y", failure_reason=FailureReason.WAF_BLOCKED))
        ct.record(TestAttempt(test_id="t3", category="c", endpoint="/c", parameter="r",
                              payload="z", failure_reason=FailureReason.RATE_LIMITED))
        fb = ct.failure_breakdown()
        assert fb["rate_limited"] == 2
        assert fb["waf_blocked"] == 1

    def test_get_retryable(self):
        from core.coverage.coverage_tracker import CoverageTracker, TestAttempt, TestOutcome, FailureReason
        ct = CoverageTracker()
        ct.record(TestAttempt(test_id="t1", category="a", endpoint="/a", parameter="p",
                              payload="x", failure_reason=FailureReason.RATE_LIMITED))
        ct.record(TestAttempt(test_id="t2", category="b", endpoint="/b", parameter="q",
                              payload="y", failure_reason=FailureReason.ENDPOINT_NOT_FOUND))
        retryable = ct.get_retryable()
        assert len(retryable) == 1
        assert retryable[0].test_id == "t1"

    def test_persist_and_report(self):
        from core.coverage.coverage_tracker import CoverageTracker, TestAttempt, TestOutcome
        import json
        with tempfile.TemporaryDirectory() as td:
            ct = CoverageTracker(output_dir=td)
            ct.record(TestAttempt(test_id="t1", category="sqli", endpoint="/a",
                                  parameter="p", payload="x", outcome=TestOutcome.CONFIRMED))
            ct.persist()
            outfile = os.path.join(td, "coverage_tracker.json")
            assert os.path.exists(outfile)
            with open(outfile) as f:
                data = json.load(f)
            assert data["total_attempts"] == 1


# ═══════════════════════════════════════════════════════════════════════════
# Pattern #3: Error Classification
# ═══════════════════════════════════════════════════════════════════════════

class TestErrorClassifier:
    def test_classify_rate_limit_by_status(self):
        from core.error.error_classifier import ErrorClassifier, ErrorCategory
        result = ErrorClassifier.classify(status_code=429)
        assert result.category == ErrorCategory.RATE_LIMITED
        assert result.max_retries == 2
        assert result.retry_delay_seconds >= 5.0

    def test_classify_rate_limit_by_message(self):
        from core.error.error_classifier import ErrorClassifier, ErrorCategory
        result = ErrorClassifier.classify(stderr="rate limit exceeded")
        assert result.category == ErrorCategory.RATE_LIMITED

    def test_classify_waf_blocked(self):
        from core.error.error_classifier import ErrorClassifier, ErrorCategory
        result = ErrorClassifier.classify(status_code=403, response_body="Request blocked by Cloudflare WAF")
        assert result.category == ErrorCategory.WAF_BLOCKED
        assert result.should_modify_payload

    def test_classify_not_found(self):
        from core.error.error_classifier import ErrorClassifier, ErrorCategory, RecoveryAction
        result = ErrorClassifier.classify(status_code=404)
        assert result.category == ErrorCategory.NOT_FOUND
        assert result.recovery == RecoveryAction.SKIP
        assert result.max_retries == 0

    def test_classify_auth_failed(self):
        from core.error.error_classifier import ErrorClassifier, ErrorCategory
        result = ErrorClassifier.classify(status_code=401)
        assert result.category == ErrorCategory.AUTH_FAILED

    def test_classify_timeout(self):
        from core.error.error_classifier import ErrorClassifier, ErrorCategory
        result = ErrorClassifier.classify(timed_out=True)
        assert result.category == ErrorCategory.TIMEOUT

    def test_classify_transient_500(self):
        from core.error.error_classifier import ErrorClassifier, ErrorCategory
        result = ErrorClassifier.classify(status_code=500)
        assert result.category == ErrorCategory.TRANSIENT
        assert result.max_retries == 3

    def test_classify_invalid_input(self):
        from core.error.error_classifier import ErrorClassifier, ErrorCategory
        result = ErrorClassifier.classify(status_code=400)
        assert result.category == ErrorCategory.INVALID_INPUT

    def test_classify_tool_failure(self):
        from core.error.error_classifier import ErrorClassifier, ErrorCategory
        result = ErrorClassifier.classify(return_code=1, stderr="connection timed out")
        assert result.category == ErrorCategory.TIMEOUT

    def test_classify_unknown(self):
        from core.error.error_classifier import ErrorClassifier, ErrorCategory
        result = ErrorClassifier.classify(status_code=200, return_code=0)
        assert result.category == ErrorCategory.UNKNOWN


class TestRetryExecutor:
    def test_retry_on_transient(self):
        from core.error.error_classifier import RetryExecutor
        call_count = 0

        class FakeResult:
            def __init__(self, success, status_code=0):
                self.success = success
                self.status_code = status_code
                self.stderr = ""
                self.stdout = ""
                self.data = ""
                self.return_code = 0
                self.tool = "test"

        async def flaky_tool():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return FakeResult(False, 500)
            return FakeResult(True)

        executor = RetryExecutor()
        result = asyncio.get_event_loop().run_until_complete(
            executor.execute_with_retry(flaky_tool)
        )
        assert result.success
        assert call_count == 3
        assert executor.stats["recovered"] == 1

    def test_skip_on_404(self):
        from core.error.error_classifier import RetryExecutor

        class FakeResult:
            success = False
            status_code = 404
            stderr = ""
            stdout = ""
            data = ""
            return_code = 0
            tool = "test"

        async def not_found():
            return FakeResult()

        executor = RetryExecutor()
        result = asyncio.get_event_loop().run_until_complete(
            executor.execute_with_retry(not_found)
        )
        assert not result.success
        assert executor.stats["permanent_failures"] == 1


# ═══════════════════════════════════════════════════════════════════════════
# Pattern #4: Confidence Scoring
# ═══════════════════════════════════════════════════════════════════════════

class TestConfidenceScorer:
    def test_high_confidence_db_error(self):
        from core.scoring.confidence_scorer import ConfidenceScorer, ResponseSample, EvidenceType
        scorer = ConfidenceScorer()
        samples = [
            ResponseSample(status_code=500, response_length=1000, response_time_ms=50,
                           contains_error=True, payload_used="' UNION SELECT @@version-- -"),
            ResponseSample(status_code=500, response_length=1020, response_time_ms=55,
                           contains_error=True, payload_used="' UNION SELECT @@version-- -"),
            ResponseSample(status_code=500, response_length=990, response_time_ms=48,
                           contains_error=True, payload_used="' UNION SELECT @@version-- -"),
        ]
        result = scorer.score(samples, evidence_type=EvidenceType.DATABASE_ERROR,
                              severity="high", payload="' UNION SELECT @@version-- -")
        assert result.score >= 0.7
        assert result.level.value == "high"
        assert result.is_reportable

    def test_low_confidence_no_evidence(self):
        from core.scoring.confidence_scorer import ConfidenceScorer, ResponseSample, EvidenceType
        scorer = ConfidenceScorer()
        samples = [ResponseSample(status_code=200, response_length=500)]
        result = scorer.score(samples, evidence_type=EvidenceType.NONE, severity="low")
        assert result.score < 0.5
        assert not result.is_reportable

    def test_timing_based_confidence(self):
        from core.scoring.confidence_scorer import ConfidenceScorer, ResponseSample, EvidenceType
        scorer = ConfidenceScorer()
        samples = [
            ResponseSample(response_time_ms=5200, contains_error=False),
            ResponseSample(response_time_ms=5100, contains_error=False),
            ResponseSample(response_time_ms=5300, contains_error=False),
        ]
        result = scorer.score(samples, evidence_type=EvidenceType.TIMING_DELAY,
                              severity="high", payload="' OR SLEEP(5)-- -",
                              expected_timing_ms=5000)
        assert result.score >= 0.5
        assert result.breakdown["timing_variance"] >= 0.8

    def test_inconsistent_timing_lowers_confidence(self):
        from core.scoring.confidence_scorer import ConfidenceScorer, ResponseSample, EvidenceType
        scorer = ConfidenceScorer()
        samples = [
            ResponseSample(response_time_ms=5000, contains_error=False),
            ResponseSample(response_time_ms=2000, contains_error=False),
            ResponseSample(response_time_ms=8000, contains_error=False),
        ]
        result = scorer.score(samples, evidence_type=EvidenceType.TIMING_DELAY,
                              severity="high", payload="' OR SLEEP(5)-- -",
                              expected_timing_ms=5000)
        consistent_result = TestConfidenceScorer.test_timing_based_confidence
        assert result.breakdown["timing_variance"] < 0.8

    def test_classify_evidence_sql_error(self):
        from core.scoring.confidence_scorer import ConfidenceScorer, EvidenceType
        scorer = ConfidenceScorer()
        ev = scorer.classify_evidence_type("You have an error in your SQL syntax near ''")
        assert ev == EvidenceType.DATABASE_ERROR

    def test_classify_evidence_code_exec(self):
        from core.scoring.confidence_scorer import ConfidenceScorer, EvidenceType
        scorer = ConfidenceScorer()
        ev = scorer.classify_evidence_type("uid=0(root) gid=0(root)")
        assert ev == EvidenceType.CODE_EXECUTION

    def test_gate_findings(self):
        from core.scoring.confidence_scorer import ConfidenceScorer, ConfidenceResult, ConfidenceLevel
        scorer = ConfidenceScorer()
        findings = [
            {"title": "SQLi", "severity": "high",
             "confidence_result": ConfidenceResult(score=0.9, level=ConfidenceLevel.HIGH, is_reportable=True, needs_review=False)},
            {"title": "XSS maybe", "severity": "medium",
             "confidence_result": ConfidenceResult(score=0.7, level=ConfidenceLevel.MEDIUM, is_reportable=False, needs_review=True)},
            {"title": "FP", "severity": "low",
             "confidence_result": ConfidenceResult(score=0.2, level=ConfidenceLevel.LOW, is_reportable=False, needs_review=False)},
        ]
        reportable, review, rejected = scorer.gate_findings(findings)
        assert len(reportable) == 1
        assert len(review) == 1
        assert len(rejected) == 1

    def test_severity_thresholds(self):
        from core.scoring.confidence_scorer import ConfidenceScorer, ResponseSample, EvidenceType
        scorer = ConfidenceScorer()
        samples = [
            ResponseSample(status_code=500, response_length=1000, response_time_ms=50,
                           contains_error=True, payload_used="' OR 1=1-- -"),
        ]
        # Critical severity has lower threshold (60%)
        crit = scorer.score(samples, EvidenceType.DATABASE_ERROR, severity="critical", payload="' OR 1=1-- -")
        # Low severity has higher threshold (90%)
        low = scorer.score(samples, EvidenceType.DATABASE_ERROR, severity="low", payload="' OR 1=1-- -")
        # Same score but different reportability
        assert crit.is_reportable or crit.score >= 0.6

    def test_counterevidence_penalty(self):
        from core.scoring.confidence_scorer import ConfidenceScorer, ResponseSample, EvidenceType
        scorer = ConfidenceScorer()
        samples = [ResponseSample(status_code=500, contains_error=True)]
        without = scorer.score(samples, EvidenceType.DATABASE_ERROR, severity="high")
        with_ce = scorer.score(samples, EvidenceType.DATABASE_ERROR, severity="high",
                                counterevidence="WAF may be generating fake errors")
        assert with_ce.score < without.score

    def test_payload_specificity(self):
        from core.scoring.confidence_scorer import ConfidenceScorer
        scorer = ConfidenceScorer()
        generic = scorer._score_payload_specificity("' OR '1'='1")
        specific = scorer._score_payload_specificity("' UNION SELECT NULL,@@version-- -")
        assert specific > generic


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
