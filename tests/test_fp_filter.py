"""
Unit tests for core/fp_filter.py false positive filtering module.
"""

import unittest
from core.reporting.fp_filter import FalsePositiveFilter
from core.memory.shared_context import SharedContext


class TestFalsePositiveFilter(unittest.TestCase):

    def setUp(self):
        self.filter = FalsePositiveFilter()

    def test_status_code_validation_reflection(self):
        finding_404 = {
            "type": "unencoded_input_reflection",
            "title": "Unencoded Reflection",
            "proof": "Tracer reflected in response (status 404)"
        }
        valid, reason = self.filter.check_status_code(finding_404)
        self.assertFalse(valid)
        self.assertIn("non-2xx status code: 404", reason)

        finding_200 = {
            "type": "unencoded_input_reflection",
            "title": "Unencoded Reflection",
            "proof": "Tracer reflected in response (status 200)"
        }
        valid, reason = self.filter.check_status_code(finding_200)
        self.assertTrue(valid)

    def test_baseline_differential_comparison(self):
        finding = {
            "type": "verbose_error_disclosure",
            "title": "Verbose SQL Error",
            "matched_error": "You have an error in your SQL syntax"
        }

        # Error present in baseline -> reject
        valid, reason = self.filter.check_baseline_differential(
            finding, baseline_body="Error: You have an error in your SQL syntax near line 1"
        )
        self.assertFalse(valid)
        self.assertIn("already present in baseline", reason)

        # Error absent in baseline -> pass
        valid, reason = self.filter.check_baseline_differential(
            finding, baseline_body="<html><body>Welcome to product page</body></html>"
        )
        self.assertTrue(valid)

    def test_tracer_reflection_matching(self):
        finding = {
            "type": "unencoded_input_reflection",
            "tracer_used": "probe_xss_check_12345"
        }

        # Tracer missing in response body -> reject
        valid, reason = self.filter.check_tracer_reflection(
            finding, response_body="<html><body>Clean response</body></html>"
        )
        self.assertFalse(valid)

        # Tracer present in response body -> pass
        valid, reason = self.filter.check_tracer_reflection(
            finding, response_body="<html><body>Search: probe_xss_check_12345</body></html>"
        )
        self.assertTrue(valid)

    def test_content_type_validation(self):
        finding = {
            "type": "unencoded_input_reflection",
            "title": "Input Reflection"
        }

        # Non-HTML content type -> reject
        valid, reason = self.filter.check_content_type(finding, content_type="application/json")
        self.assertFalse(valid)
        self.assertIn("non-HTML Content-Type", reason)

        # HTML content type -> pass
        valid, reason = self.filter.check_content_type(finding, content_type="text/html; charset=utf-8")
        self.assertTrue(valid)

    def test_shared_context_auditing(self):
        ctx = SharedContext("http://example.com")

        bad_finding = {
            "type": "unencoded_input_reflection",
            "title": "Reflection on 404",
            "proof": "Tracer reflected (status 404)"
        }

        added = ctx.add_vulnerability(bad_finding)
        self.assertFalse(added)
        self.assertEqual(len(ctx.vulnerabilities), 0)
        self.assertEqual(len(ctx.false_positives), 1)
        self.assertEqual(ctx.false_positives[0]["finding"]["title"], "Reflection on 404")
        self.assertIn("non-2xx status code: 404", ctx.false_positives[0]["reason"])


if __name__ == "__main__":
    unittest.main()
