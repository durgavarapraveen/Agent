"""
Unit test suite for Phase 3 Module 3.4: Token Optimizer & LLM Orchestrator.
"""

import os
import tempfile
import unittest

from core.security.authorization import TargetScopeValidator
from core.common.token_optimizer import TokenOptimizer
from core.orchestration.llm_orchestrator import LLMOrchestrator


class TestModule34TokenOptimizer(unittest.TestCase):

    def setUp(self):
        TargetScopeValidator.set(TargetScopeValidator(["example.com", "192.168.1.10"]))
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_orch.sqlite")
        self.optimizer = TokenOptimizer(model_name="gpt-4", token_limit=1000)
        self.orchestrator = LLMOrchestrator(model_name="gpt-4", token_limit=1000, db_path=self.db_path)

    def tearDown(self):
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_token_counting_and_trimming(self):
        cnt = self.optimizer.count_tokens("Hello world this is a token counting test.")
        self.assertGreater(cnt, 0)

        long_output = "\n".join([f"Line {i}" for i in range(50)])
        trimmed = self.optimizer.trim_tool_output(long_output, max_lines=10)
        self.assertIn("truncated 40 lines", trimmed)
        self.assertEqual(len(trimmed.strip().splitlines()), 11)

    def test_finding_deduplication_and_filtering(self):
        findings = [
            {"cve_id": "CVE-2021-44228", "target": "example.com", "confidence_score": 0.90, "severity": "CRITICAL"},
            {"cve_id": "CVE-2021-44228", "target": "example.com", "confidence_score": 0.90, "severity": "CRITICAL"},  # Duplicate
            {"cve_id": "CVE-2023-9999", "target": "example.com", "confidence_score": 0.10, "severity": "LOW"}  # Low confidence < 30%
        ]
        filtered = self.optimizer.deduplicate_and_filter_findings(findings, min_confidence=0.30)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["cve_id"], "CVE-2021-44228")

    def test_threshold_compression_and_warning(self):
        prompt = "Assess security posture"
        # Generate 15 findings to exceed 70% threshold with token_limit=500
        small_optimizer = TokenOptimizer(model_name="gpt-4", token_limit=500)
        findings = [
            {"cve_id": f"CVE-2023-00{i}", "target": "example.com", "severity": "HIGH", "confidence_score": 0.80}
            for i in range(15)
        ]
        tool_outputs = {"nmap": "nmap output " * 50}

        result = small_optimizer.compress_prompt_context(prompt, findings, tool_outputs)
        self.assertIn(result["status"], ["COMPRESSION_TRIGGERED_70", "TOKEN_LIMIT_WARNING_90"])
        self.assertGreater(result["reduction_percent"], 0.0)

    def test_master_llm_orchestrator(self):
        res = self.orchestrator.prepare_llm_execution_context(
            tech_stack=["nginx", "postgresql"],
            industry="finance",
            depth="deep",
            findings=[{"cve_id": "CVE-2021-44228", "severity": "CRITICAL", "confidence_score": 0.95}],
            tool_outputs={"nmap": "PORT 443 OPEN"}
        )
        self.assertIn("compressed_payload", res)
        self.assertIn("prompt", res["compressed_payload"])
        self.assertIn("Finance", res["compressed_payload"]["prompt"])


if __name__ == "__main__":
    unittest.main()
