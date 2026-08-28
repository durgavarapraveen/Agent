"""
Unit test suite for Phase 3 Module 3.2: Adaptive Prompt Engineering (core/prompts/adaptive.py).
"""

import os
import tempfile
import unittest

from core.prompts.adaptive import AdaptivePromptEngine


class TestModule32AdaptivePrompts(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_ab.sqlite")
        self.variants_dir = os.path.join(self.tmp_dir.name, "prompt_variants")

        # Create mock variants
        for ind in ["healthcare", "finance", "retail", "default"]:
            ind_dir = os.path.join(self.variants_dir, ind)
            os.makedirs(ind_dir, exist_ok=True)
            with open(os.path.join(ind_dir, "base.txt"), "w", encoding="utf-8") as f:
                f.write(f"=== BASE PROMPT FOR {ind.upper()} ===")

        self.engine = AdaptivePromptEngine(variants_dir=self.variants_dir, db_path=self.db_path)

    def tearDown(self):
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_industry_and_depth_prompt_generation(self):
        prompt = self.engine.build_prompt(industry="finance", depth="deep")
        self.assertIn("BASE PROMPT FOR FINANCE", prompt)
        self.assertIn("SCAN DEPTH: DEEP", prompt)
        self.assertIn("100% Payloads", prompt)
        self.assertIn("business_logic_tester", prompt)

    def test_error_recovery_prompt_injection(self):
        prompt = self.engine.build_prompt(industry="default", depth="poc", error_context="Tool failed with WAF Block")
        self.assertIn("ERROR RECOVERY ACTIVE", prompt)
        self.assertIn("Use generic, non-signature payloads", prompt)

    def test_ab_testing_and_recommendation(self):
        # Log 10 run results for finance web apps
        for i in range(10):
            self.engine.log_run_result(variant_key="finance/deep", target_type="web_finance", findings_count=5, success_rate=0.85)

        suggestion = self.engine.suggest_best_variant("web_finance")
        self.assertIsNotNone(suggestion)
        self.assertIn("Suggested prompt: finance/deep", suggestion)
        self.assertIn("85% success rate across 10 scans", suggestion)


if __name__ == "__main__":
    unittest.main()
