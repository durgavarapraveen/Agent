"""
Unit test suite for Phase 3 Module 3.1: Few-Shot Learning from Past Pentests (core/pentest_memory.py).
"""

import os
import tempfile
import unittest

from core.pentest_memory import anonymize_text, hash_hostname, PentestMemoryEngine


class TestModule31PentestMemory(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_memory.sqlite")
        self.engine = PentestMemoryEngine(db_path=self.db_path, anonymize_history=True)

    def tearDown(self):
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_anonymization_helpers(self):
        raw_text = "Target IP 192.168.1.100 and user admin@company.com scanned"
        anon = anonymize_text(raw_text)
        self.assertNotIn("192.168.1.100", anon)
        self.assertIn("10.0.0.", anon)
        self.assertNotIn("admin@company.com", anon)

        h = hash_hostname("server.company.internal")
        self.assertEqual(len(h), 16)

    def test_similarity_retrieval(self):
        scans = self.engine.retrieve_similar_past_scans(["nginx", "postgresql"], top_k=2)
        self.assertGreaterEqual(len(scans), 1)
        self.assertIn("relevance_score", scans[0])
        self.assertGreater(scans[0]["relevance_score"], 0.0)

    def test_tool_ranking_by_effectiveness(self):
        tools = ["gobuster", "nmap", "nuclei", "sqlmap"]
        ranked = self.engine.rank_tools_by_effectiveness(tools)
        # gobuster should be skipped or ranked last due to low score
        self.assertEqual(ranked[0], "nuclei")
        self.assertNotIn("gobuster", ranked)

    def test_dynamic_system_prompt_insight(self):
        insight = self.engine.build_dynamic_system_prompt_insight(["nginx", "postgresql"])
        self.assertIn("Historical Insight:", insight)
        self.assertIn("recommended_tools", insight)


if __name__ == "__main__":
    unittest.main()
