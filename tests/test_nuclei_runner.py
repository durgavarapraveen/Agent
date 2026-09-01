"""
Unit tests for core/nuclei_runner.py module.
"""

import asyncio
import json
import unittest
from unittest.mock import patch, AsyncMock

from core.tools.nuclei_runner import NucleiRunner
from core.memory.shared_context import SharedContext


class TestNucleiRunner(unittest.TestCase):

    def setUp(self):
        from core.memory.dedup_tracker import DeduplicationTracker
        DeduplicationTracker().reset_all()

    def test_find_templates_for(self):
        runner = NucleiRunner()
        self.assertEqual(runner.find_templates_for("nginx"), "nginx")
        self.assertEqual(runner.find_templates_for("WordPress 6.2"), "wordpress,wp")
        self.assertEqual(runner.find_templates_for("Apache HTTP Server"), "apache")
        self.assertEqual(runner.find_templates_for("django"), "django")

    @patch("asyncio.create_subprocess_exec")
    def test_execute_template_parses_jsonl_output(self, mock_exec):
        sample_jsonl = (
            json.dumps({
                "template-id": "cve-2021-44228",
                "info": {
                    "name": "Apache Log4j RCE",
                    "severity": "critical",
                    "description": "Log4j RCE vulnerability",
                    "classification": {"cve-id": ["CVE-2021-44228"]}
                },
                "matched-at": "http://example.com/login",
                "extracted-results": ["log4j-payload"]
            }) + "\n"
        )

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (sample_jsonl.encode("utf-8"), b"")
        mock_proc.returncode = 0
        mock_exec.return_value = mock_proc

        runner = NucleiRunner()
        findings = asyncio.run(runner.execute_template("http://example.com", ["apache"]))

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["type"], "NUCLEI_MATCH")
        self.assertEqual(finding["template_id"], "cve-2021-44228")
        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertEqual(finding["cve"], "CVE-2021-44228")
        self.assertIn("cve-2021-44228", finding["proof"])

    @patch("asyncio.create_subprocess_exec")
    def test_execute_template_handles_missing_binary(self, mock_exec):
        mock_exec.side_effect = FileNotFoundError("nuclei binary not found")
        runner = NucleiRunner(binary_path="nonexistent_nuclei")
        findings = asyncio.run(runner.execute_template("http://example.com", ["nginx"]))
        self.assertEqual(findings, [])

    @patch("asyncio.create_subprocess_exec")
    def test_scan_context_technologies_registers_vulnerabilities(self, mock_exec):
        sample_jsonl = (
            json.dumps({
                "template-id": "nginx-version-detect",
                "info": {"name": "Nginx Disclosure", "severity": "low"},
                "matched-at": "http://example.com"
            }) + "\n"
        )

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (sample_jsonl.encode("utf-8"), b"")
        mock_proc.returncode = 0
        mock_exec.return_value = mock_proc

        ctx = SharedContext("http://example.com")
        ctx.add_technologies("http://example.com", ["nginx"])

        runner = NucleiRunner()
        findings = asyncio.run(runner.scan_context_technologies(ctx))

        self.assertEqual(len(findings), 1)
        self.assertEqual(len(ctx.vulnerabilities), 1)
        self.assertEqual(ctx.vulnerabilities[0]["type"], "NUCLEI_MATCH")


if __name__ == "__main__":
    unittest.main()
