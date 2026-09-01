import unittest
from unittest.mock import patch, MagicMock
import subprocess
import json

from core.domain.endpoint import Endpoint
from core.fuzzing.fuzzer_orchestrator import FuzzerOrchestrator
from core.fuzzing.models import ToolStatus

class TestFuzzerOrchestrator(unittest.TestCase):
    def setUp(self):
        self.orchestrator = FuzzerOrchestrator(target="https://target.com")
        self.endpoint = Endpoint(
            endpoint_id="EP-1",
            path="/api/test",
            url="https://target.com/api/test",
            method_set={"GET"}
        )

    @patch("core.fuzzing.adapters.subprocess.run")
    def test_sqlmap_success(self, mock_run):
        # Mocking an SQLMap success finding
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Parameter: id is vulnerable. Payload: id=1' OR '1'='1"
        mock_run.return_value = mock_result
        
        result = self.orchestrator.run_fuzzing("sqli", self.endpoint, {})
        
        self.assertEqual(result.status, ToolStatus.SUCCESS)
        self.assertEqual(result.tool_name, "sqlmap")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].title, "SQL Injection Detected")
        self.assertIn("Parameter: id is vulnerable", result.evidence)

    @patch("core.fuzzing.adapters.subprocess.run")
    def test_sqlmap_timeout_fallback_to_nuclei(self, mock_run):
        # We need to simulate subprocess throwing a TimeoutExpired for SQLMap (first call),
        # but succeeding for Nuclei (second call).
        def side_effect(*args, **kwargs):
            cmd = args[0]
            if "sqlmap" in cmd:
                raise subprocess.TimeoutExpired(cmd=cmd, timeout=30.0, output=b"")
            elif "nuclei" in cmd:
                mock_res = MagicMock()
                mock_res.returncode = 0
                mock_res.stdout = json.dumps({
                    "info": {"name": "Test Nuclei Finding", "severity": "high"}
                })
                return mock_res
            return MagicMock()
            
        mock_run.side_effect = side_effect
        
        result = self.orchestrator.run_fuzzing("sqli", self.endpoint, {})
        
        # It should fallback from sqlmap -> nuclei and succeed
        self.assertEqual(result.status, ToolStatus.SUCCESS)
        self.assertEqual(result.tool_name, "nuclei")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].title, "Test Nuclei Finding")

    def test_exhausted_fallback_chain(self):
        # idor chain is ["custom", "manual"] which are not real tools, so it will exhaust
        result = self.orchestrator.run_fuzzing("idor", self.endpoint, {})
        self.assertEqual(result.status, ToolStatus.ERROR)
        self.assertEqual(result.tool_name, "custom")

if __name__ == '__main__':
    unittest.main()
