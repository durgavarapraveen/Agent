import unittest
from unittest.mock import patch, MagicMock
import io

from core.domain.experiment_v2 import SecurityExperiment
from core.execution.executors.base import ExecutorBase, ExecutionResult, ExecutionStatus
from core.execution.executors.authentication import AuthenticationExecutor
from core.execution.executors.authorization import AuthorizationExecutor
from core.execution.executors.sql_injection import SQLiExecutor
from core.execution.executors.xss import XSSExecutor
from core.tools.tool_portfolio import ToolPortfolio


class TestExecutorBase(unittest.TestCase):

    def test_executor_base_timeout(self):
        self.assertTrue(issubclass(AuthenticationExecutor, ExecutorBase))
        executor = AuthenticationExecutor(timeout_seconds=60)
        self.assertEqual(executor.timeout_seconds, 60)
        default = AuthenticationExecutor()
        self.assertEqual(default.timeout_seconds, 30)


class TestAuthenticationExecutor(unittest.TestCase):

    def test_authentication_executor_validates_inputs(self):
        ex = AuthenticationExecutor()
        ok, err = ex.validate_inputs({"username": "a", "password": "b", "login_url": "http://x"})
        self.assertTrue(ok)
        self.assertIsNone(err)

        ok, err = ex.validate_inputs({"username": "a"})
        self.assertFalse(ok)
        self.assertIn("password", err)
        self.assertIn("login_url", err)

    def test_authentication_executor_executes(self):
        ex = AuthenticationExecutor()
        exp = SecurityExperiment(
            hypothesis_id="h1", endpoint_id="/login", capability="auth",
            input_parameters={"username": "admin", "password": "pass", "login_url": "http://127.0.0.1:99999/login"},
        )
        result = ex.execute(exp)
        self.assertIsInstance(result, ExecutionResult)
        self.assertIn(result.status, (ExecutionStatus.SUCCESS, ExecutionStatus.FAILURE))
        self.assertIsInstance(result.evidence, dict)
        self.assertGreater(result.execution_time_ms, 0)


class TestAuthorizationExecutor(unittest.TestCase):

    def test_authorization_executor_validates_target_has_id(self):
        ex = AuthorizationExecutor()
        ok, err = ex.validate_target({"url": "/api/users/{id}/profile"}, {})
        self.assertTrue(ok)

        ok, err = ex.validate_target({"url": "/api/users/profile"}, {})
        self.assertFalse(ok)
        self.assertIn("{id}", err)

    def test_authorization_executor_executes(self):
        ex = AuthorizationExecutor()
        exp = SecurityExperiment(
            hypothesis_id="h1", endpoint_id="/api", capability="idor",
            input_parameters={
                "resource_url": "http://127.0.0.1:99999/api/users/{id}",
                "resource_id": "42",
                "target_identity": "guest",
            },
        )
        result = ex.execute(exp)
        self.assertIsInstance(result, ExecutionResult)
        self.assertIsInstance(result.evidence, dict)


class TestSQLiExecutor(unittest.TestCase):

    def test_sql_injection_executor_detects_error_signatures(self):
        ex = SQLiExecutor()

        fake_body_with_error = 'Error: You have an error in your SQL syntax near "1=1"'

        exp = SecurityExperiment(
            hypothesis_id="h1", endpoint_id="/search", capability="sqli",
            input_parameters={
                "injection_url": "http://127.0.0.1:99999/search",
                "injectable_param": "q",
                "payloads": ["' OR 1=1--"],
            },
        )

        import urllib.error
        http_error = urllib.error.HTTPError(
            url="http://127.0.0.1:99999/search",
            code=500, msg="Internal Server Error",
            hdrs=MagicMock(), fp=io.BytesIO(fake_body_with_error.encode()),
        )

        with patch("urllib.request.urlopen", side_effect=http_error):
            result = ex.execute(exp)

        self.assertEqual(result.status, ExecutionStatus.SUCCESS)
        results = result.evidence.get("results", [])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["error_detected"])


class TestXSSExecutor(unittest.TestCase):

    def test_xss_executor_detects_reflection(self):
        ex = XSSExecutor()
        payload = "<script>alert(1)</script>"
        reflected_body = f'<html><body>Search: {payload}</body></html>'

        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = reflected_body.encode()
        mock_resp.headers = {}
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        exp = SecurityExperiment(
            hypothesis_id="h1", endpoint_id="/search", capability="xss",
            input_parameters={
                "injection_url": "http://127.0.0.1:99999/search",
                "injectable_param": "q",
                "payloads": [payload],
            },
        )

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = ex.execute(exp)

        self.assertEqual(result.status, ExecutionStatus.SUCCESS)
        results = result.evidence.get("results", [])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["reflection_detected"])


class TestToolPortfolio(unittest.TestCase):

    def test_tool_portfolio_registers_fallback_chain(self):
        tp = ToolPortfolio()
        tp.register_fallback_chain("sql_injection", ["sqlmap", "nuclei", "custom_mutator"])
        self.assertEqual(tp.get_tools("sql_injection"), ["sqlmap", "nuclei", "custom_mutator"])
        self.assertEqual(tp.get_tools("unknown"), [])

    def test_tool_portfolio_returns_chain_in_order(self):
        tp = ToolPortfolio()
        tp.register_fallback_chain("port_discovery", ["nmap", "masscan", "port_check"])
        tp.register_fallback_chain("xss", ["dalfox", "nuclei", "browser"])
        tools = tp.get_tools("port_discovery")
        self.assertEqual(tools[0], "nmap")
        self.assertEqual(tools[1], "masscan")
        self.assertEqual(tools[2], "port_check")


if __name__ == "__main__":
    unittest.main()
