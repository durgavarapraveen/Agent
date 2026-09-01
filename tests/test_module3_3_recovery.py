"""
Unit test suite for Phase 3 Module 3.3: Fallback & Recovery Strategies (core/recovery_strategies.py).
"""

import unittest
from core.security.authorization import TargetScopeValidator
from core.common.recovery_strategies import (
    retry_with_backoff,
    FallbackRecoveryManager
)


class TestModule33RecoveryStrategies(unittest.TestCase):

    def setUp(self):
        TargetScopeValidator.set(TargetScopeValidator(["example.com", "192.168.1.10"]))
        self.manager = FallbackRecoveryManager()

    def test_error_to_action_mapping(self):
        action1 = self.manager.handle_error_action("ConnectionTimeout: host failed to respond")
        self.assertEqual(action1["action"], "increase_timeout")
        self.assertEqual(action1["params"]["timeout"], 120)

        action2 = self.manager.handle_error_action("HTTP 403 WAF Block Detected")
        self.assertEqual(action2["action"], "activate_bypass_mode")

    def test_exponential_backoff_retry_decorator(self):
        attempts = [0]

        @retry_with_backoff(max_attempts=3, base_delay=0.01)
        def failing_func():
            attempts[0] += 1
            if attempts[0] < 3:
                raise Exception("Transient 502 Bad Gateway")
            return "SUCCESS"

        res = failing_func()
        self.assertEqual(res, "SUCCESS")
        self.assertEqual(attempts[0], 3)

    def test_tool_fallback_chain_execution(self):
        # Primary tool nmap fails, secondary masscan succeeds
        def mock_runner(tool_name: str) -> bool:
            if tool_name == "nmap":
                return False
            return True

        res = self.manager.execute_tool_fallback_chain("port_scan", mock_runner)
        self.assertEqual(res["successful_tool"], "masscan")
        self.assertEqual(res["attempts"], 2)

    def test_protocol_downgrade_https_to_http(self):
        def mock_request(url: str) -> str:
            if url.startswith("https://"):
                raise Exception("SSLCertVerificationError: certificate verification failed")
            return "HTTP_OK_BODY"

        body, findings = self.manager.perform_protocol_downgrade_request("https://example.com", mock_request)
        self.assertEqual(body, "HTTP_OK_BODY")
        self.assertEqual(len(findings), 1)
        self.assertIn("Potential insecure service", findings[0]["vulnerability"])


if __name__ == "__main__":
    unittest.main()
