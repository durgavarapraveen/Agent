"""
Unit tests for CensysClient and Censys Tool integration.
Tests PAT Bearer authentication, header generation, error handling, log masking, and tool integration.
No real external network calls are made (mocked via unittest.mock).
"""

import unittest
from unittest.mock import patch, AsyncMock, MagicMock
import logging
import io
import httpx

from core.censys_client import CensysClient
from tools.censys_tool import CensysTool


class TestCensysClient(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.test_token = "test-censys-pat-12345"

    def test_1_token_loaded(self):
        """Test 1 — Token loaded successfully."""
        client = CensysClient(api_token=self.test_token)
        self.assertTrue(client.is_configured)
        self.assertEqual(client.api_token, self.test_token)

    def test_2_missing_token(self):
        """Test 2 — Missing token fails cleanly."""
        client = CensysClient(api_token="")
        self.assertFalse(client.is_configured)
        with self.assertRaises(ValueError) as ctx:
            client._get_headers()
        self.assertIn("Censys PAT not configured", str(ctx.exception))

    @patch("httpx.AsyncClient.get")
    async def test_3_authorization_header(self, mock_get):
        """Test 3 — Authorization header Bearer token generation."""
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"code": 200, "status": "OK", "result": {"hits": []}}
        mock_get.return_value = mock_resp

        client = CensysClient(api_token=self.test_token)
        res = await client.search_hosts("8.8.8.8")

        mock_get.assert_called_once()
        _, kwargs = mock_get.call_args
        headers = kwargs.get("headers", {})
        self.assertIn("Authorization", headers)
        self.assertEqual(headers["Authorization"], f"Bearer {self.test_token}")
        self.assertEqual(headers["Accept"], "application/json")

    @patch("httpx.AsyncClient.get")
    async def test_4_token_is_not_logged(self, mock_get):
        """Test 4 — Ensure application logs never contain the PAT string."""
        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        censys_logger = logging.getLogger("core.censys_client")
        censys_logger.addHandler(handler)
        censys_logger.setLevel(logging.DEBUG)

        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 500
        mock_resp.text = f"Server error with header Bearer {self.test_token}"
        mock_get.return_value = mock_resp

        client = CensysClient(api_token=self.test_token)
        with self.assertRaises(RuntimeError):
            await client.search_hosts("error-target")

        censys_logger.removeHandler(handler)
        log_contents = log_stream.getvalue()
        self.assertNotIn(self.test_token, log_contents)

    @patch("httpx.AsyncClient.get")
    async def test_5_unauthorized_response(self, mock_get):
        """Test 5 — Mock HTTP 401 response and verify clean authentication error."""
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_get.return_value = mock_resp

        client = CensysClient(api_token=self.test_token)
        with self.assertRaises(PermissionError) as ctx:
            await client.search_hosts("unauthorized-target")
        self.assertIn("Censys authentication failed", str(ctx.exception))

    @patch("httpx.AsyncClient.get")
    async def test_6_rate_limiting(self, mock_get):
        """Test 6 — Mock HTTP 429 response and verify rate limit handling."""
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 429
        mock_resp.text = "Rate limit exceeded"
        mock_get.return_value = mock_resp

        client = CensysClient(api_token=self.test_token)
        with self.assertRaises(RuntimeError) as ctx:
            await client.search_hosts("ratelimit-target")
        self.assertIn("rate limit exceeded", str(ctx.exception).lower())

    @patch("core.censys_client.CensysClient.search_hosts")
    async def test_7_existing_censys_tool(self, mock_search):
        """Test 7 — Verify Censys tool integration workflow."""
        mock_search.return_value = {
            "code": 200,
            "status": "OK",
            "result": {"hits": [{"ip": "1.1.1.1"}]}
        }

        tool = CensysTool()
        with patch("core.censys_client.CensysClient.is_configured", new=True):
            result = await tool.execute(target="1.1.1.1")
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["target"], "1.1.1.1")
            self.assertIn("data", result)


if __name__ == "__main__":
    unittest.main()
