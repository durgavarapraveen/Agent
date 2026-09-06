"""Login-response classifier tests (#096)."""
from __future__ import annotations

import pytest

from core.execution.executors.authentication import _classify_login_response


class TestLoginClassifier:
    def test_2xx_with_session_cookie_is_success(self):
        r = _classify_login_response(200, "<html>ok</html>", "session=abc123; Path=/")
        assert r["verdict"] == "SUCCESS"

    def test_2xx_with_signed_in_body_is_success(self):
        r = _classify_login_response(200, "<h1>Welcome, alice</h1><a href='/logout'>Logout</a>", "")
        assert r["verdict"] == "SUCCESS"

    def test_2xx_with_wrong_password_message_is_failure(self):
        r = _classify_login_response(200, "<p>Invalid credentials, try again</p>", "")
        assert r["verdict"] == "FAILURE"

    def test_2xx_with_no_markers_is_inconclusive(self):
        r = _classify_login_response(200, "<html><body></body></html>", "")
        assert r["verdict"] == "INCONCLUSIVE"

    def test_403_is_failure(self):
        r = _classify_login_response(403, "", "")
        assert r["verdict"] == "FAILURE"

    def test_500_is_failure(self):
        r = _classify_login_response(500, "<h1>error</h1>", "")
        assert r["verdict"] == "FAILURE"

    def test_login_failed_message_beats_ambiguous_status(self):
        r = _classify_login_response(200, "<div>Login failed</div>", "sess=abc")
        # Explicit failure marker wins over the session-cookie signal.
        assert r["verdict"] == "FAILURE"

    def test_dashboard_marker(self):
        r = _classify_login_response(200, "<h1>Dashboard</h1>", "")
        assert r["verdict"] == "SUCCESS"
