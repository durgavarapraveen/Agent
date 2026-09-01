import unittest
from unittest.mock import MagicMock
from core.domain.request import CapturedRequest, ResponseData
from core.domain.identity import Identity, Role, AuthenticationState
from core.replay.identity_store import IdentityStore
from core.replay.session_manager import SessionManager
from core.replay.http_proxy import HttpProxy
from core.replay.replay_engine import ReplayEngine

class TestReplayEngine(unittest.TestCase):
    def setUp(self):
        self.store = IdentityStore()
        # Mock env vars
        import os
        os.environ["APP_USER_A_CREDENTIALS"] = "password123"
        
        self.identity_a = Identity(
            identity_id="user_a",
            label="User A",
            username_reference="user_a",
            role=Role.STANDARD
        )
        self.store.add_identity(self.identity_a)
        
        self.session_manager = SessionManager(self.store)
        
        # Mock Proxy
        self.proxy = HttpProxy()
        self.proxy.forward = MagicMock(return_value=ResponseData(status_code=200, body=b"OK"))
        
        self.engine = ReplayEngine(self.session_manager, self.proxy)

    def test_replay_with_identity(self):
        req = CapturedRequest(
            request_id="REQ-1",
            method="GET",
            url="https://api.com/users/me",
            full_headers={"Authorization": "Bearer old_token"},
            response=ResponseData(status_code=200)
        )
        
        replayed = self.engine.replay_request(req, self.identity_a)
        
        # Verify proxy was called
        self.proxy.forward.assert_called_once()
        
        # Verify identity swapped headers
        args, _ = self.proxy.forward.call_args
        forwarded_req = args[0]
        
        self.assertNotIn("Bearer old_token", forwarded_req.full_headers.values())
        self.assertEqual(forwarded_req.identity_id, "user_a")
        self.assertTrue(forwarded_req.session_id.strip() != "")

    def test_replay_with_modifications(self):
        req = CapturedRequest(
            request_id="REQ-2",
            method="POST",
            url="https://api.com/search?q=foo",
            body=b'{"name": "Alice"}',
            response=ResponseData(status_code=200)
        )
        
        mods = {
            "query": {"q": "bar"},
            "body": {"name": "Bob"}
        }
        
        self.engine.replay_with_modifications(req, self.identity_a, mods)
        
        args, _ = self.proxy.forward.call_args
        forwarded_req = args[0]
        
        self.assertIn("q=bar", forwarded_req.url)
        self.assertNotIn("q=foo", forwarded_req.url)
        
        self.assertIn(b'"name": "Bob"', forwarded_req.body)

if __name__ == '__main__':
    unittest.main()
