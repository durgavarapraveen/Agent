import unittest
import os
import sys
import io
import logging

from core.identity.credential_store import CredentialStore
from core.identity.identity_manager import IdentityManager
from core.identity.session_manager import SessionManager
from core.identity.login_flow import LoginFlowEngine
from core.memory.shared_context_v2 import SharedContextV2
from tests.test_app import LocalTestApp

# Suppress debug logs for clean output in tests
logging.getLogger("core.identity").setLevel(logging.INFO)

class TestAutomatedAuthenticationPhase6(unittest.TestCase):

    def setUp(self):
        # Set environment variables for testing
        os.environ["APP_USER_A"] = "test_user_a"
        os.environ["APP_PASS_A"] = "passwordA123!"
        
        os.environ["APP_USER_B"] = "test_user_b"
        os.environ["APP_PASS_B"] = "passwordB123!"
        
        os.environ["APP_ADMIN"] = "admin_user"
        os.environ["APP_ADMIN_PASS"] = "superSecretAdminPass!"
        
        self.config = [
            {"id": "user_a", "role": "standard", "username_env": "APP_USER_A", "password_env": "APP_PASS_A"},
            {"id": "user_b", "role": "standard", "username_env": "APP_USER_B", "password_env": "APP_PASS_B"},
            {"id": "admin", "role": "administrator", "username_env": "APP_ADMIN", "password_env": "APP_ADMIN_PASS"}
        ]
        
        self.app = LocalTestApp()
        self.shared_context = SharedContextV2(target="http://localhost")
        self.credential_store = CredentialStore()
        self.session_manager = SessionManager(shared_context=self.shared_context)
        self.identity_manager = IdentityManager(self.credential_store, shared_context=self.shared_context)
        self.login_flow = LoginFlowEngine(self.credential_store, self.session_manager)
        
        # Override mock login logic in LoginFlowEngine to route through LocalTestApp
        self.login_flow._handle_form_login = self._mock_form_login
        self.login_flow._handle_jwt_login = self._mock_jwt_login
        self.login_flow._handle_spa_login = self._mock_spa_login

    def _mock_form_login(self, username, password):
        resp = self.app.handle_request("POST", "/login", body={"username": username, "password": password})
        if resp["status"] != 302: raise Exception("Invalid credentials")
        return __import__("core.identity.session_manager", fromlist=["SessionArtifact"]).SessionArtifact(
            identity_id="", cookies=resp["cookies"], csrf_tokens={"csrf_token": "real_csrf_123"}
        )

    def _mock_jwt_login(self, username, password):
        resp = self.app.handle_request("POST", "/api/auth/login", body={"username": username, "password": password})
        if resp["status"] != 200: raise Exception("Invalid credentials")
        token = __import__("json").loads(resp["content"])["token"]
        return __import__("core.identity.session_manager", fromlist=["SessionArtifact"]).SessionArtifact(
            identity_id="", headers={"Authorization": f"Bearer {token}"}, jwt_metadata={"token": token}
        )

    def _mock_spa_login(self, username, password):
        resp = self.app.handle_request("POST", "/api/spa/login", body={"username": username, "password": password})
        if resp["status"] != 200: raise Exception("Invalid credentials")
        return __import__("core.identity.session_manager", fromlist=["SessionArtifact"]).SessionArtifact(
            identity_id="", headers={"X-Auth-Token": resp["headers"]["X-Auth-Token"]}, csrf_tokens={"x-csrf-token": resp["headers"]["X-CSRF-Token"]}
        )

    def tearDown(self):
        # Clean up
        for key in ["APP_USER_A", "APP_PASS_A", "APP_USER_B", "APP_PASS_B", "APP_ADMIN", "APP_ADMIN_PASS"]:
            if key in os.environ:
                del os.environ[key]

    def test_identity_discovery_and_authentication(self):
        # Capture stdout to verify specific log output requirements
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        # 1. Identity Discovery
        self.identity_manager.load_identities(self.config)
        
        # 2. Authentication flow for each user
        users = ["user_a", "user_b", "admin"]
        urls = [
            "/login", # Maps to generic or form depending on content
            "/api/auth/login", # Maps to JWT
            "https://app.com/#/login" # Maps to SPA
        ]
        page_contents = [
            '<form><input type="password"></form>', # Form
            '{"status": "ok"}', # API
            'React.createElement()' # SPA
        ]
        
        for i, user_id in enumerate(users):
            identity = self.identity_manager.get_identity(user_id)
            self.assertIsNotNone(identity)
            
            # Fetch the page content via the local app mock
            init_resp = self.app.handle_request("GET", urls[i])
            
            # Ensure raw passwords are NOT in the identity object directly
            self.assertNotEqual(identity.password_ref, "passwordA123!")
            
            # Authenticate
            success = self.login_flow.authenticate(identity, target_url=urls[i], page_content=init_resp["content"])
            self.assertTrue(success)
            
            # Check session exists
            session = self.session_manager.get_session(user_id)
            self.assertIsNotNone(session)
            self.assertTrue(session.is_valid)
            
            # Test Validation & Refresh manually (for logging purposes)
            from core.identity.session_validator import SessionValidator
            from core.identity.session_refresh import SessionRefreshHandler
            validator = SessionValidator(self.session_manager)
            validator.is_valid(session)
            validator.is_valid(None) # Force expired log
            refresher = SessionRefreshHandler(self.session_manager)
            session.headers["Authorization"] = "Bearer real_token" # Fake a refreshable token
            refresher.refresh(user_id)

        # Force a LOGIN_FAILED log
        os.environ["BAD_USER"] = "bad"
        os.environ["BAD_PASS"] = "wrong"
        bad_identity = __import__("core.identity.identity_manager", fromlist=["Identity"]).Identity(
            id="bad", role="standard", 
            username_ref=self.credential_store.load_from_env("BAD_USER"),
            password_ref=self.credential_store.load_from_env("BAD_PASS")
        )
        self.login_flow.authenticate(bad_identity, target_url="/login", page_content='<form type="password"></form>')

        # 3. Verify exactly matching logs
        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        
        self.assertIn("IDENTITY_DISCOVERY count=3", output)
        self.assertIn("AUTH_FLOW_DISCOVERED", output)
        self.assertIn("LOGIN_ATTEMPT identity=user_a", output)
        self.assertIn("LOGIN_SUCCESS identity=user_a", output)
        self.assertIn("SESSION_CREATED count=1", output)
        self.assertIn("SESSION_VALIDATED identity=user_a", output)
        self.assertIn("SESSION_EXPIRED", output)
        self.assertIn("SESSION_REFRESHED", output)
        self.assertIn("LOGIN_FAILED", output)
        
        # Verify SharedContext
        self.assertIn("user_a", self.shared_context.identities)
        self.assertIn("user_a", self.shared_context.sessions)
        self.assertEqual(self.shared_context.auth_health_metrics["login_success"], 3)
        self.assertEqual(self.shared_context.auth_health_metrics["login_failed"], 1)

if __name__ == '__main__':
    unittest.main()
