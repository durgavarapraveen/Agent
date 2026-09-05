import unittest
import sys
import io

from core.access_control.matrix_engine import MatrixEngine
from core.identity.identity_manager import Identity
from core.memory.shared_context import SharedContextV2

class MockRequestReplayer:
    def replay(self, request_node, identity_id=None):
        path = request_node.get("path")
        
        # 1. Secure Endpoint: /api/secure/data
        if path == "/api/secure/data":
            if identity_id == "user_a":
                return {"status": 200, "body": '{"data": "a"}'}
            elif identity_id == "user_b":
                return {"status": 403, "body": 'Forbidden'}
            elif identity_id == "admin":
                return {"status": 200, "body": '{"data": "a"}'}
            elif identity_id is None:
                return {"status": 401, "body": 'Unauthorized'}
                
        # 2. Vulnerable IDOR Endpoint: /api/users/1
        if path.startswith("/api/users/"):
            if identity_id is None:
                return {"status": 401, "body": 'Unauthorized'}
            # Anyone authenticated gets a 200 (IDOR vulnerability) - returns real data
            return {"status": 200, "body": '{"sensitive": "data", "id": 1, "email": "a@b.com"}'}
            
        # 3. Candidate IDOR Endpoint: /api/orders/2
        if path.startswith("/api/orders/"):
            if identity_id is None:
                return {"status": 401, "body": 'Unauthorized'}
            # Returns 200 but body is empty or generic
            return {"status": 200, "body": '{"ok": 1}'}
            
        return {"status": 404, "body": "Not Found"}

class TestAccessControl(unittest.TestCase):
    def setUp(self):
        self.identities = {
            "user_a": Identity(id="user_a", role="standard", username_ref=None, password_ref=None),
            "user_b": Identity(id="user_b", role="standard", username_ref=None, password_ref=None),
            "admin": Identity(id="admin", role="administrator", username_ref=None, password_ref=None),
        }
        self.replayer = MockRequestReplayer()
        self.shared_context = SharedContextV2(target="http://localhost")
        self.engine = MatrixEngine(self.replayer, self.identities, shared_context=self.shared_context)

    def test_secure_endpoint_matrix(self):
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        request = {"method": "GET", "path": "/api/secure/data"}
        self.engine.analyze(request)
        
        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        
        # Verify Secure Matrix logs
        self.assertIn("AUTHORIZATION_TEST_STARTED", output)
        self.assertIn("AUTHORIZATION_MATRIX_CREATED", output)
        self.assertIn("AUTHORIZATION_TEST_COMPLETED", output)
        
        self.assertIn("AUTHORIZATION_MATRIX", output)
        self.assertIn("endpoint=/api/secure/data", output)
        self.assertIn("user_a=200", output)
        self.assertIn("user_b=403", output)
        self.assertIn("admin=200", output)
        self.assertIn("anonymous=401", output)
        self.assertIn("IDOR=REJECTED", output)
        
    def test_vulnerable_idor_validated(self):
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        request = {"method": "GET", "path": "/api/users/1"}
        self.engine.analyze(request)
        
        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        
        # Verify IDOR Matrix
        self.assertIn("AUTHORIZATION_MATRIX_CREATED", output)
        self.assertIn("endpoint=/api/users/1", output)
        self.assertIn("user_a=200", output)
        self.assertIn("user_b=200", output) # Horizontal escalation successful
        self.assertIn("IDOR=VULNERABLE", output)
        self.assertIn("IDOR_VALIDATED", output)
        self.assertIn("PRIVILEGE_ESCALATION_CANDIDATE", output)
        self.assertIn("cross_user_access=true", output)
        
    def test_idor_candidate_only(self):
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        request = {"method": "GET", "path": "/api/orders/2"}
        self.engine.analyze(request)
        
        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        
        # Verify it stops at CANDIDATE due to generic body
        self.assertIn("IDOR=CANDIDATE", output)
        self.assertIn("IDOR_CANDIDATE", output)
        self.assertNotIn("IDOR_VALIDATED", output)
        
        # Verify SharedContext
        self.assertIn("/api/orders/2", self.shared_context.authorization_coverage)
        self.assertEqual(self.shared_context.authorization_coverage["/api/orders/2"]["idor"], "CANDIDATE")

if __name__ == '__main__':
    unittest.main()
