import json

class LocalTestApp:
    """
    Simulates a local web application for testing identity and authentication flows
    without spawning actual HTTP server threads that hang tests.
    """
    def __init__(self):
        # We model internal database state
        self.users = {
            "test_user_a": "passwordA123!",
            "test_user_b": "passwordB123!",
            "admin_user": "superSecretAdminPass!"
        }
        
    def handle_request(self, method: str, path: str, headers: dict = None, body: dict = None):
        """Simulates an HTTP request to the application."""
        headers = headers or {}
        body = body or {}
        
        # 1. Login Page (Form)
        if method == "GET" and path == "/login":
            return {
                "status": 200,
                "content": '<form><input type="password" name="pwd"><input type="hidden" name="csrf" value="real_csrf_123"></form>'
            }
            
        # 2. API Login (JWT)
        if method == "POST" and path == "/api/auth/login":
            user = body.get("username")
            pwd = body.get("password")
            if user in self.users and self.users[user] == pwd:
                return {
                    "status": 200,
                    "content": json.dumps({"token": f"jwt_for_{user}"}),
                    "headers": {"Content-Type": "application/json"}
                }
            return {"status": 401, "content": "Unauthorized"}
            
        # 3. SPA Login
        if method == "GET" and path == "/#/login":
            return {
                "status": 200,
                "content": '<html><div id="app">React.createElement()</div></html>'
            }
            
        if method == "POST" and path == "/api/spa/login":
            user = body.get("username")
            pwd = body.get("password")
            if user in self.users and self.users[user] == pwd:
                return {
                    "status": 200,
                    "content": '{"success": true}',
                    "headers": {"X-Auth-Token": f"spa_token_{user}", "X-CSRF-Token": f"csrf_{user}"}
                }
            return {"status": 401, "content": "Unauthorized"}
            
        # 4. Form Submission
        if method == "POST" and path == "/login":
            user = body.get("username")
            pwd = body.get("password")
            if user in self.users and self.users[user] == pwd:
                return {
                    "status": 302,
                    "content": "Redirecting...",
                    "cookies": {"session_id": f"cookie_for_{user}"}
                }
            return {"status": 401, "content": "Unauthorized"}
            
        return {"status": 404, "content": "Not Found"}
