"""
Security Test Catalog (Phase 9).

Expanded from 44 tests toward 200+ concrete, executable, evidence-backed tests.
Tests are only applicable when the target actually exposes the relevant attack surface.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class SecurityTest:
    test_id: str
    name: str
    attack_type: str
    description: str
    cwe: str = ""
    applicable_to: Callable[..., bool] = field(default_factory=lambda: lambda **kw: True)
    target_type: str = "endpoint"
    prerequisites: List[str] = field(default_factory=list)
    required_identity: str = ""
    capability: str = ""
    inputs: Dict[str, Any] = field(default_factory=dict)
    expected_signals: List[str] = field(default_factory=list)
    evidence_requirements: List[str] = field(default_factory=list)
    oracle: str = ""
    risk: str = "low"
    cost: str = "low"
    priority: int = 5


class SecurityTestCatalog:

    def __init__(self) -> None:
        self._tests: Dict[str, SecurityTest] = {}

    def register(self, test: SecurityTest) -> None:
        self._tests[test.test_id] = test

    def get(self, test_id: str) -> Optional[SecurityTest]:
        return self._tests.get(test_id)

    def list_by_category(self, category: str) -> List[SecurityTest]:
        return [t for t in self._tests.values() if t.attack_type == category]

    def list_all(self) -> List[SecurityTest]:
        return list(self._tests.values())

    def count(self) -> int:
        return len(self._tests)

    def categories(self) -> List[str]:
        return sorted(set(t.attack_type for t in self._tests.values()))


# --- Applicability predicates ---

def _has_input(**kw: Any) -> bool:
    return len(kw.get("parameters", [])) > 0

def _has_url_param_and_html(**kw: Any) -> bool:
    params = kw.get("parameters", [])
    ct = kw.get("content_type", "text/html")
    has_param = any(p.get("location") in ("query", "url", "path") for p in params) if params else len(params) > 0
    return has_param and "html" in ct.lower()

def _has_post_param(**kw: Any) -> bool:
    params = kw.get("parameters", [])
    return any(p.get("location") in ("body", "form", "json") for p in params)

def _has_object_id_and_identities(**kw: Any) -> bool:
    path = kw.get("path", "")
    identities = kw.get("identities", [])
    return ("{id}" in path or "{" in path) and len(identities) > 1

def _is_authenticated_multi_role(**kw: Any) -> bool:
    return kw.get("auth_required", False) and len(kw.get("identities", [])) > 1

def _has_url_param(**kw: Any) -> bool:
    params = kw.get("parameters", [])
    return any("url" in p.get("name", "").lower() or "resource" in p.get("name", "").lower() for p in params)

def _has_multipart(**kw: Any) -> bool:
    return "multipart" in kw.get("content_type", "").lower()

def _always(**kw: Any) -> bool:
    return True

def _has_jwt(**kw: Any) -> bool:
    return kw.get("has_jwt", False)

def _has_graphql(**kw: Any) -> bool:
    return kw.get("has_graphql", False)

def _has_websocket(**kw: Any) -> bool:
    return kw.get("has_websocket", False)

def _has_xml_input(**kw: Any) -> bool:
    ct = kw.get("content_type", "")
    return "xml" in ct.lower()

def _has_json_input(**kw: Any) -> bool:
    ct = kw.get("content_type", "")
    params = kw.get("parameters", [])
    return "json" in ct.lower() or any(p.get("location") == "json" for p in params)

def _is_authenticated(**kw: Any) -> bool:
    return kw.get("auth_required", False)

def _has_cookie(**kw: Any) -> bool:
    return kw.get("has_cookies", False)

def _has_state_change(**kw: Any) -> bool:
    method = kw.get("method", "GET").upper()
    return method in ("POST", "PUT", "PATCH", "DELETE")

def _has_login(**kw: Any) -> bool:
    return kw.get("has_login", False)

def _has_api(**kw: Any) -> bool:
    path = kw.get("path", "")
    return "/api/" in path or "/rest/" in path or "/v1/" in path or "/v2/" in path

def _has_file_param(**kw: Any) -> bool:
    params = kw.get("parameters", [])
    return any(p.get("name", "").lower() in ("file", "filename", "upload", "attachment", "document", "image") for p in params)

def _has_redirect(**kw: Any) -> bool:
    params = kw.get("parameters", [])
    return any(p.get("name", "").lower() in ("redirect", "return", "next", "url", "goto", "target", "dest", "continue", "returnurl", "redirect_uri") for p in params)

def _has_email_param(**kw: Any) -> bool:
    params = kw.get("parameters", [])
    return any("email" in p.get("name", "").lower() or "mail" in p.get("name", "").lower() for p in params)

def _has_search(**kw: Any) -> bool:
    params = kw.get("parameters", [])
    return any(p.get("name", "").lower() in ("q", "query", "search", "keyword", "term", "s") for p in params)

def _has_numeric_id(**kw: Any) -> bool:
    path = kw.get("path", "")
    import re
    return bool(re.search(r'/\d+', path) or '{id}' in path or '{' in path)

def _has_header_injection_surface(**kw: Any) -> bool:
    params = kw.get("parameters", [])
    return any(p.get("location") in ("header", "cookie") for p in params) or _has_input(**kw)

def _has_archive_upload(**kw: Any) -> bool:
    return _has_multipart(**kw)

def _has_otp(**kw: Any) -> bool:
    return kw.get("has_otp", False) or kw.get("has_mfa", False)


def build_default_catalog() -> SecurityTestCatalog:
    catalog = SecurityTestCatalog()
    tests = [
        # ═══════════════════════════════════════════
        # AUTHENTICATION (13 tests)
        # ═══════════════════════════════════════════
        SecurityTest("auth_login_01", "Login Brute Force", "authentication",
                     "Test login endpoint against credential lists", "CWE-307", _has_login,
                     risk="medium", priority=7),
        SecurityTest("auth_session_hijack_01", "Session Hijacking", "authentication",
                     "Test session token predictability and fixation", "CWE-384", _has_cookie),
        SecurityTest("auth_credential_stuffing_01", "Credential Stuffing", "authentication",
                     "Test with known breached credentials", "CWE-521", _has_login),
        SecurityTest("auth_default_creds_01", "Default Credentials", "authentication",
                     "Test for default admin credentials", "CWE-798", _has_login, priority=8),
        SecurityTest("auth_password_policy_01", "Weak Password Policy", "authentication",
                     "Test password complexity requirements", "CWE-521", _has_login),
        SecurityTest("auth_username_enum_01", "Username Enumeration", "authentication",
                     "Detect different responses for valid/invalid usernames", "CWE-204", _has_login),
        SecurityTest("auth_account_lockout_01", "Account Lockout", "authentication",
                     "Test account lockout after failed attempts", "CWE-307", _has_login),
        SecurityTest("auth_remember_me_01", "Remember Me Token", "authentication",
                     "Test remember-me cookie security", "CWE-613", _has_cookie),
        SecurityTest("auth_logout_01", "Logout Invalidation", "authentication",
                     "Test session invalidation on logout", "CWE-613", _is_authenticated),
        SecurityTest("auth_session_fixation_01", "Session Fixation", "authentication",
                     "Test for session fixation vulnerability", "CWE-384", _has_cookie),
        SecurityTest("auth_session_expiry_01", "Session Expiration", "authentication",
                     "Test session timeout and expiration", "CWE-613", _is_authenticated),
        SecurityTest("auth_concurrent_sessions_01", "Concurrent Sessions", "authentication",
                     "Test concurrent session handling", "CWE-613", _is_authenticated),
        SecurityTest("auth_password_reset_01", "Password Reset Flow", "authentication",
                     "Test password reset token security", "CWE-640", _has_login),

        # ═══════════════════════════════════════════
        # AUTHORIZATION (12 tests)
        # ═══════════════════════════════════════════
        SecurityTest("authz_idor_01", "IDOR Basic", "authorization",
                     "Access another user's resource by changing ID", "CWE-639",
                     _has_object_id_and_identities, risk="high", priority=9),
        SecurityTest("authz_priv_esc_01", "Privilege Escalation", "authorization",
                     "Access admin functions as regular user", "CWE-269",
                     _is_authenticated_multi_role, risk="high", priority=9),
        SecurityTest("authz_horizontal_01", "Horizontal Access Control", "authorization",
                     "Access peer user's data", "CWE-639", _has_object_id_and_identities),
        SecurityTest("authz_forced_browsing_01", "Forced Browsing", "authorization",
                     "Access unlinked admin pages directly", "CWE-425", _always),
        SecurityTest("authz_object_level_01", "Object-Level Authorization", "authorization",
                     "BOLA — access objects by ID manipulation", "CWE-639",
                     _has_object_id_and_identities, risk="high"),
        SecurityTest("authz_function_level_01", "Function-Level Authorization", "authorization",
                     "Access admin API endpoints as regular user", "CWE-285",
                     _is_authenticated_multi_role),
        SecurityTest("authz_api_auth_01", "API Authorization", "authorization",
                     "Test API key/token authorization boundaries", "CWE-862", _has_api),
        SecurityTest("authz_hidden_endpoint_01", "Hidden Endpoint Access", "authorization",
                     "Access undocumented admin/debug endpoints", "CWE-425", _always),
        SecurityTest("authz_role_boundary_01", "Role Boundary Test", "authorization",
                     "Test actions across role boundaries", "CWE-269",
                     _is_authenticated_multi_role),
        SecurityTest("authz_mass_assignment_01", "Mass Assignment", "authorization",
                     "Modify restricted fields via mass assignment", "CWE-915",
                     _has_json_input, risk="high"),
        SecurityTest("authz_method_tampering_01", "HTTP Method Tampering", "authorization",
                     "Bypass auth via method override (GET→PUT)", "CWE-650", _is_authenticated),
        SecurityTest("authz_parameter_pollution_01", "Parameter Pollution", "authorization",
                     "Duplicate parameter to bypass authorization", "CWE-235", _has_input),

        # ═══════════════════════════════════════════
        # SQL INJECTION (8 tests)
        # ═══════════════════════════════════════════
        SecurityTest("sqli_basic_01", "SQL Injection Basic", "sqli",
                     "Basic SQL injection with single quote", "CWE-89", _has_input,
                     risk="high", priority=9),
        SecurityTest("sqli_time_based_01", "SQL Injection Time-Based", "sqli",
                     "Time-based blind SQL injection", "CWE-89", _has_input, cost="medium"),
        SecurityTest("sqli_error_based_01", "SQL Injection Error-Based", "sqli",
                     "Error-based SQL injection extraction", "CWE-89", _has_input),
        SecurityTest("sqli_union_01", "SQL Injection UNION", "sqli",
                     "UNION-based SQL injection", "CWE-89", _has_input),
        SecurityTest("sqli_stacked_01", "SQL Injection Stacked", "sqli",
                     "Stacked queries SQL injection", "CWE-89", _has_input, risk="high"),
        SecurityTest("sqli_second_order_01", "Second-Order SQL Injection", "sqli",
                     "SQL injection via stored data re-use", "CWE-89", _has_input, cost="high"),
        SecurityTest("sqli_header_01", "SQL Injection via Headers", "sqli",
                     "Injection through User-Agent/Referer/X-Forwarded-For", "CWE-89", _always),
        SecurityTest("sqli_json_01", "SQL Injection in JSON Body", "sqli",
                     "Injection in JSON parameter values", "CWE-89", _has_json_input),

        # ═══════════════════════════════════════════
        # NOSQL INJECTION (4 tests)
        # ═══════════════════════════════════════════
        SecurityTest("nosqli_basic_01", "NoSQL Injection", "nosqli",
                     "MongoDB/NoSQL operator injection", "CWE-943", _has_input),
        SecurityTest("nosqli_logical_01", "NoSQL Logical Operators", "nosqli",
                     "Injection via $gt, $ne operators", "CWE-943", _has_json_input),
        SecurityTest("nosqli_regex_01", "NoSQL Regex DoS", "nosqli",
                     "ReDoS via MongoDB $regex operator", "CWE-1333", _has_json_input),
        SecurityTest("nosqli_js_01", "NoSQL JavaScript Injection", "nosqli",
                     "Injection via $where JavaScript", "CWE-943", _has_json_input),

        # ═══════════════════════════════════════════
        # XSS (10 tests)
        # ═══════════════════════════════════════════
        SecurityTest("xss_reflected_01", "XSS Reflected", "xss",
                     "Reflected cross-site scripting", "CWE-79",
                     _has_url_param_and_html, priority=8),
        SecurityTest("xss_stored_01", "XSS Stored", "xss",
                     "Stored cross-site scripting", "CWE-79", _has_post_param,
                     risk="high", priority=9),
        SecurityTest("xss_dom_01", "XSS DOM-Based", "xss",
                     "DOM-based cross-site scripting", "CWE-79", _has_url_param_and_html),
        SecurityTest("xss_attribute_ctx_01", "XSS Attribute Context", "xss",
                     "XSS in HTML attribute context", "CWE-79", _has_input),
        SecurityTest("xss_js_ctx_01", "XSS JavaScript Context", "xss",
                     "XSS in inline JavaScript context", "CWE-79", _has_input),
        SecurityTest("xss_url_ctx_01", "XSS URL Context", "xss",
                     "XSS via javascript: in href/src attributes", "CWE-79", _has_input),
        SecurityTest("xss_encoded_01", "XSS Encoded Payloads", "xss",
                     "XSS using URL/HTML/Unicode encoding", "CWE-79", _has_input),
        SecurityTest("xss_svg_01", "XSS via SVG", "xss",
                     "XSS through SVG upload/injection", "CWE-79", _has_multipart),
        SecurityTest("xss_event_handler_01", "XSS Event Handlers", "xss",
                     "XSS via event handler attributes (onerror/onload)", "CWE-79", _has_input),
        SecurityTest("xss_mutation_01", "XSS Mutation", "xss",
                     "mXSS via browser HTML parsing quirks", "CWE-79", _has_input),

        # ═══════════════════════════════════════════
        # TEMPLATE INJECTION (3 tests)
        # ═══════════════════════════════════════════
        SecurityTest("ssti_basic_01", "Server-Side Template Injection", "ssti",
                     "Template injection via user input", "CWE-1336", _has_input, risk="high"),
        SecurityTest("ssti_jinja2_01", "SSTI Jinja2", "ssti",
                     "Jinja2-specific template injection", "CWE-1336", _has_input),
        SecurityTest("ssti_detection_01", "SSTI Detection", "ssti",
                     "Detect template engine via math expressions", "CWE-1336", _has_input),

        # ═══════════════════════════════════════════
        # COMMAND INJECTION (4 tests)
        # ═══════════════════════════════════════════
        SecurityTest("cmdi_basic_01", "Command Injection", "command_injection",
                     "OS command injection via user input", "CWE-78", _has_input, risk="critical"),
        SecurityTest("cmdi_blind_01", "Blind Command Injection", "command_injection",
                     "Blind OS command injection via time delay", "CWE-78", _has_input),
        SecurityTest("cmdi_chained_01", "Chained Command Injection", "command_injection",
                     "Command injection via semicolons/pipes", "CWE-78", _has_input),
        SecurityTest("cmdi_substitution_01", "Command Substitution", "command_injection",
                     "Command injection via $()/backticks", "CWE-78", _has_input),

        # ═══════════════════════════════════════════
        # PATH/FILE (8 tests)
        # ═══════════════════════════════════════════
        SecurityTest("path_traversal_01", "Path Traversal", "path_traversal",
                     "Directory traversal via ../ sequences", "CWE-22", _has_input),
        SecurityTest("path_directory_01", "Directory Listing", "path_traversal",
                     "Exposed directory listings", "CWE-548", _always),
        SecurityTest("path_lfi_01", "Local File Inclusion", "path_traversal",
                     "Include local files via parameter", "CWE-98", _has_input, risk="high"),
        SecurityTest("path_null_byte_01", "Null Byte Injection", "path_traversal",
                     "Bypass extension check via null byte", "CWE-158", _has_input),
        SecurityTest("path_sensitive_files_01", "Sensitive File Exposure", "path_traversal",
                     "Check for .env, .git, backups, configs", "CWE-538", _always, priority=7),
        SecurityTest("path_backup_files_01", "Backup File Discovery", "path_traversal",
                     "Find .bak, .old, .swp, ~ files", "CWE-530", _always),

        SecurityTest("upload_type_01", "File Upload Type Validation", "file_upload",
                     "Bypass file type restrictions", "CWE-434", _has_multipart),
        SecurityTest("upload_rce_01", "File Upload RCE", "file_upload",
                     "Upload web shell for remote code execution", "CWE-434",
                     _has_multipart, risk="critical"),

        # ═══════════════════════════════════════════
        # SSRF (4 tests)
        # ═══════════════════════════════════════════
        SecurityTest("ssrf_basic_01", "SSRF Basic", "ssrf",
                     "Server-side request forgery", "CWE-918", _has_url_param, risk="high"),
        SecurityTest("ssrf_cloud_01", "SSRF Cloud Metadata", "ssrf",
                     "SSRF targeting cloud metadata endpoints", "CWE-918", _has_url_param),
        SecurityTest("ssrf_redirect_01", "SSRF via Redirect", "ssrf",
                     "SSRF bypassing allow-list via redirect", "CWE-918", _has_url_param),
        SecurityTest("ssrf_dns_rebind_01", "SSRF DNS Rebinding", "ssrf",
                     "SSRF via DNS rebinding attack", "CWE-918", _has_url_param),

        # ═══════════════════════════════════════════
        # XXE (3 tests)
        # ═══════════════════════════════════════════
        SecurityTest("xxe_basic_01", "XML External Entity", "xxe",
                     "XXE injection via XML input", "CWE-611", _has_xml_input, risk="high"),
        SecurityTest("xxe_oob_01", "XXE Out-of-Band", "xxe",
                     "OOB XXE via external DTD", "CWE-611", _has_xml_input),
        SecurityTest("xxe_ssrf_01", "XXE to SSRF", "xxe",
                     "XXE chained to internal SSRF", "CWE-611", _has_xml_input),

        # ═══════════════════════════════════════════
        # CSRF (5 tests)
        # ═══════════════════════════════════════════
        SecurityTest("csrf_token_01", "CSRF Token Validation", "csrf",
                     "Missing or weak CSRF token validation", "CWE-352", _has_state_change),
        SecurityTest("csrf_samesite_01", "CSRF SameSite Cookie", "csrf",
                     "Test SameSite cookie attribute", "CWE-1275", _has_cookie),
        SecurityTest("csrf_origin_01", "CSRF Origin Validation", "csrf",
                     "Test Origin/Referer header validation", "CWE-346", _has_state_change),
        SecurityTest("csrf_method_override_01", "CSRF Method Override", "csrf",
                     "Bypass CSRF via method override header", "CWE-352", _has_state_change),
        SecurityTest("csrf_json_01", "CSRF JSON Content-Type", "csrf",
                     "CSRF with JSON content-type", "CWE-352", _has_json_input),

        # ═══════════════════════════════════════════
        # CORS (4 tests)
        # ═══════════════════════════════════════════
        SecurityTest("cors_misconfig_01", "CORS Misconfiguration", "cors",
                     "Overly permissive CORS headers", "CWE-942", _always),
        SecurityTest("cors_wildcard_01", "CORS Wildcard Origin", "cors",
                     "CORS with wildcard origin and credentials", "CWE-942", _always),
        SecurityTest("cors_reflected_01", "CORS Reflected Origin", "cors",
                     "Origin header reflected in Access-Control-Allow-Origin", "CWE-942", _always),
        SecurityTest("cors_null_origin_01", "CORS Null Origin", "cors",
                     "CORS allows null origin with credentials", "CWE-942", _always),

        # ═══════════════════════════════════════════
        # API SECURITY (12 tests)
        # ═══════════════════════════════════════════
        SecurityTest("api_excessive_data_01", "Excessive Data Exposure", "api",
                     "API returns more data than needed", "CWE-213", _has_api),
        SecurityTest("api_rate_limit_01", "API Rate Limiting", "api",
                     "Test API rate limiting controls", "CWE-770", _has_api),
        SecurityTest("api_content_type_01", "Content-Type Confusion", "api",
                     "Send unexpected content types to API", "CWE-436", _has_api),
        SecurityTest("api_version_01", "API Version Discovery", "api",
                     "Enumerate API versions for older unpatched versions", "CWE-1059", _has_api),
        SecurityTest("api_pagination_01", "API Pagination Abuse", "api",
                     "Excessive pagination to extract all data", "CWE-770", _has_api),
        SecurityTest("api_batch_01", "API Batch Request Abuse", "api",
                     "Abuse batch endpoints for amplification", "CWE-770", _has_api),
        SecurityTest("api_graphql_introspection_01", "GraphQL Introspection", "graphql",
                     "Query __schema for full API surface", "CWE-200", _has_graphql),
        SecurityTest("api_graphql_mutation_01", "GraphQL Mutation Abuse", "graphql",
                     "Unauthorized mutations via GraphQL", "CWE-862", _has_graphql),
        SecurityTest("api_graphql_dos_01", "GraphQL DoS", "graphql",
                     "Deeply nested query denial of service", "CWE-400", _has_graphql),
        SecurityTest("api_graphql_batching_01", "GraphQL Query Batching", "graphql",
                     "Abuse query batching for brute force", "CWE-307", _has_graphql),
        SecurityTest("api_ws_hijack_01", "WebSocket Hijacking", "websocket",
                     "Cross-site WebSocket hijacking", "CWE-1385", _has_websocket),
        SecurityTest("api_ws_auth_01", "WebSocket Auth", "websocket",
                     "Test WebSocket authentication enforcement", "CWE-306", _has_websocket),

        # ═══════════════════════════════════════════
        # BUSINESS LOGIC (10 tests)
        # ═══════════════════════════════════════════
        SecurityTest("biz_price_manipulation_01", "Price Manipulation", "business_logic",
                     "Modify price/amount in client-side requests", "CWE-472",
                     _has_state_change, risk="high"),
        SecurityTest("biz_quantity_01", "Quantity Manipulation", "business_logic",
                     "Set negative/zero quantity in orders", "CWE-472", _has_state_change),
        SecurityTest("biz_workflow_bypass_01", "Workflow Bypass", "business_logic",
                     "Skip required steps in multi-step process", "CWE-841", _has_state_change),
        SecurityTest("biz_replay_01", "Replay Attack", "business_logic",
                     "Replay valid requests to duplicate actions", "CWE-294", _has_state_change),
        SecurityTest("race_condition_01", "Race Condition", "business_logic",
                     "Exploit TOCTOU race conditions", "CWE-362", _has_state_change),
        SecurityTest("biz_coupon_abuse_01", "Coupon/Discount Abuse", "business_logic",
                     "Apply coupons multiple times or stack", "CWE-840", _has_state_change),
        SecurityTest("biz_state_abuse_01", "State Transition Abuse", "business_logic",
                     "Skip/reverse state transitions", "CWE-841", _has_state_change),
        SecurityTest("biz_privilege_workflow_01", "Privilege Workflow Abuse", "business_logic",
                     "Escalate privileges via workflow manipulation", "CWE-269",
                     _is_authenticated),
        SecurityTest("biz_negative_testing_01", "Negative Value Testing", "business_logic",
                     "Submit negative values for amounts/quantities", "CWE-20", _has_input),
        SecurityTest("biz_time_manipulation_01", "Time-Based Manipulation", "business_logic",
                     "Manipulate date/time parameters for abuse", "CWE-807", _has_input),

        # ═══════════════════════════════════════════
        # CLIENT-SIDE (8 tests)
        # ═══════════════════════════════════════════
        SecurityTest("client_dom_sink_01", "DOM Sink Analysis", "client_side",
                     "Identify dangerous DOM sinks (innerHTML, eval)", "CWE-79", _always),
        SecurityTest("client_postmessage_01", "postMessage Handler", "client_side",
                     "Test postMessage origin validation", "CWE-345", _always),
        SecurityTest("client_localstorage_01", "LocalStorage Token Exposure", "client_side",
                     "Sensitive tokens stored in localStorage", "CWE-922", _always),
        SecurityTest("client_js_sourcemap_01", "JavaScript Source Maps", "client_side",
                     "Exposed source maps leaking source code", "CWE-540", _always),
        SecurityTest("client_url_handling_01", "Dangerous URL Handling", "client_side",
                     "Client-side URL parsing vulnerabilities", "CWE-601", _always),
        SecurityTest("client_auth_bypass_01", "Client-Side Auth Check", "client_side",
                     "Authorization enforced only client-side", "CWE-602",
                     _is_authenticated),
        SecurityTest("client_prototype_01", "Prototype Pollution", "client_side",
                     "JavaScript prototype pollution via __proto__", "CWE-1321", _has_json_input),
        SecurityTest("client_csp_01", "CSP Analysis", "client_side",
                     "Content Security Policy weakness analysis", "CWE-1021", _always),

        # ═══════════════════════════════════════════
        # JWT (5 tests)
        # ═══════════════════════════════════════════
        SecurityTest("jwt_manipulation_01", "JWT Manipulation", "jwt",
                     "Modify JWT claims without re-signing", "CWE-345", _has_jwt),
        SecurityTest("jwt_algo_confusion_01", "JWT Algorithm Confusion", "jwt",
                     "Switch RS256 to HS256 with public key", "CWE-327", _has_jwt),
        SecurityTest("jwt_none_algo_01", "JWT None Algorithm", "jwt",
                     "Set algorithm to none to bypass validation", "CWE-327", _has_jwt),
        SecurityTest("jwt_expiry_01", "JWT Expiration", "jwt",
                     "Test JWT expiration enforcement", "CWE-613", _has_jwt),
        SecurityTest("jwt_jwk_injection_01", "JWT JWK Injection", "jwt",
                     "Inject JWK in JWT header", "CWE-347", _has_jwt),

        # ═══════════════════════════════════════════
        # HEADERS & MISCONFIGURATION (12 tests)
        # ═══════════════════════════════════════════
        SecurityTest("header_injection_01", "HTTP Header Injection", "header_injection",
                     "CRLF injection in HTTP headers", "CWE-113", _has_input),
        SecurityTest("header_host_01", "Host Header Injection", "header_injection",
                     "Host header manipulation for cache poisoning", "CWE-644", _always),
        SecurityTest("open_redirect_01", "Open Redirect", "open_redirect",
                     "Redirect to attacker-controlled domain", "CWE-601", _has_url_param),
        SecurityTest("info_disclosure_01", "Information Disclosure", "info_disclosure",
                     "Sensitive data in error messages or headers", "CWE-200", _always),
        SecurityTest("info_stack_trace_01", "Stack Trace Leakage", "info_disclosure",
                     "Stack traces in error responses", "CWE-209", _always),
        SecurityTest("info_debug_endpoint_01", "Debug Endpoint", "info_disclosure",
                     "Exposed debug/profiling endpoints", "CWE-489", _always),
        SecurityTest("info_version_header_01", "Server Version Exposure", "info_disclosure",
                     "Server/framework version in headers", "CWE-200", _always),
        SecurityTest("config_hsts_01", "Missing HSTS", "misconfiguration",
                     "Missing Strict-Transport-Security header", "CWE-319", _always),
        SecurityTest("config_xframe_01", "Missing X-Frame-Options", "misconfiguration",
                     "Missing clickjacking protection", "CWE-1021", _always),
        SecurityTest("config_csp_01", "Missing/Weak CSP", "misconfiguration",
                     "Missing or weak Content-Security-Policy", "CWE-1021", _always),
        SecurityTest("config_cookie_flags_01", "Insecure Cookie Flags", "misconfiguration",
                     "Missing Secure/HttpOnly/SameSite flags", "CWE-614", _has_cookie),
        SecurityTest("config_tls_01", "TLS Configuration", "misconfiguration",
                     "Weak TLS versions/ciphers", "CWE-326", _always),

        # ═══════════════════════════════════════════
        # LDAP / XPATH / EXPRESSION LANGUAGE (3 tests)
        # ═══════════════════════════════════════════
        SecurityTest("ldap_injection_01", "LDAP Injection", "ldap",
                     "LDAP query injection", "CWE-90", _has_input),
        SecurityTest("xpath_injection_01", "XPath Injection", "xpath",
                     "XPath query injection", "CWE-643", _has_xml_input),
        SecurityTest("el_injection_01", "Expression Language Injection", "expression_language",
                     "Java EL / OGNL injection", "CWE-917", _has_input),

        # ═══════════════════════════════════════════
        # DESERIALIZATION (3 tests)
        # ═══════════════════════════════════════════
        SecurityTest("deser_java_01", "Java Deserialization", "deserialization",
                     "Java object deserialization RCE", "CWE-502", _has_input, risk="critical"),
        SecurityTest("deser_php_01", "PHP Object Injection", "deserialization",
                     "PHP unserialize() object injection", "CWE-502", _has_input),
        SecurityTest("deser_python_01", "Python Pickle Injection", "deserialization",
                     "Python pickle deserialization RCE", "CWE-502", _has_input),

        # ═══════════════════════════════════════════
        # CACHE POISONING (3 tests)
        # ═══════════════════════════════════════════
        SecurityTest("cache_poison_01", "Web Cache Poisoning", "cache_poisoning",
                     "Poison web cache with unkeyed headers", "CWE-444", _always),
        SecurityTest("cache_deception_01", "Web Cache Deception", "cache_poisoning",
                     "Force caching of authenticated responses", "CWE-525", _is_authenticated),
        SecurityTest("cache_key_01", "Cache Key Normalization", "cache_poisoning",
                     "Exploit cache key normalization differences", "CWE-444", _always),

        # ═══════════════════════════════════════════
        # HTTP SMUGGLING (3 tests)
        # ═══════════════════════════════════════════
        SecurityTest("smuggle_clte_01", "HTTP Smuggling CL.TE", "http_smuggling",
                     "Content-Length / Transfer-Encoding desync", "CWE-444", _always,
                     risk="high"),
        SecurityTest("smuggle_tecl_01", "HTTP Smuggling TE.CL", "http_smuggling",
                     "Transfer-Encoding / Content-Length desync", "CWE-444", _always),
        SecurityTest("smuggle_te_te_01", "HTTP Smuggling TE.TE", "http_smuggling",
                     "Obfuscated Transfer-Encoding desync", "CWE-444", _always),

        # ═══════════════════════════════════════════
        # SUBDOMAIN / DNS (4 tests)
        # ═══════════════════════════════════════════
        SecurityTest("dns_takeover_01", "Subdomain Takeover", "dns",
                     "Dangling CNAME pointing to unclaimed service", "CWE-1395", _always,
                     risk="high", priority=8),
        SecurityTest("dns_zone_transfer_01", "DNS Zone Transfer", "dns",
                     "Attempt AXFR zone transfer", "CWE-200", _always),
        SecurityTest("dns_wildcard_01", "DNS Wildcard Detection", "dns",
                     "Detect wildcard DNS for false positive suppression", "CWE-200", _always),
        SecurityTest("dns_email_spf_01", "SPF/DKIM/DMARC Check", "dns",
                     "Email spoofing via missing DNS records", "CWE-290", _always),

        # ═══════════════════════════════════════════
        # MFA / OTP (6 tests)
        # ═══════════════════════════════════════════
        SecurityTest("mfa_bypass_01", "MFA Bypass via Direct Access", "authentication",
                     "Access protected resource without completing MFA step", "CWE-287",
                     _has_otp, risk="high", priority=8),
        SecurityTest("mfa_otp_brute_01", "OTP Brute Force", "authentication",
                     "Brute-force 4-6 digit OTP codes without rate limiting", "CWE-307",
                     _has_otp, risk="high", priority=8),
        SecurityTest("mfa_otp_reuse_01", "OTP Reuse", "authentication",
                     "Reuse previously valid OTP code", "CWE-287", _has_otp),
        SecurityTest("mfa_otp_leak_01", "OTP Leakage in Response", "authentication",
                     "OTP code disclosed in response body or headers", "CWE-200", _has_otp, risk="high"),
        SecurityTest("mfa_backup_code_01", "Backup Code Weakness", "authentication",
                     "Predictable or unlimited backup codes", "CWE-330", _has_otp),
        SecurityTest("mfa_disable_01", "MFA Disable Without Verification", "authentication",
                     "Disable MFA without re-authentication", "CWE-287", _has_otp),

        # ═══════════════════════════════════════════
        # SECURITY QUESTIONS (3 tests)
        # ═══════════════════════════════════════════
        SecurityTest("auth_sec_question_01", "Security Question Bypass", "authentication",
                     "Bypass security questions via parameter tampering", "CWE-640", _has_login),
        SecurityTest("auth_sec_question_enum_01", "Security Question Enumeration", "authentication",
                     "Enumerate valid security questions", "CWE-204", _has_login),
        SecurityTest("auth_sec_question_brute_01", "Security Question Brute Force", "authentication",
                     "Brute-force common answers to security questions", "CWE-307", _has_login),

        # ═══════════════════════════════════════════
        # FILE UPLOAD EXTENDED (6 tests)
        # ═══════════════════════════════════════════
        SecurityTest("upload_archive_01", "Archive Upload (Zip Bomb)", "file_upload",
                     "Upload malicious archive that expands to massive size", "CWE-409",
                     _has_archive_upload, risk="medium"),
        SecurityTest("upload_archive_path_01", "Archive Path Traversal (Zip Slip)", "file_upload",
                     "Archive with ../../ paths to overwrite files", "CWE-22",
                     _has_archive_upload, risk="high", priority=8),
        SecurityTest("upload_mime_bypass_01", "MIME Type Bypass", "file_upload",
                     "Upload executable with manipulated Content-Type", "CWE-434",
                     _has_multipart, risk="high"),
        SecurityTest("upload_filename_01", "Filename Manipulation", "file_upload",
                     "Upload with special characters in filename (null byte, double extension)", "CWE-434",
                     _has_multipart, risk="high"),
        SecurityTest("upload_svg_xss_01", "SVG XSS via Upload", "file_upload",
                     "Upload SVG containing JavaScript", "CWE-79", _has_multipart),
        SecurityTest("upload_polyglot_01", "Polyglot File Upload", "file_upload",
                     "Upload file valid as both image and HTML/JS", "CWE-434", _has_multipart),

        # ═══════════════════════════════════════════
        # GRAPHQL EXTENDED (5 tests)
        # ═══════════════════════════════════════════
        SecurityTest("graphql_depth_01", "GraphQL Query Depth Attack", "graphql",
                     "Nested query exceeding depth limit causing DoS", "CWE-400",
                     _has_graphql, risk="medium"),
        SecurityTest("graphql_alias_01", "GraphQL Alias Batching", "graphql",
                     "Batch queries via aliases to bypass rate limits", "CWE-799", _has_graphql),
        SecurityTest("graphql_field_suggestion_01", "GraphQL Field Suggestion Leak", "graphql",
                     "Extract schema via field suggestion error messages", "CWE-200", _has_graphql),
        SecurityTest("graphql_mutation_auth_01", "GraphQL Mutation Authorization", "graphql",
                     "Execute mutations without proper authorization", "CWE-862",
                     _has_graphql, risk="high", priority=8),
        SecurityTest("graphql_subscription_01", "GraphQL Subscription Abuse", "graphql",
                     "Subscribe to events without authorization", "CWE-862", _has_graphql),

        # ═══════════════════════════════════════════
        # WEBSOCKET EXTENDED (4 tests)
        # ═══════════════════════════════════════════
        SecurityTest("ws_auth_01", "WebSocket Authentication Bypass", "websocket",
                     "Connect to WebSocket without valid token", "CWE-287",
                     _has_websocket, risk="high"),
        SecurityTest("ws_injection_01", "WebSocket Message Injection", "websocket",
                     "Inject malicious payloads via WebSocket messages", "CWE-74", _has_websocket),
        SecurityTest("ws_flood_01", "WebSocket Message Flooding", "websocket",
                     "Send excessive messages to cause DoS", "CWE-400", _has_websocket),
        SecurityTest("ws_origin_01", "WebSocket Cross-Origin", "websocket",
                     "Connect from unauthorized origin", "CWE-346", _has_websocket),

        # ═══════════════════════════════════════════
        # OPEN REDIRECT EXTENDED (3 tests)
        # ═══════════════════════════════════════════
        SecurityTest("redirect_open_01", "Open Redirect via Parameter", "open_redirect",
                     "Redirect to external domain via URL parameter", "CWE-601",
                     _has_redirect, risk="medium", priority=7),
        SecurityTest("redirect_schema_01", "Open Redirect Protocol Bypass", "open_redirect",
                     "Bypass redirect validation with javascript: or data: scheme", "CWE-601",
                     _has_redirect),
        SecurityTest("redirect_double_encode_01", "Open Redirect Double Encoding", "open_redirect",
                     "Bypass redirect filter with double URL encoding", "CWE-601", _has_redirect),

        # ═══════════════════════════════════════════
        # RATE LIMITING (4 tests)
        # ═══════════════════════════════════════════
        SecurityTest("rate_login_01", "Login Rate Limiting", "rate_limiting",
                     "No rate limit on login endpoint", "CWE-307", _has_login, priority=7),
        SecurityTest("rate_api_01", "API Rate Limiting", "rate_limiting",
                     "No rate limit on API endpoints", "CWE-770", _has_api),
        SecurityTest("rate_password_reset_01", "Password Reset Rate Limiting", "rate_limiting",
                     "No rate limit on password reset", "CWE-307", _has_login),
        SecurityTest("rate_otp_01", "OTP Rate Limiting", "rate_limiting",
                     "No rate limit on OTP verification", "CWE-307", _has_otp),

        # ═══════════════════════════════════════════
        # SEARCH / INFORMATION DISCLOSURE (5 tests)
        # ═══════════════════════════════════════════
        SecurityTest("info_error_stack_01", "Stack Trace in Error Response", "info_disclosure",
                     "Verbose error messages exposing internal paths", "CWE-209", _always),
        SecurityTest("info_debug_endpoint_01", "Debug Endpoint Exposed", "info_disclosure",
                     "Debug/profiling endpoints accessible in production", "CWE-489", _always, priority=7),
        SecurityTest("info_source_map_01", "Source Map Exposure", "info_disclosure",
                     "JavaScript source maps accessible revealing source code", "CWE-540", _always),
        SecurityTest("info_git_exposed_01", ".git Directory Exposed", "info_disclosure",
                     "Git repository files accessible via web", "CWE-538", _always, risk="high", priority=9),
        SecurityTest("info_env_file_01", ".env File Exposed", "info_disclosure",
                     "Environment file with secrets accessible", "CWE-538", _always, risk="critical", priority=10),

        # ═══════════════════════════════════════════
        # EMAIL INJECTION (3 tests)
        # ═══════════════════════════════════════════
        SecurityTest("email_injection_01", "Email Header Injection", "injection",
                     "Inject additional headers via email parameter", "CWE-93", _has_email_param),
        SecurityTest("email_html_injection_01", "Email HTML Injection", "injection",
                     "Inject HTML content into email body", "CWE-79", _has_email_param),
        SecurityTest("email_spoofing_01", "Email Spoofing via Parameter", "injection",
                     "Manipulate sender address in contact forms", "CWE-290", _has_email_param),

        # ═══════════════════════════════════════════
        # RACE CONDITIONS (4 tests)
        # ═══════════════════════════════════════════
        SecurityTest("race_coupon_01", "Race Condition — Coupon Reuse", "business_logic",
                     "Apply coupon multiple times via concurrent requests", "CWE-362",
                     _has_state_change, risk="medium"),
        SecurityTest("race_transfer_01", "Race Condition — Double Spend", "business_logic",
                     "Transfer funds twice via concurrent requests", "CWE-362",
                     _has_state_change, risk="high"),
        SecurityTest("race_registration_01", "Race Condition — Duplicate Registration", "business_logic",
                     "Create duplicate accounts via concurrent requests", "CWE-362", _has_state_change),
        SecurityTest("race_vote_01", "Race Condition — Vote Manipulation", "business_logic",
                     "Submit multiple votes via concurrent requests", "CWE-362", _has_state_change),

        # ═══════════════════════════════════════════
        # PROTOTYPE POLLUTION (3 tests)
        # ═══════════════════════════════════════════
        SecurityTest("proto_pollution_01", "Prototype Pollution via JSON", "client_side",
                     "Inject __proto__ in JSON body", "CWE-1321", _has_json_input, risk="medium"),
        SecurityTest("proto_pollution_param_01", "Prototype Pollution via Query", "client_side",
                     "Inject constructor.prototype via URL parameters", "CWE-1321", _has_input),
        SecurityTest("proto_pollution_merge_01", "Prototype Pollution via Deep Merge", "client_side",
                     "Exploit recursive object merge with __proto__", "CWE-1321", _has_json_input),

        # ═══════════════════════════════════════════
        # REQUEST SMUGGLING EXTENDED (3 tests)
        # ═══════════════════════════════════════════
        SecurityTest("smuggle_clte_01", "CL.TE Request Smuggling", "http_smuggling",
                     "Content-Length / Transfer-Encoding desync", "CWE-444", _always, risk="high", priority=8),
        SecurityTest("smuggle_tecl_01", "TE.CL Request Smuggling", "http_smuggling",
                     "Transfer-Encoding / Content-Length desync", "CWE-444", _always, risk="high"),
        SecurityTest("smuggle_tete_01", "TE.TE Request Smuggling", "http_smuggling",
                     "Obfuscated Transfer-Encoding header desync", "CWE-444", _always, risk="high"),

        # ═══════════════════════════════════════════
        # MASS ASSIGNMENT (3 tests)
        # ═══════════════════════════════════════════
        SecurityTest("mass_assign_role_01", "Mass Assignment — Role Escalation", "authorization",
                     "Add role/admin field to registration/update request", "CWE-915",
                     _has_post_param, risk="high", priority=8),
        SecurityTest("mass_assign_price_01", "Mass Assignment — Price Manipulation", "business_logic",
                     "Modify price/amount field in order request", "CWE-915",
                     _has_post_param, risk="high"),
        SecurityTest("mass_assign_status_01", "Mass Assignment — Status Manipulation", "authorization",
                     "Modify status/verified field in update request", "CWE-915", _has_post_param),

        # ═══════════════════════════════════════════
        # PARAMETER TAMPERING (4 tests)
        # ═══════════════════════════════════════════
        SecurityTest("param_hpp_01", "HTTP Parameter Pollution", "injection",
                     "Duplicate parameters to bypass validation", "CWE-235", _has_input),
        SecurityTest("param_negative_01", "Negative Value Tampering", "business_logic",
                     "Submit negative quantity/price values", "CWE-20",
                     _has_input, risk="medium"),
        SecurityTest("param_type_juggle_01", "Type Juggling", "injection",
                     "Send unexpected types (array, object) for scalar params", "CWE-843", _has_input),
        SecurityTest("param_overflow_01", "Integer Overflow", "injection",
                     "Send very large integers to trigger overflow", "CWE-190", _has_input),

        # ═══════════════════════════════════════════
        # SSRF EXTENDED (3 tests)
        # ═══════════════════════════════════════════
        SecurityTest("ssrf_dns_rebind_01", "SSRF via DNS Rebinding", "ssrf",
                     "Bypass SSRF filters using DNS rebinding", "CWE-918",
                     _has_url_param, risk="high"),
        SecurityTest("ssrf_redirect_01", "SSRF via Open Redirect", "ssrf",
                     "Chain open redirect to bypass SSRF allowlist", "CWE-918", _has_url_param),
        SecurityTest("ssrf_cloud_metadata_01", "SSRF to Cloud Metadata", "ssrf",
                     "Access cloud metadata endpoint (169.254.169.254)", "CWE-918",
                     _has_url_param, risk="critical", priority=9),

        # ═══════════════════════════════════════════
        # CRLF / HEADER INJECTION EXTENDED (3 tests)
        # ═══════════════════════════════════════════
        SecurityTest("crlf_response_split_01", "HTTP Response Splitting", "header_injection",
                     "Inject CRLF to split HTTP response", "CWE-113",
                     _has_header_injection_surface, risk="high"),
        SecurityTest("crlf_log_injection_01", "Log Injection via CRLF", "header_injection",
                     "Inject fake log entries via CRLF in input", "CWE-117", _has_input),
        SecurityTest("host_header_routing_01", "Host Header Routing Abuse", "header_injection",
                     "Manipulate Host header to access internal vhosts", "CWE-644", _always),

        # ═══════════════════════════════════════════
        # MISCONFIGURATION EXTENDED (4 tests)
        # ═══════════════════════════════════════════
        SecurityTest("misconfig_cors_null_01", "CORS Null Origin Accepted", "misconfiguration",
                     "Origin: null accepted with credentials", "CWE-346", _always, risk="high"),
        SecurityTest("misconfig_hsts_01", "Missing HSTS Header", "misconfiguration",
                     "Strict-Transport-Security header not set", "CWE-319", _always),
        SecurityTest("misconfig_csp_01", "Missing/Weak CSP", "misconfiguration",
                     "Content-Security-Policy missing or uses unsafe-inline", "CWE-693", _always),
        SecurityTest("misconfig_cookie_flags_01", "Insecure Cookie Flags", "misconfiguration",
                     "Cookies without Secure/HttpOnly/SameSite flags", "CWE-614", _has_cookie),
    ]

    for t in tests:
        catalog.register(t)
    return catalog
