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


def _has_input(**kw: Any) -> bool:
    params = kw.get("parameters", [])
    return len(params) > 0


def _has_url_param_and_html(**kw: Any) -> bool:
    params = kw.get("parameters", [])
    content_type = kw.get("content_type", "text/html")
    has_param = any(p.get("location") in ("query", "url", "path") for p in params) if params else len(params) > 0
    return has_param and "html" in content_type.lower()


def _has_post_param(**kw: Any) -> bool:
    params = kw.get("parameters", [])
    return any(p.get("location") in ("body", "form") for p in params)


def _has_object_id_and_identities(**kw: Any) -> bool:
    path = kw.get("path", "")
    identities = kw.get("identities", [])
    return ("{id}" in path or "{" in path) and len(identities) > 1


def _is_authenticated_multi_role(**kw: Any) -> bool:
    auth_required = kw.get("auth_required", False)
    identities = kw.get("identities", [])
    return auth_required and len(identities) > 1


def _has_url_param(**kw: Any) -> bool:
    params = kw.get("parameters", [])
    return any("url" in p.get("name", "").lower() or "resource" in p.get("name", "").lower() for p in params)


def _has_multipart(**kw: Any) -> bool:
    content_type = kw.get("content_type", "")
    return "multipart" in content_type.lower()


def _always(**kw: Any) -> bool:
    return True


def _has_jwt(**kw: Any) -> bool:
    return kw.get("has_jwt", False)


def build_default_catalog() -> SecurityTestCatalog:
    catalog = SecurityTestCatalog()
    tests = [
        SecurityTest("auth_login_01", "Login Brute Force", "authentication", "Test login endpoint against credential lists", "CWE-307", _has_input),
        SecurityTest("auth_session_hijack_01", "Session Hijacking", "authentication", "Test session token predictability and fixation", "CWE-384", _always),
        SecurityTest("auth_credential_stuffing_01", "Credential Stuffing", "authentication", "Test with known breached credentials", "CWE-521", _has_input),
        SecurityTest("auth_default_creds_01", "Default Credentials", "authentication", "Test for default admin credentials", "CWE-798", _always),
        SecurityTest("auth_password_policy_01", "Weak Password Policy", "authentication", "Test password complexity requirements", "CWE-521", _has_input),

        SecurityTest("authz_idor_01", "IDOR Basic", "authorization", "Access another user's resource by changing ID", "CWE-639", _has_object_id_and_identities),
        SecurityTest("authz_priv_esc_01", "Privilege Escalation", "authorization", "Access admin functions as regular user", "CWE-269", _is_authenticated_multi_role),
        SecurityTest("authz_horizontal_01", "Horizontal Access Control", "authorization", "Access peer user's data", "CWE-639", _has_object_id_and_identities),
        SecurityTest("authz_forced_browsing_01", "Forced Browsing", "authorization", "Access unlinked admin pages directly", "CWE-425", _always),

        SecurityTest("sqli_basic_01", "SQL Injection Basic", "sqli", "Basic SQL injection with single quote", "CWE-89", _has_input),
        SecurityTest("sqli_time_based_01", "SQL Injection Time-Based", "sqli", "Time-based blind SQL injection", "CWE-89", _has_input),
        SecurityTest("sqli_error_based_01", "SQL Injection Error-Based", "sqli", "Error-based SQL injection extraction", "CWE-89", _has_input),
        SecurityTest("sqli_union_01", "SQL Injection UNION", "sqli", "UNION-based SQL injection", "CWE-89", _has_input),
        SecurityTest("sqli_stacked_01", "SQL Injection Stacked", "sqli", "Stacked queries SQL injection", "CWE-89", _has_input),

        SecurityTest("nosqli_basic_01", "NoSQL Injection", "nosqli", "MongoDB/NoSQL operator injection", "CWE-943", _has_input),
        SecurityTest("nosqli_logical_01", "NoSQL Logical Operators", "nosqli", "Injection via $gt, $ne operators", "CWE-943", _has_input),

        SecurityTest("xss_reflected_01", "XSS Reflected", "xss", "Reflected cross-site scripting", "CWE-79", _has_url_param_and_html),
        SecurityTest("xss_stored_01", "XSS Stored", "xss", "Stored cross-site scripting", "CWE-79", _has_post_param),
        SecurityTest("xss_dom_01", "XSS DOM-Based", "xss", "DOM-based cross-site scripting", "CWE-79", _has_url_param_and_html),

        SecurityTest("ssti_basic_01", "Server-Side Template Injection", "ssti", "Template injection via user input", "CWE-1336", _has_input),

        SecurityTest("cmdi_basic_01", "Command Injection", "command_injection", "OS command injection via user input", "CWE-78", _has_input),

        SecurityTest("path_traversal_01", "Path Traversal", "path_traversal", "Directory traversal via ../ sequences", "CWE-22", _has_input),
        SecurityTest("path_directory_01", "Directory Listing", "path_traversal", "Exposed directory listings", "CWE-548", _always),

        SecurityTest("ldap_injection_01", "LDAP Injection", "ldap", "LDAP query injection", "CWE-90", _has_input),

        SecurityTest("xxe_basic_01", "XML External Entity", "xxe", "XXE injection via XML input", "CWE-611", _has_input),

        SecurityTest("csrf_token_01", "CSRF Token Validation", "csrf", "Missing or weak CSRF token validation", "CWE-352", _has_post_param),

        SecurityTest("cors_misconfig_01", "CORS Misconfiguration", "cors", "Overly permissive CORS headers", "CWE-942", _always),

        SecurityTest("ssrf_basic_01", "SSRF Basic", "ssrf", "Server-side request forgery", "CWE-918", _has_url_param),
        SecurityTest("ssrf_cloud_01", "SSRF Cloud Metadata", "ssrf", "SSRF targeting cloud metadata endpoints", "CWE-918", _has_url_param),

        SecurityTest("jwt_manipulation_01", "JWT Manipulation", "jwt", "Modify JWT claims without re-signing", "CWE-345", _has_jwt),
        SecurityTest("jwt_algo_confusion_01", "JWT Algorithm Confusion", "jwt", "Switch RS256 to HS256 with public key", "CWE-327", _has_jwt),
        SecurityTest("jwt_none_algo_01", "JWT None Algorithm", "jwt", "Set algorithm to none to bypass validation", "CWE-327", _has_jwt),

        SecurityTest("graphql_introspection_01", "GraphQL Introspection", "graphql", "Query __schema for full API surface", "CWE-200", _always),
        SecurityTest("graphql_mutation_01", "GraphQL Mutation Abuse", "graphql", "Unauthorized mutations via GraphQL", "CWE-862", _has_input),
        SecurityTest("graphql_dos_01", "GraphQL DoS", "graphql", "Deeply nested query denial of service", "CWE-400", _always),

        SecurityTest("ws_hijack_01", "WebSocket Hijacking", "websocket", "Cross-site WebSocket hijacking", "CWE-1385", _always),

        SecurityTest("upload_type_01", "File Upload Type Validation", "file_upload", "Bypass file type restrictions", "CWE-434", _has_multipart),
        SecurityTest("upload_rce_01", "File Upload RCE", "file_upload", "Upload web shell for remote code execution", "CWE-434", _has_multipart),

        SecurityTest("race_condition_01", "Race Condition", "business_logic", "Exploit TOCTOU race conditions", "CWE-362", _always),
        SecurityTest("workflow_bypass_01", "Workflow Bypass", "business_logic", "Skip required steps in multi-step process", "CWE-841", _always),

        SecurityTest("header_injection_01", "HTTP Header Injection", "header_injection", "CRLF injection in HTTP headers", "CWE-113", _has_input),
        SecurityTest("open_redirect_01", "Open Redirect", "open_redirect", "Redirect to attacker-controlled domain", "CWE-601", _has_url_param),
        SecurityTest("info_disclosure_01", "Information Disclosure", "info_disclosure", "Sensitive data in error messages or headers", "CWE-200", _always),
    ]
    for t in tests:
        catalog.register(t)
    return catalog
