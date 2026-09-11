# AntiGravity — Full Implementation Plan

You are implementing fixes and features for an autonomous pentesting framework. The codebase is at the current working directory. It has 533 Python files, 65 packages, 1272 passing tests (2 fail due to Postgres dependency — that's one of the things you're fixing).

## Rules

1. **Reuse existing code.** Before writing anything new, search for existing implementations. This codebase has massive duplication — consolidate, don't add more.
2. **Delete dead code.** If you replace something, delete the old version. If code is unreachable, remove it. If a module is superseded, delete the file and remove all imports.
3. **After each phase, run `python -m pytest tests/ -x --tb=short -q` and fix any failures before moving on.**
4. **Never break existing tests.** If a test fails, fix the code, not the test (unless the test is testing the wrong behavior).
5. **Follow existing patterns.** Look at how similar things are already done before inventing new patterns.
6. **No new dependencies unless absolutely necessary.** Check `requirements.txt` first.
7. **Every new module must have tests.** Add them to the `tests/` directory following the existing naming convention.
8. **Keep files under 500 lines.** If a file would exceed this, split it.

---

## PHASE 0: Critical Fixes

### 0.1 Encryption Key Generation

**Problem:** `.env` lines 68-70 have `ANTIGRAVITY_MASTER_KEY_32BYTES_LONG!` — a fixed ASCII string, not a real key.

**Tasks:**
- [ ] Create `scripts/generate_keys.py` that generates cryptographically random keys using `os.urandom(32)` encoded as base64
- [ ] Update `core/security/encryption.py` (or wherever the master key is loaded) to decode base64 keys from env vars
- [ ] Update `.env.example` and `.env.anon.example` with placeholder `CHANGE_ME_RUN_generate_keys` values
- [ ] Add a startup check in `core/common/startup_diagnostics.py`: if the key contains `ANTIGRAVITY_MASTER_KEY` or `CHANGE_ME`, log a CRITICAL warning and refuse to start in production mode (`ANTIGRAVITY_ENV=production`)
- [ ] Add test: verify key loading works with a proper base64-encoded 32-byte key

**Files to modify:** `core/security/encryption.py`, `core/common/startup_diagnostics.py`, `.env.example`, `.env.anon.example`
**Files to create:** `scripts/generate_keys.py`

### 0.2 SQLite Fallback — Zero-Dependency Local Runs

**Problem:** `core/memory/database.py` hard-crashes if Postgres is unavailable. Every component that touches DB (dedup tracker, tool router, knowledge store, finding store) fails.

**Tasks:**
- [ ] Create `core/database/backend.py` with an abstract `DatabaseBackend` class:
  ```
  class DatabaseBackend(ABC):
      def get_connection(self) -> ContextManager
      def initialize(self)
      def close_all(self)
  ```
- [ ] Create `core/database/sqlite_backend.py` implementing `DatabaseBackend` using stdlib `sqlite3`
  - Use `data/pentest.db` as default path (configurable via `SQLITE_DB_PATH` env var)
  - Translate Postgres-specific SQL: `ON CONFLICT` → `INSERT OR REPLACE`, `BYTEA` → `BLOB`, `SERIAL` → `INTEGER PRIMARY KEY AUTOINCREMENT`, `NOW()` → `datetime('now')`, `%s` → `?`
  - Skip `CREATE EXTENSION` (pgvector) — not applicable
  - Use `threading.Lock` for thread safety (sqlite3 default is single-thread)
- [ ] Create `core/database/postgres_backend.py` — move existing `DatabaseManager` logic here, implementing the same `DatabaseBackend` interface
- [ ] Update `core/memory/database.py`:
  - Auto-select backend: if `POSTGRES_HOST` or `DATABASE_URL` is set → Postgres, else → SQLite
  - `DatabaseManager` becomes a facade that delegates to the selected backend
  - `get_connection()` works identically regardless of backend
- [ ] Update `core/database/pg_store.py`:
  - All raw SQL must work on both Postgres and SQLite
  - Use the `DatabaseManager` facade, never import `psycopg2` directly
  - Replace `psycopg2.extras.execute_values` with standard `executemany` when on SQLite
  - Replace `psycopg2.extras.RealDictCursor` with a wrapper that returns dicts from SQLite rows
- [ ] Update `core/memory/dedup_tracker.py` to use the facade
- [ ] Update `core/tools/tool_router.py` (`EffectivenessDB`) to use the facade
- [ ] Run full test suite WITHOUT Postgres running — all tests must pass
- [ ] Add test: verify SQLite backend creates tables, inserts, queries, and handles ON CONFLICT

**Files to create:** `core/database/backend.py`, `core/database/sqlite_backend.py`, `core/database/postgres_backend.py`
**Files to modify:** `core/memory/database.py`, `core/database/pg_store.py`, `core/memory/dedup_tracker.py`, `core/tools/tool_router.py`

**Search for reuse:** `grep -rn "psycopg2\|DatabaseManager\|get_connection" --include="*.py" core/ agents/` — every file that imports psycopg2 directly or uses DatabaseManager must be updated.

### 0.3 Remove All Hardcoded Targets

**Problem:** Source code contains target-specific data that makes the framework look like a demo.

**Tasks:**
- [ ] Delete `.pentest_scope.json` — scope must be generated dynamically from `--target` arg at scan start
- [ ] Update wherever `.pentest_scope.json` is loaded to generate scope from `CentralBrain.target` instead
- [ ] `agents/authorization.py:193` — remove `preview.owasp-juice.shop` fallback domain. If no scope is configured, fail-closed with a clear error
- [ ] `core/exploitation/hash_cracker.py:26` — remove Juice Shop-specific wordlist entries (`juice`, `juiceshop`, `bjoern`, `kimminich`). Replace with a generic approach: common passwords (rockyou-top-1000 embedded or loaded from `data/wordlists/`), plus dynamically extracted words from the target site (company name, product names, extracted from crawled pages)
- [ ] Search and fix: `grep -rn "speshway\|decibyl\|juice.shop\|owasp.*juice\|preview\.owasp" --include="*.py" . | grep -v .venv | grep -v tests/` — remove every non-test reference
- [ ] Verify no other hardcoded domains exist: `grep -rn "\.com\"\|\.io\"\|\.ai\"\|\.org\"" --include="*.py" core/ agents/ | grep -v .venv | grep -v test | grep -v example | grep -v localhost` — review each hit

**Files to modify:** `agents/authorization.py`, `core/exploitation/hash_cracker.py`
**Files to delete:** `.pentest_scope.json`

### 0.4 Policy Engine Fail-Closed

**Problem:** `core/decisions/policy_engine.py:114` returns `allow=True` for unknown topics.

**Tasks:**
- [ ] Change default to `allow=False` with reason `"unknown policy topic — denied by default"`
- [ ] Audit all callers of `enforce()` — find every topic string passed. Add each legitimate topic to an explicit allowlist in the policy engine
- [ ] Add test: `enforce("never_heard_of_this", {})` → denied
- [ ] Add test: every existing topic in `CODE_DOMAIN` and `LLM_DOMAIN` still works correctly

**Files to modify:** `core/decisions/policy_engine.py`

### 0.5 Global Scope Enforcement on HTTP Requests

**Problem:** `ScopeManager.validate_url()` exists but isn't wired as a mandatory interceptor on every outbound HTTP request.

**Tasks:**
- [ ] Search for how httpx clients are created: `grep -rn "httpx.AsyncClient\|httpx.Client" --include="*.py" core/ agents/` — find all client instantiation points
- [ ] Create `core/security/scoped_http.py`:
  - An httpx event hook or transport wrapper that calls `ScopeManager.validate_url()` on every request URL (including after redirects)
  - If URL is out of scope → raise `OutOfScopeError` (don't silently drop)
  - Log every blocked request at WARNING level
- [ ] Create a factory function `get_scoped_client(**kwargs) -> httpx.AsyncClient` that returns a client with the scope hook pre-installed
- [ ] Update all httpx client creation points to use `get_scoped_client()` instead of raw `httpx.AsyncClient()`
- [ ] Add test: in-scope request succeeds, out-of-scope request raises, redirect to out-of-scope raises

**Files to create:** `core/security/scoped_http.py`
**Files to modify:** every file that creates an httpx client (find with grep above)

### 0.6 Move Hardcoded LLM URLs to Config

**Tasks:**
- [ ] `agents/universal_llm_harness.py:366` and `agents/llm_client.py:163` — replace `https://api.deepseek.com` with `os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")`
- [ ] `agents/universal_llm_harness.py:857` — replace `https://api.groq.com/openai/v1` with `os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")`
- [ ] Add these to `.env.example`

### 0.7 Silent Exception Cleanup

**Tasks:**
- [ ] `grep -rn "except.*Exception.*pass\|except.*:$" --include="*.py" core/ agents/ | grep -v .venv | grep -v test` — find all silent exception swallowing
- [ ] For each: replace `pass` with `logger.warning(f"Swallowed exception in {context}: {e}")`
- [ ] For critical paths (finding persistence, evidence storage, DB writes): re-raise after logging instead of swallowing
- [ ] Add a counter metric for swallowed exceptions if `core/reporting/metrics.py` has a metrics tracker

### PHASE 0 VERIFICATION
```
python -m pytest tests/ -x --tb=short -q
# Must pass ALL tests WITHOUT Postgres running
# Must pass with only: python, pip install -r requirements.txt
```

---

## PHASE 1: Business Logic Attack Engine

### 1.1 HTTP Request Interception & Mutation Engine

**Why:** The current `BusinessLogicExecutor` asks the LLM to *imagine* attack sequences. It doesn't intercept real HTTP requests during a workflow and mutate them. This is the #1 gap vs human pentesters.

**Search for reuse first:**
- `core/exploitation/request_capture.py` — `RequestCapturer` already exists. Read it. Can it be extended?
- `core/replay/replay_engine.py` — `ReplayEngine` exists. Read it. Can it replay with mutations?
- `core/replay/http_proxy.py` — `HttpProxy` exists. Read it. Can it intercept and modify in-flight requests?
- `core/actuation/browser_actuator.py` — Does it drive browser flows?

**Tasks:**
- [ ] Read the 4 files above and understand what already exists
- [ ] Create `core/exploitation/workflow_interceptor.py`:
  - Drive a real user flow via Playwright (add item to cart → checkout → payment)
  - Capture every HTTP request in the flow with full request/response
  - Build a request sequence graph (ordered list of requests with dependencies)
  - For each request in the sequence: identify mutable parameters (prices, quantities, IDs, tokens, discounts)
  - Generate mutation variants: zero price, negative quantity, overflow, duplicate coupon, skip steps, reorder steps
  - Replay the mutated sequence and compare responses to the baseline
  - If a mutation causes a different success response → potential business logic vulnerability
- [ ] Wire it into `BusinessLogicExecutor` — the executor should use the interceptor, not LLM imagination
- [ ] Delete any dead code in the existing `BusinessLogicExecutor` that's replaced by the interceptor
- [ ] Add tests: mock HTTP flow → interceptor captures → mutations generated → replayed

### 1.2 Workflow State Machine Crawler

**Tasks:**
- [ ] Create `core/discovery/workflow_crawler.py`:
  - Use Playwright to crawl multi-step flows (signup, checkout, password reset)
  - At each step, record: URL, method, parameters, cookies, response
  - Build state machine: nodes = states (page/API response), edges = transitions (requests)
  - Identify required vs optional transitions
  - Generate test cases: skip steps, replay steps, reorder, access final state directly
- [ ] Integrate with `core/attack_surface/workflow_inventory.py` — it already exists, read it first and extend rather than duplicate
- [ ] Add tests

### 1.3 Price/Quantity/Discount Tampering

**Tasks:**
- [ ] Extend `BusinessLogicExecutor` or create `core/execution/executors/ecommerce.py`:
  - Detect e-commerce patterns: cart endpoints, checkout flows, payment callbacks
  - Parameter mutations: negative price, zero quantity, overflow, currency change, decimal manipulation
  - Coupon stacking: apply same coupon multiple times, apply expired coupons, brute-force coupon codes
  - Payment callback replay: capture success callback, modify amount, replay
  - Shipping address manipulation: change address after payment
- [ ] Reuse `core/exploitation/request_capture.py` for capture
- [ ] Reuse `core/fuzzing/grammar_engine.py` for mutation generation — it already supports numeric types
- [ ] Add tests

### 1.4 Role Escalation Sequence Finder

**Tasks:**
- [ ] Create `core/execution/executors/role_escalation.py`:
  - For each CRUD endpoint, test with every identity context:
    - Create as user A → Read as user B → should fail
    - Create as user A → Update as user B → should fail
    - Create as user A → Delete as unauthenticated → should fail
  - Test object-level auth: does auth check happen on creation only, or on every access?
  - Test horizontal privilege escalation: user A accessing user B's resources
  - Test vertical privilege escalation: regular user accessing admin endpoints
- [ ] Reuse `core/access_control/matrix_engine.py` — it already has multi-identity matrix testing. Read it first. Extend it rather than duplicating.
- [ ] Reuse `core/identity/identity_manager.py` for identity context management
- [ ] Reuse `core/replay/identity_store.py` for identity-specific request replay
- [ ] Add tests

### 1.5 LLM Semantic App Understanding

**Tasks:**
- [ ] Create `core/intelligence/app_understanding.py`:
  - Feed crawled UI text, form labels, API field names, error messages to LLM
  - LLM outputs: business domain (healthcare/finance/ecommerce/social/etc.), data sensitivity classification, business rules that should be tested
  - Generate domain-specific test hypotheses: "patient records isolated by provider", "financial transactions require MFA", "user data deletable per GDPR"
  - Convert hypotheses into executable test specs that the experiment scheduler can run
- [ ] Reuse `core/intelligence/target_profiler.py` — it already does target analysis. Read it and extend.
- [ ] Reuse `core/knowledge/semantic_inference.py` — it already does semantic analysis. Read it.
- [ ] Wire into `CentralBrain` RECON phase — run app understanding after initial crawl
- [ ] Add tests

### PHASE 1 VERIFICATION
```
python -m pytest tests/ -x --tb=short -q
# All existing + new tests pass
# Run against Juice Shop locally: python main.py --target localhost:3000 --tier POC
# Verify business logic findings are generated
```

---

## PHASE 2: Attack Chain Synthesis

### 2.1 Exploit Chain Builder

**Search for reuse:** `core/exploitation/chain_integration.py` — `ChainManager` already exists. Read it first.

**Tasks:**
- [ ] Read `core/exploitation/chain_integration.py` — understand what `ChainManager` does
- [ ] Extend or replace with `core/exploitation/chain_builder.py`:
  - After all findings are collected, build a directed graph: nodes = findings, edges = "enables" relationships
  - Edge detection: SSRF enables internal access, credential leak enables auth bypass, file upload enables RCE, etc.
  - Use LLM to evaluate: "Does finding A enable finding B?" for non-obvious chains
  - Find all paths from initial access to critical impact (data exfiltration, admin takeover, RCE)
  - Score each chain: end-to-end CVSS based on final impact, not individual findings
  - Generate step-by-step narrative with request/response at each hop
- [ ] Re-score individual findings based on chain membership: a "medium" in a critical chain gets upgraded
- [ ] Wire into reporting: chain visualization in HTML report (reuse `core/reporting/chain_intelligence.py` if it exists)
- [ ] Delete `ChainManager` if fully superseded by new code
- [ ] Add tests

### 2.2 Auto-Pivot on Successful Exploit

**Tasks:**
- [ ] Create `core/exploitation/pivot_engine.py`:
  - When SSRF or similar gives access to internal network: auto-discover services on internal ranges
  - Probe common ports (80, 443, 8080, 8443, 3000, 5000, 6379, 27017, 5432, 3306)
  - Test for: default credentials, known CVEs, open admin panels, unauthenticated APIs
  - Build internal attack surface graph
  - **CRITICAL**: require explicit scope approval before pivoting — add a consent gate. Never auto-pivot to internal systems without customer authorization
- [ ] Reuse `core/security/consent.py` `ExploitConsentManager` for the authorization gate
- [ ] Add tests

---

## PHASE 3: Continuous Monitoring (PTaaS)

### 3.1 Attack Surface Baseline & Diff

**Tasks:**
- [ ] Create `core/monitoring/surface_baseline.py`:
  - After a full scan, persist the complete attack surface: subdomains, endpoints, params, response schemas, JS file hashes, DNS records
  - Store as JSON in DB (new table `attack_surface_snapshots`)
  - On next scan: diff against baseline, identify changes
  - Return only changed/new items for targeted re-scan
- [ ] Reuse `core/attack_surface/attack_surface_state.py` — it already tracks attack surface. Read it. Can it be serialized/diffed?
- [ ] Reuse `core/reporting/scan_diff.py` — it already does scan comparison. Read it. Extend for attack surface diffing.
- [ ] Add tests

### 3.2 CI/CD Integration — GitHub Action

**Tasks:**
- [ ] Create `.github/actions/antigravity-scan/action.yml`:
  - Inputs: target URL, auth credentials (from GitHub Secrets), scan depth, fail-on-severity
  - Runs the scan in a Docker container
  - Outputs: SARIF file → upload to GitHub Security tab via `github/codeql-action/upload-sarif`
  - PR comment with finding summary (use `actions/github-script`)
  - Exit code 1 if findings exceed `fail-on-severity` threshold
- [ ] Reuse existing `core/reporting/sarif_export.py` for SARIF generation
- [ ] Create `scripts/ci_scan.py` — lightweight wrapper around `main.py` optimized for CI (no interactive consent, JSON output, exit codes)
- [ ] Add GitHub Actions workflow in `.github/workflows/` that tests the action against Juice Shop

### 3.3 Regression Detection

**Tasks:**
- [ ] Create `core/monitoring/regression_detector.py`:
  - For each fixed finding: store the exact test case that found it
  - On re-scan: replay that exact test case
  - If it succeeds again → regression detected, flag as "REGRESSED" finding
  - Track: mean-time-to-fix per severity, regression rate
- [ ] Reuse `core/reporting/retest_engine.py` — it already exists. Read it. Is this already implemented?
- [ ] Wire into scheduled scan flow
- [ ] Add tests

### 3.4 Jira/Linear Integration

**Tasks:**
- [ ] Create `core/integrations/ticket_export.py`:
  - Abstract `TicketProvider` interface: `create_ticket()`, `update_ticket()`, `get_status()`
  - `JiraProvider` — REST API integration (Jira Cloud + Server)
  - `LinearProvider` — GraphQL API integration
  - One-click export: finding → ticket with severity, description, reproduction steps, fix suggestion
  - Bi-directional sync: poll ticket status, update finding status in DB
  - Auto-close ticket when re-scan confirms fix
- [ ] Config via env vars: `JIRA_URL`, `JIRA_TOKEN`, `LINEAR_API_KEY`
- [ ] Add tests with mocked API responses

---

## PHASE 4: Advanced Attack Capabilities

### 4.1 API-First Deep Testing

**Search for reuse:** `core/discovery/api_schema_importer.py` already exists. Read it first.

**Tasks:**
- [ ] Read `core/discovery/api_schema_importer.py` — what does it already import?
- [ ] Extend to support: OpenAPI 3.x, Swagger 2.0, GraphQL introspection, gRPC proto files, Postman collections
- [ ] For each imported endpoint + parameter + auth level, auto-generate test specs:
  - Mass assignment: send extra fields not in schema, check if they persist
  - Broken function-level auth: call admin endpoints with user token
  - Excessive data exposure: compare response fields to schema — flag any field returned that isn't in the documented response
  - Parameter pollution: duplicate params, array injection in scalar fields
- [ ] Wire generated specs into experiment scheduler
- [ ] Add tests

### 4.2 AI/LLM Application Testing

**Tasks:**
- [ ] Create `core/execution/executors/llm_app_testing.py`:
  - **Prompt injection** (extend existing `PromptInjectionTester`):
    - Multi-turn injection: benign message → injection in follow-up
    - Indirect injection: inject via user-controlled data the AI reads (profile bio, document content)
    - Encoded injection: base64, unicode, homoglyphs
  - **System prompt extraction**: probe for system prompt leakage via "repeat your instructions" variants
  - **Training data extraction**: probe for memorized PII, code, credentials with targeted prompts
  - **RAG poisoning**: if the app has a knowledge base, test injecting malicious content that the AI retrieves and acts on
  - **Agent hijacking**: if the AI has tools/actions, make it perform attacker-controlled actions via injected instructions
- [ ] Detect AI-powered apps: look for `/chat`, `/completion`, `/generate` endpoints, OpenAI/Anthropic SDK headers, streaming responses
- [ ] Add tests

### 4.3 OAuth Client Flow in Auth Session

**Tasks:**
- [ ] Extend `core/authentication/auth_session.py`:
  - Authorization Code + PKCE flow
  - Client Credentials flow
  - Token refresh with automatic retry on 401
  - Token exchange flow
  - `.well-known/openid-configuration` discovery
- [ ] Reuse existing `OAuthMisconfigExecutor` endpoint discovery logic
- [ ] Add tests

### 4.4 Mobile App Backend Testing

**Tasks:**
- [ ] Create `core/discovery/mobile_analyzer.py`:
  - Accept APK path → decompile with `apktool` or `jadx` (shell out, don't add as Python dep)
  - Extract: API endpoints (string matching for URLs), hardcoded keys, cert pinning configs
  - Extract deeplink handlers from AndroidManifest.xml
  - Feed discovered endpoints into the normal scan pipeline
- [ ] Create `core/discovery/ipa_analyzer.py` — same for iOS (use `plutil` for plist parsing)
- [ ] Add CLI flag: `--mobile-app path/to/app.apk`
- [ ] Add tests

### 4.5 Source Code-Aware Grey Box Mode

**Tasks:**
- [ ] Create `core/analysis/sast_bridge.py`:
  - Clone target repo (if customer provides access)
  - Run Semgrep with security rules (it's a pip package: `semgrep`)
  - Parse Semgrep JSON output → map to internal finding format
  - Correlate SAST findings with DAST findings: same endpoint + same vuln class = confirmed
  - SAST-only findings = "potential, needs runtime validation"
  - DAST-only findings = "confirmed at runtime"
- [ ] Add to requirements.txt: `semgrep` (optional, graceful fallback if not installed)
- [ ] Add CLI flag: `--source-repo https://github.com/org/repo` or `--source-path /path/to/repo`
- [ ] Add tests

---

## PHASE 5: Reports That Replace Pentesters

### 5.1 Attack Narrative with Browser Recording

**Tasks:**
- [ ] Create `core/reporting/attack_recorder.py`:
  - When exploiting a critical/high finding, record the Playwright session as video (Playwright has built-in video recording)
  - Take annotated screenshots at key moments (before exploit, during, after)
  - Capture request/response pairs at each step
  - Generate step-by-step narrative: "1. Navigate to /admin 2. Bypass auth by... 3. Access all user records"
  - Embed video + screenshots + narrative in HTML report
- [ ] Reuse `core/browser/browser_worker.py` for Playwright session management
- [ ] Reuse `core/evidence/evidence.py` for evidence capture
- [ ] Reuse `core/reporting/repro_bundle.py` for reproduction bundle generation
- [ ] Add to HTML report template in `core/reporting/reporting.py`
- [ ] Add tests

### 5.2 AI-Generated Fix Code

**Tasks:**
- [ ] Create `core/reporting/fix_generator.py`:
  - Detect target's language/framework from: response headers (`X-Powered-By`, `Server`), error pages (stack traces), file extensions
  - For each finding, generate fix code using LLM:
    - Prompt: "Generate a code fix for {vuln_type} in {language}/{framework}. The vulnerable endpoint is {endpoint}. The vulnerability is: {description}. Return ONLY the fixed code."
  - Include framework-specific fixes: Django `@permission_required`, Spring `@PreAuthorize`, Express `helmet()`, etc.
  - In grey-box mode (source available): generate exact diff for the actual vulnerable file
- [ ] Add fix code to each finding in the report
- [ ] Add tests with known vuln types → verify fix code is syntactically valid

### 5.3 Executive Risk Score in Dollars

**Tasks:**
- [ ] Create `core/reporting/risk_calculator.py`:
  - Map findings to breach cost using IBM Cost of a Data Breach methodology
  - Factors: industry (from target profiler), data types exposed (PII, financial, health), record count estimate, regulatory environment (GDPR, CCPA, HIPAA)
  - Output: dollar estimate per finding + total portfolio risk
  - Trend: risk over time if historical scans exist
- [ ] Add to executive summary in report
- [ ] Add to dashboard API
- [ ] Add tests

---

## PHASE 6: Speed & Cost

### 6.1 Persistent Cost Tracking

**Tasks:**
- [ ] Extend `agents/universal_llm_harness.py` `TokenBudget`:
  - Persist spend to DB after each LLM call (new table `llm_cost_log`: scan_id, provider, model, input_tokens, output_tokens, cost_usd, timestamp)
  - Add `get_total_cost(scan_id)`, `get_cost_breakdown(scan_id)` queries
- [ ] Add API endpoint in `ui/api/server.py`: `GET /api/scans/{scan_id}/cost`
- [ ] Add tests

### 6.2 Incremental Scanning

**Tasks:**
- [ ] In `CentralBrain.run_main_loop()`:
  - At start of RECON: load previous attack surface baseline for this target (if exists)
  - After RECON: diff current surface vs baseline
  - In ACTIVE_SCANNING: only queue experiments for new/changed endpoints
  - After scan: save new baseline
- [ ] Reuse `core/monitoring/surface_baseline.py` (from Phase 3.1)
- [ ] Add CLI flag: `--incremental` (default: full scan; `--incremental` uses baseline diff)
- [ ] Add tests

### 6.3 Parallel Agent Swarm

**Search for reuse:** `core/orchestration/agent_spawner.py`, `core/orchestration/parallel_executor.py` — these already exist.

**Tasks:**
- [ ] Read `core/orchestration/agent_spawner.py` and `core/orchestration/parallel_executor.py`
- [ ] Extend to support domain-specialist agents running concurrently:
  - Auth specialist: runs all auth/authz executors
  - Injection specialist: runs all injection executors (SQLi, XSS, command injection, etc.)
  - Business logic specialist: runs workflow crawler + mutation engine
  - API specialist: runs API-specific tests (mass assignment, BOLA, etc.)
- [ ] Shared finding feed: all agents write to the same `FindingStoreV2`, dedup prevents duplicates
- [ ] Coordinator: assigns endpoints to specialists, prevents testing the same endpoint twice
- [ ] Add tests

### 6.4 Database Performance Fixes

**Tasks:**
- [ ] `core/database/pg_store.py` `VulnRepo.get_all()` — replace hardcoded `LIMIT 1000` with cursor-based pagination
- [ ] Set explicit transaction isolation: `SET default_transaction_isolation = 'read committed'` on connection init
- [ ] Move binary artifacts from `scan_artifacts` BYTEA to filesystem: `data/artifacts/{scan_id}/{artifact_id}`, keep only metadata + path in DB
- [ ] Add artifact size limit: reject artifacts > 10MB
- [ ] Add tests

---

## PHASE 7: Code Cleanup — Delete Dead Code

**Do this last, after all features are implemented and tests pass.**

**Tasks:**
- [ ] Find unused imports: `python -m py_compile` or use `ruff check --select F401` on all files
- [ ] Find unused files: for every `.py` file in `core/`, check if it's imported anywhere. If not imported and not a test, delete it.
  ```
  for f in $(find core/ -name "*.py" -not -name "__init__.py"); do
    module=$(echo $f | sed 's|/|.|g' | sed 's|\.py$||')
    if ! grep -r "$(basename $f .py)" --include="*.py" core/ agents/ main.py tests/ | grep -v "$f" | grep -q .; then
      echo "UNUSED: $f"
    fi
  done
  ```
- [ ] Find duplicate functionality: search for modules that do the same thing under different names. Consolidate into one.
  - Known duplicates to investigate:
    - `core/coverage/convergence_engine.py` vs `core/convergence/convergence_engine.py`
    - `core/coverage/hypothesis_engine.py` vs `core/hypothesis/`
    - `core/memory/stores.py` `FindingStore` vs `core/findings/finding_store.py` `FindingStoreV2`
    - `core/coverage/catalog.py` `SecurityTestCatalog` vs `core/coverage/security_test_catalog.py` `SecurityTestCatalogV2`
    - `core/orchestration/legacy_scheduler.py` — if it's legacy, delete it
- [ ] Remove all `# TODO`, `# FIXME`, `# HACK` comments that reference completed work
- [ ] Remove all commented-out code blocks (more than 3 consecutive commented lines)
- [ ] Run `ruff check . --fix` to auto-fix lint issues
- [ ] Run full test suite — all tests must still pass
- [ ] `central_brain.py` is 7699 lines — split it:
  - Extract phase runners into `core/orchestration/phases/recon.py`, `active_scanning.py`, `exploitation.py`, `reporting.py`
  - Extract finding ingestion into its own module (mixin already exists — make it standalone)
  - The brain should be an orchestrator that calls phase runners, not contain all logic
  - Target: `central_brain.py` under 500 lines

---

## Final Verification Checklist

After ALL phases are complete, run these checks:

```bash
# 1. All tests pass without Postgres
python -m pytest tests/ --tb=short -q

# 2. No lint errors
ruff check . --select E,F,W

# 3. No hardcoded targets
grep -rn "speshway\|decibyl\|juice.shop\|owasp.*juice\|preview\.owasp" --include="*.py" . | grep -v .venv | grep -v tests/

# 4. No hardcoded secrets
grep -rn "ANTIGRAVITY_MASTER_KEY\|gsk_\|sk-ant-\|ghp_\|sk-[a-f0-9]" --include="*.py" . | grep -v .venv | grep -v .env

# 5. Policy engine fails closed
python -c "from core.decisions.policy_engine import enforce; r = enforce('unknown_topic', {}); assert not r.allowed, 'FAIL: policy engine allows unknown topics'"

# 6. No silent exception swallowing in critical paths
grep -rn "except.*Exception.*pass" --include="*.py" core/database/ core/findings/ core/evidence/ | grep -v .venv
# Should return 0 results

# 7. central_brain.py is under 500 lines
wc -l core/orchestration/central_brain.py
# Must be < 500

# 8. No unused files (spot check)
python -c "
import ast, sys
from pathlib import Path
for f in Path('core').rglob('*.py'):
    if f.name == '__init__.py': continue
    mod = str(f).replace('/', '.').replace('\\\\', '.').removesuffix('.py')
    # Quick check: is the module name referenced anywhere?
"

# 9. Scan runs end-to-end (dry run)
python main.py --target example.com --tier POC --phases RECON 2>&1 | head -50
# Should start and run RECON phase without crashes
```

---

## Implementation Order Summary

```
Phase 0 (Week 1-2)  → Fix blockers. No new features until this passes.
Phase 1 (Week 3-6)  → Business logic engine. The differentiator.
Phase 2 (Week 7-8)  → Attack chains. Makes findings actionable.
Phase 3 (Week 9-12) → PTaaS. Recurring revenue.
Phase 4 (Week 13-18)→ Advanced attacks. Competitive moat.
Phase 5 (Week 19-22)→ Reports. Replace the pentester.
Phase 6 (Week 23-24)→ Speed and cost. Scale.
Phase 7 (Week 25)   → Cleanup. Ship quality.
```

Each phase is independently testable and shippable. Never start Phase N+1 until Phase N's verification passes.

---

## PHASE 8: Token Optimization — Cut LLM Costs 60-80%

**Do this before scaling to large e-commerce sites.** A full scan of a big shopping website (500-2000 endpoints, 5-10 auth roles, 15-30 workflows) consumes ~5M-8M tokens unoptimized. That's $1.50 on DeepSeek, $12 on Bedrock Claude per scan — too expensive for a $29/month product. Target: **under 2M tokens per scan.**

### 8.1 LLM Response Caching

**Problem:** Testing SQLi on `/api/products/1` and `/api/products/2` generates nearly identical LLM prompts. The agent wastes tokens re-analyzing the same pattern for each endpoint instance.

**Tasks:**
- [ ] Create `core/llm/response_cache.py`:
  - Hash the prompt template (strip endpoint-specific values like IDs, paths) to create a cache key
  - Store: cache_key → LLM response in DB (new table `llm_cache`: hash, prompt_template, response, model, created_at, hit_count)
  - TTL: 24 hours for same-scan, 7 days for same-target
  - Cache hit rate target: 40-60% for a typical scan
- [ ] Search for reuse: `core/common/token_optimizer.py` already exists — read it, check if it does caching. Extend rather than duplicate.
- [ ] Wire into `agents/universal_llm_harness.py` — check cache before every LLM call
- [ ] Add cache stats to scan metrics: hits, misses, tokens saved
- [ ] Add tests

### 8.2 Batch Endpoint Classification

**Problem:** RECON phase sends 1 LLM call per endpoint to classify risk. A large site with 500 endpoints = 500 LLM calls just for classification.

**Tasks:**
- [ ] Modify endpoint classification logic in `CentralBrain` RECON phase:
  - Group endpoints by path pattern (e.g., all `/api/products/*` together)
  - Send 20-50 endpoints per LLM call: "Classify these endpoints by risk level and likely vulnerability classes"
  - Parse batch response and assign classifications individually
  - Cuts classification calls from 500 to 10-25
- [ ] Search for reuse: check how `core/coverage/applicability_engine.py` classifies endpoints — it may already batch
- [ ] Add tests

### 8.3 Deterministic-First, LLM-Second

**Problem:** Many executors call the LLM for things that can be determined by regex/signature. CORS misconfiguration, missing security headers, info disclosure in error pages — all detectable without LLM.

**Tasks:**
- [ ] Audit every executor in `core/execution/executors/`:
  - For each `generate_json`/`generate_response` call, ask: can this be done deterministically?
  - CORS: check `Access-Control-Allow-Origin: *` → no LLM needed
  - Security headers: check for missing `X-Frame-Options`, `CSP`, `HSTS` → no LLM needed
  - Info disclosure: regex for stack traces, version strings, debug endpoints → no LLM needed
  - SQL injection: detect error-based SQLi by response pattern matching → no LLM needed for detection, only for classification
- [ ] Refactor: each executor should try deterministic detection first, call LLM only when:
  - The response is ambiguous (can't tell if it's a real vuln or noise)
  - Business logic analysis is needed (requires understanding what the app does)
  - Evidence quality assessment (is this a true positive or false positive?)
- [ ] Estimated savings: 30-50% of executor LLM calls eliminated
- [ ] Add tests: verify deterministic path produces same results as LLM path for known cases

### 8.4 Progressive Depth Scanning

**Problem:** The framework runs all 60+ executors against every endpoint. A 500-endpoint site × 60 executors = 30,000 test attempts, most of which call the LLM.

**Tasks:**
- [ ] Implement three-tier scanning in `CentralBrain` ACTIVE_SCANNING phase:
  - **Tier 0 — Headers & Config (no LLM):** Run on ALL endpoints. Check security headers, CORS, CSP, cookie flags, HTTPS, info disclosure. Pure deterministic. ~0 tokens.
  - **Tier 1 — Common Vulns (minimal LLM):** Run on endpoints that look interesting (have parameters, accept POST, handle auth). SQLi, XSS, CSRF, path traversal, file upload. LLM only for ambiguous results. ~500 tokens/endpoint.
  - **Tier 2 — Deep Testing (full LLM):** Run only on endpoints flagged by Tier 0/1 as potentially vulnerable, plus high-risk endpoints (payment, auth, admin). Business logic, chain analysis, advanced attacks. ~2,000 tokens/endpoint.
- [ ] Expected distribution for a 500-endpoint site:
  - Tier 0: 500 endpoints × 0 tokens = 0
  - Tier 1: 200 endpoints × 500 tokens = 100K tokens
  - Tier 2: 50 endpoints × 2,000 tokens = 100K tokens
  - Brain + reporting: ~300K tokens
  - **Total: ~500K tokens** (vs 5-8M unoptimized)
- [ ] Wire into experiment scheduler: prioritize Tier 0 → 1 → 2 ordering
- [ ] Add tests

### 8.5 Skip Tested Patterns (Endpoint Dedup)

**Problem:** `/api/products/1`, `/api/products/2`, `/api/products/3` are the same endpoint pattern. Testing all three for SQLi is redundant — test one, apply the result to all.

**Tasks:**
- [ ] Extend `core/attack_surface/route_normalizer.py`:
  - Group endpoints by normalized pattern: `/api/products/{id}`, `/api/users/{id}/orders/{orderId}`
  - For each pattern group, test only 1-2 representative endpoints
  - Apply findings to all endpoints matching the same pattern
  - Mark remaining endpoints as "covered by pattern" in coverage matrix
- [ ] Search for reuse: `core/memory/dedup_tracker.py` and `core/common/endpoint_normalizer.py` already exist — check if they do pattern grouping
- [ ] Expected savings: 60-80% endpoint reduction on large APIs with RESTful patterns
- [ ] Add tests

### 8.6 Streaming Token Budget with Auto-Downgrade

**Problem:** `TokenBudget` tracks spend but doesn't adapt behavior. If 80% of budget is spent in RECON, the remaining phases get starved.

**Tasks:**
- [ ] Extend `agents/universal_llm_harness.py` `TokenBudget`:
  - Reserve budget per phase: RECON 15%, SCANNING 40%, EXPLOITATION 30%, REPORTING 15%
  - Track spend per phase against reservation
  - When a phase exceeds 80% of its budget: auto-downgrade LARGE → SMALL tier for remaining calls
  - When total budget exceeds 90%: switch all calls to cheapest available model
  - When budget exhausted: graceful stop with partial report (don't crash)
- [ ] Search for reuse: `core/economics/budget_governor.py` already exists — read it. It may already do tier downgrading.
- [ ] Add tests

### 8.7 Prompt Compression

**Problem:** The `BRAIN_SYSTEM` prompt is sent with every brain decision call (~40-80 calls per scan). That's ~800 tokens × 80 calls = 64K tokens just in repeated system prompts.

**Tasks:**
- [ ] Measure actual system prompt sizes: `BRAIN_SYSTEM`, phase-specific prompts, executor prompts
- [ ] For providers that support it (Anthropic, OpenAI): use prompt caching / system prompt caching — the system prompt tokens are cached after first call, charged at reduced rate
- [ ] For Ollama/local: system prompt is already cached in KV cache, but verify it's working
- [ ] For executor prompts: create a compressed template that includes only the fields relevant to the current test, not the full executor description
- [ ] Estimated savings: 10-20% on input tokens

### PHASE 8 VERIFICATION
```bash
# 1. Run a token-counted dry scan
python -c "
from agents.universal_llm_harness import get_llm
llm = get_llm()
print(f'Budget: {llm.budget.total_tokens_used} tokens, \${llm.budget.total_cost_usd:.4f}')
"

# 2. Compare before/after on same target
# Before optimization: save token count
# After optimization: verify 60%+ reduction

# 3. All tests still pass
python -m pytest tests/ --tb=short -q
```

---

## PHASE 9: Infrastructure — Bedrock & Multi-Provider

### 9.1 Amazon Bedrock Provider

**Tasks:**
- [ ] Create `agents/providers/bedrock_provider.py`:
  ```python
  import boto3, json
  class BedrockProvider(LLMProvider):
      def __init__(self):
          self.client = boto3.client('bedrock-runtime', region_name=os.getenv('AWS_REGION', 'us-east-1'))
          self.small_model = os.getenv('AWS_BEDROCK_SMALL_MODEL', 'us.anthropic.claude-haiku-4-5-v1')
          self.large_model = os.getenv('AWS_BEDROCK_LARGE_MODEL', 'us.anthropic.claude-sonnet-4-v1')
      
      async def generate_response(self, prompt, tier, system, max_tokens, temperature, response_format):
          model = self.small_model if tier == TaskTier.SMALL else self.large_model
          body = {"anthropic_version": "bedrock-2023-05-31", "max_tokens": max_tokens,
                  "messages": [{"role": "user", "content": prompt}]}
          if system: body["system"] = system
          response = self.client.invoke_model(modelId=model, body=json.dumps(body))
          # Parse response, return NormalizedLLMResponse
  ```
- [ ] Register in `agents/universal_llm_harness.py` provider factory — add `"bedrock"` to the provider switch
- [ ] Support both IAM role auth (ECS/EC2) and access key auth (local dev)
- [ ] Add token counting for Bedrock pricing: use Anthropic's token counting for Claude models, Meta's for Llama
- [ ] Add `.env` config:
  ```
  LLM_PROVIDER=bedrock
  AWS_REGION=us-east-1
  AWS_BEDROCK_SMALL_MODEL=us.anthropic.claude-haiku-4-5-v1
  AWS_BEDROCK_LARGE_MODEL=us.anthropic.claude-sonnet-4-v1
  ```
- [ ] Add tests with mocked boto3 client

### 9.2 Provider Fallback Chain

**Tasks:**
- [ ] Create `agents/providers/fallback_chain.py`:
  - Configure ordered list of providers: e.g., `[ollama, bedrock, deepseek]`
  - If primary fails (timeout, rate limit, down): auto-fallback to next provider
  - Log every fallback with reason
  - Config via env: `LLM_FALLBACK_CHAIN=ollama,bedrock,deepseek`
- [ ] Search for reuse: `core/llm/model_routing.py` and `core/llm/llm_router.py` already exist — check if they do fallback. Extend rather than duplicate.
- [ ] Add tests

### 9.3 Hybrid Local + Cloud Routing

**Tasks:**
- [ ] Extend model router to support split routing:
  - Route SMALL tier → Ollama (free, fast for simple tasks)
  - Route LARGE tier → Bedrock/API (better quality for complex reasoning)
  - Config: `LLM_SMALL_PROVIDER=ollama`, `LLM_LARGE_PROVIDER=bedrock`
- [ ] Auto-detect Ollama availability: if Ollama is running, use it for SMALL; if not, fall back to cloud
- [ ] Add health check: ping Ollama `/api/tags` on startup
- [ ] Add tests

---

## PHASE 10: Local LLM Optimization

### 10.1 Ollama Model Selection Guide

**Tasks:**
- [ ] Create `scripts/setup_local_models.py`:
  - Detect available RAM and GPU VRAM
  - Recommend model sizes:
    - <16GB RAM: `qwen3:8b` (SMALL only, API for LARGE)
    - 16-32GB RAM: `qwen3:14b` SMALL + API for LARGE
    - 32-64GB RAM: `qwen3:14b` SMALL + `qwen3:32b` LARGE
    - 64GB+ RAM: `qwen3:14b` SMALL + `qwen3:72b` LARGE
  - Auto-pull recommended models via `ollama pull`
  - Update `.env` with selected models
- [ ] Add to startup diagnostics: log which models are available, estimated quality level

### 10.2 Structured Output Enforcement for Local Models

**Problem:** Small local models (8B-14B) produce invalid JSON ~15-20% of the time. This causes executor failures and wasted retries.

**Tasks:**
- [ ] Create `core/llm/json_enforcer.py`:
  - Post-process LLM output: strip markdown fences, fix trailing commas, fix unquoted keys
  - If still invalid: extract JSON from mixed text/JSON response using regex
  - If still invalid: retry with a simpler prompt ("Return ONLY valid JSON, no other text")
  - Max 2 retries, then fall back to deterministic default
- [ ] Search for reuse: `agents/universal_llm_harness.py` already has `generate_json` with retry logic — check line ~661. Extend its error handling rather than duplicating.
- [ ] Track JSON parse failure rate per model — log to metrics
- [ ] Add tests: feed known-bad LLM outputs → verify recovery

### 10.3 Ollama Performance Tuning

**Tasks:**
- [ ] Document optimal Ollama settings in `scripts/setup_local_models.py`:
  - `OLLAMA_NUM_PARALLEL=4` — parallel request handling
  - `OLLAMA_MAX_LOADED_MODELS=2` — keep both SMALL and LARGE in memory
  - `OLLAMA_KEEP_ALIVE=30m` — don't unload models between calls
  - GPU layer offloading: `--num-gpu 999` for full GPU offload
- [ ] Add these as defaults in `.env.example`
- [ ] Add startup check: warn if Ollama is running with suboptimal settings

---

## PHASE 11: Benchmark & Validation

### 11.1 Juice Shop Benchmark Suite

**Tasks:**
- [ ] Create `tests/benchmarks/juice_shop_benchmark.py`:
  - List all 117 Juice Shop challenges with: name, category, difficulty, expected detection method
  - For each: map to the executor(s) that should find it
  - Run scan against local Juice Shop instance
  - Score: found / total per category, overall score
  - Target scores: Phase 0 complete → 55+, Phase 1 complete → 80+, Phase 4 complete → 95+
- [ ] Create `docker-compose.benchmark.yml` that starts Juice Shop + the scanner
- [ ] Add to CI: weekly benchmark run, alert on score regression

### 11.2 DVWA Benchmark Suite

**Tasks:**
- [ ] Create `tests/benchmarks/dvwa_benchmark.py`:
  - Similar to Juice Shop but for DVWA's vulnerability categories
  - Test at each DVWA security level (low, medium, high, impossible)
  - Score per security level — agent should find more at low, gracefully degrade at high
- [ ] Add to CI alongside Juice Shop benchmark

### 11.3 Token Cost Benchmark

**Tasks:**
- [ ] Create `tests/benchmarks/token_benchmark.py`:
  - Run scan against Juice Shop with token counting enabled
  - Record: total tokens, tokens per phase, tokens per executor, cost per provider
  - Assert: total tokens < 2M (after Phase 8 optimizations)
  - Track over time: alert if token usage regresses by >20%
- [ ] Add to CI: weekly token cost regression check

---

## Updated Implementation Order Summary

```
Phase 0  (Week 1-2)   → Fix blockers. No new features until this passes.
Phase 1  (Week 3-6)   → Business logic engine. The differentiator.
Phase 2  (Week 7-8)   → Attack chains. Makes findings actionable.
Phase 3  (Week 9-12)  → PTaaS. Recurring revenue.
Phase 4  (Week 13-18) → Advanced attacks. Competitive moat.
Phase 5  (Week 19-22) → Reports. Replace the pentester.
Phase 6  (Week 23-24) → Speed and cost. Scale.
Phase 7  (Week 25)    → Cleanup. Ship quality.
Phase 8  (Week 26-28) → Token optimization. Cut costs 60-80%.
Phase 9  (Week 29-30) → Bedrock + multi-provider. Enterprise infra.
Phase 10 (Week 31-32) → Local LLM optimization. Best free experience.
Phase 11 (Week 33-34) → Benchmarks. Prove it works. Track regressions.
```

Each phase is independently testable and shippable. Never start Phase N+1 until Phase N's verification passes.
