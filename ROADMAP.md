# AntiGravity — Implementation Roadmap

Ordered by: fix blockers first, then features that get paying customers fastest.

---

## Phase 0: Critical Fixes (Week 1-2) — MUST DO BEFORE ANYTHING ELSE

### 0.1 Rotate All Exposed API Keys
- [ ] Rotate: Groq, DeepSeek, GitHub, Shodan, NVD, Censys, AbuseIPDB, VirusTotal
- [ ] Generate real 32-byte encryption keys with `os.urandom(32)` — replace `ANTIGRAVITY_MASTER_KEY_32BYTES_LONG!` in `.env`
- [ ] Add key generation script: `scripts/generate_keys.py` that creates `.env` with fresh keys on first boot
- [ ] Add key rotation support: store key version, support decrypting with old key + re-encrypting with new key

### 0.2 SQLite Fallback for Zero-Dependency Local Runs
- [ ] Create `core/database/db_backend.py` — abstract interface: `get_connection()`, `execute()`, `executemany()`
- [ ] Implement `SQLiteBackend` using `aiosqlite` or stdlib `sqlite3`
- [ ] Implement `PostgresBackend` wrapping existing `DatabaseManager`
- [ ] Auto-select: if `POSTGRES_HOST` is set → Postgres, else → SQLite at `data/pentest.db`
- [ ] Translate Postgres-specific SQL (`ON CONFLICT`, `BYTEA`, `CREATE EXTENSION`) to SQLite equivalents
- [ ] Update `core/memory/database.py`, `core/database/pg_store.py`, `core/memory/dedup_tracker.py` to use the abstract backend
- [ ] All 1272 tests must pass without Postgres running

### 0.3 Remove All Hardcoded Targets
- [ ] Delete `.pentest_scope.json` — generate it dynamically from `--target` at scan start
- [ ] Remove `preview.owasp-juice.shop` fallback in `agents/authorization.py:193` — fail-closed if no scope
- [ ] Remove Juice Shop wordlist entries (`juice`, `juiceshop`, `bjoern`, `kimminich`) from `core/exploitation/hash_cracker.py:26`
- [ ] Grep entire codebase for `speshway`, `decibyl`, `juice.shop`, `owasp` in non-test files and remove

### 0.4 Policy Engine Fail-Closed
- [ ] `core/decisions/policy_engine.py:114` — change default from `allow=True` to `allow=False`
- [ ] Add explicit ALLOW entries for all legitimate topics so nothing breaks
- [ ] Add test: unknown topic → deny

### 0.5 Global Scope Enforcement on All HTTP Requests
- [ ] Create httpx `EventHook` or transport wrapper that calls `ScopeManager.validate_url()` on every request including redirects
- [ ] Register it globally on every httpx client instance in the codebase
- [ ] Add test: request to in-scope host that redirects to out-of-scope host → blocked

### 0.6 Move Hardcoded LLM Provider URLs to Config
- [ ] Move `https://api.deepseek.com` from `agents/llm_client.py:163` and `agents/universal_llm_harness.py:366` to `.env`
- [ ] Move `https://api.groq.com/openai/v1` from `agents/universal_llm_harness.py:857` to `.env`

---

## Phase 1: Sellable Product (Week 3-6) — Get First Paying Customers

### 1.1 Multi-Tenant Dashboard + RBAC
- [ ] Build web UI with React/Next.js or FastAPI + HTMX
- [ ] Organization → Teams → Projects → Scans hierarchy
- [ ] Roles: Admin (manage team, billing), Analyst (run scans, triage), Viewer (read reports)
- [ ] SSO via SAML/OIDC (use `python-social-auth` or `authlib`)
- [ ] Audit log of every user action
- [ ] Scan management: start, stop, schedule, view progress
- [ ] Findings list with severity filters, search, status tracking

### 1.2 CI/CD Integration — GitHub Actions
- [ ] Create `antigravity-action` GitHub Action
- [ ] Inputs: target URL, auth credentials (via GitHub Secrets), scan depth, fail-on-severity
- [ ] Outputs: SARIF upload to GitHub Security tab, PR comment with summary
- [ ] Block merge if critical/high findings open
- [ ] Add GitLab CI template and Jenkins plugin later

### 1.3 Live Scan Dashboard with Agent Reasoning
- [ ] WebSocket feed from scan engine to dashboard
- [ ] Show real-time: current phase, what the agent is testing, findings as they appear
- [ ] Show agent reasoning: "Testing IDOR on /api/users/{id} with 3 identity contexts..."
- [ ] Progress bar: endpoints tested / total, vuln classes covered / total
- [ ] You already have `live_progress` and `live_results` DB tables — wire them to the UI

### 1.4 Schema Migrations with Alembic
- [ ] Install Alembic, configure for both Postgres and SQLite backends
- [ ] Generate initial migration from current `_init_schema()` DDL
- [ ] Add `schema_version` table
- [ ] Replace `IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS` pattern with proper migrations
- [ ] Add migration CI check: `alembic check` fails if models changed without a migration

---

## Phase 2: Beat the Scanners (Week 7-12) — Differentiation

### 2.1 Business Logic Attack Engine
- [ ] **Workflow State Machine Crawler**: auto-map multi-step flows from browser sessions
  - Intercept all requests during a user journey
  - Build state machine graph: nodes = pages/API calls, edges = transitions
  - Generate attack cases: skip steps, replay steps, reorder steps, access steps out of sequence
- [ ] **Price/Quantity Tampering**: for e-commerce flows
  - Detect price/quantity/discount parameters in requests
  - Mutate: negative values, zero, overflow, currency change, decimal manipulation
  - Replay payment success callbacks with tampered amounts
- [ ] **Role Escalation Sequences**: multi-step broken auth
  - Create resource as user A → modify as user B → access as unauthenticated
  - Map which operations check auth per-request vs only on creation
  - Test all CRUD operations across all identity contexts
- [ ] **LLM Semantic App Understanding**
  - Feed UI text, form labels, API field names to LLM
  - LLM identifies business domain (healthcare, finance, e-commerce, etc.)
  - LLM generates domain-specific test hypotheses ("patient records should be isolated by provider")
  - Execute those hypotheses as targeted tests

### 2.2 Attack Chain Synthesis
- [ ] After discovery phase, build directed graph of all findings
- [ ] Attempt to chain: SSRF → internal service → credential leak → admin takeover
- [ ] Score end-to-end chain impact (not individual bugs)
- [ ] Present chain as step-by-step narrative with request/response at each hop
- [ ] Re-score individual findings based on their role in chains (a "medium" that enables a critical chain becomes high)

### 2.3 API-First Deep Testing
- [ ] Import OpenAPI/Swagger specs → auto-generate test cases for every endpoint + parameter + auth level
- [ ] Import GraphQL schemas → introspection query, mutation fuzzing, nested query DoS, batching attacks
- [ ] Import gRPC proto files → generate test messages
- [ ] Import Postman collections → replay with mutations
- [ ] Test: mass assignment (extra fields), broken function-level auth (admin endpoints as user), excessive data exposure (response fields the role shouldn't see)

### 2.4 OAuth Client Flow in Auth Session
- [ ] Implement Authorization Code + PKCE flow in `core/authentication/auth_session.py`
- [ ] Implement Client Credentials flow for API-to-API testing
- [ ] Token refresh with automatic retry on 401
- [ ] Support for custom OAuth providers (not just well-known)

---

## Phase 3: PTaaS — Recurring Revenue (Week 13-16)

### 3.1 Incremental Scanning
- [ ] After first full scan, persist attack surface baseline (endpoints, params, response schemas)
- [ ] On repeat scan, diff against baseline — only test new/modified endpoints
- [ ] Cut scan time 80%, LLM costs 90% on repeat scans
- [ ] Track what was tested when — never skip an endpoint that hasn't been tested yet

### 3.2 Attack Surface Change Detection
- [ ] Scheduled monitor: new subdomains, new endpoints, changed response schemas, new JS files, DNS changes
- [ ] On change detected → auto-trigger targeted scan of changed surface only
- [ ] Alert: "3 new endpoints appeared on api.example.com since last scan"
- [ ] Dashboard view: attack surface timeline showing growth/changes

### 3.3 Regression Detection & Patch Verification
- [ ] After vuln is patched, auto re-test weekly
- [ ] Detect fix regressions (patch reverted, similar bug elsewhere)
- [ ] Track mean-time-to-fix per severity
- [ ] Dashboard: "5 findings fixed, 2 regressed, 3 open" with timeline

### 3.4 Jira/Linear/ServiceNow Integration
- [ ] One-click export findings to ticket system
- [ ] Track fix status bi-directionally
- [ ] Auto-close ticket when re-scan confirms fix
- [ ] "Won't fix" in Jira → accepted-risk in dashboard with expiry date

---

## Phase 4: Report That Replaces a Pentester (Week 17-20)

### 4.1 Attack Narrative with Video Replay
- [ ] For each critical/high finding, record Playwright browser session during exploit
- [ ] Generate step-by-step narrative with annotated screenshots
- [ ] Include request/response pairs at each step
- [ ] Impact analysis: what data was accessed, what actions were possible

### 4.2 AI-Generated Fix Code
- [ ] Detect target's language/framework from response headers, stack traces, error pages
- [ ] For each finding, generate exact fix code in that language
- [ ] Grey-box mode: generate ready-to-merge PR with the fix
- [ ] Include before/after explanation for developers

### 4.3 Executive Risk Score in Dollars
- [ ] Map findings to breach cost estimates using IBM Cost of a Data Breach data
- [ ] Factor in: industry, company size (from public data), data types exposed, regulatory environment
- [ ] Dashboard: "Total risk exposure: $4.7M across 12 findings"
- [ ] Board-ready one-page PDF: risk in dollars, trend over time, comparison to industry average

### 4.4 Compliance Audit Evidence Packages
- [ ] Auto-generate downloadable ZIP per compliance framework
- [ ] Contents: findings mapped to controls, scan dates, re-test proof, remediation timelines
- [ ] SOC2, PCI-DSS, HIPAA, ISO 27001, NIST CSF formats
- [ ] Auditor-friendly: control ID → finding → evidence → status

---

## Phase 5: Advanced Capabilities (Week 21-28)

### 5.1 AI/LLM Application Testing
- [ ] Prompt injection: multi-turn, indirect, encoded (you have basic version — expand)
- [ ] Training data extraction: probe for memorized PII, code, credentials
- [ ] System prompt leakage: extract system prompts from AI chatbots
- [ ] RAG poisoning: inject malicious content into knowledge base sources
- [ ] Agent hijacking: make AI agents perform attacker-controlled actions
- [ ] Model API abuse: excessive token usage, billing attacks, rate limit bypass

### 5.2 Mobile App Backend Testing
- [ ] Accept APK/IPA upload or app store URL
- [ ] Decompile and extract: API endpoints, hardcoded keys, cert pinning config, deeplink handlers
- [ ] Test all discovered backend APIs with mobile-specific request patterns
- [ ] Test: cert pinning bypass, deeplink injection, intent spoofing (Android), URL scheme hijacking (iOS)

### 5.3 Source Code-Aware Grey Box Mode
- [ ] GitHub/GitLab repo integration — clone and analyze source alongside runtime testing
- [ ] Run CodeQL/Semgrep for SAST findings
- [ ] Map source code paths to runtime endpoints
- [ ] Validate SAST findings with live DAST testing — eliminate false positives
- [ ] Generate PRs with fixes directly in the customer's repo

### 5.4 Parallel Agent Swarm
- [ ] Spawn specialist agents in parallel: auth, injection, business logic, API fuzzing
- [ ] Shared live finding feed — dedup across agents
- [ ] Coordinator agent: assigns work, prevents duplication, merges results
- [ ] Target: 5-10 parallel agents finishing a full scan in 1-2 hours

### 5.5 Autonomous Pivot & Lateral Movement
- [ ] When SSRF or similar gives internal network access: auto-discover internal services
- [ ] Port scan internal ranges (with explicit scope approval)
- [ ] Test discovered internal services for default creds, known CVEs, misconfigs
- [ ] Map internal attack surface graph
- [ ] Requires explicit customer authorization gate — never auto-pivot without consent

---

## Phase 6: Cost & Performance (Ongoing)

### 6.1 Persistent Cost Tracking
- [ ] Persist `TokenBudget` to DB per `scan_id`
- [ ] Add `/api/cost` endpoint: cost per scan, per day, per organization
- [ ] Dashboard: cost breakdown by LLM provider, by scan phase
- [ ] Alert when approaching budget limits

### 6.2 Local LLM Optimization
- [ ] Route 80% of decisions through Ollama (free)
- [ ] Escalate only: exploit chain analysis, business logic understanding, report generation
- [ ] Target: full scan under $0.50 in LLM costs for typical small website
- [ ] Benchmark: Ollama quality vs cloud quality per task type, auto-tune routing thresholds

### 6.3 Silent Exception Cleanup
- [ ] Grep all `except Exception: pass` and `except Exception as e: pass` blocks
- [ ] Replace with `logger.warning()` minimum
- [ ] Add metrics counter for swallowed exceptions
- [ ] Critical paths (finding persistence, evidence storage) must raise, never swallow

### 6.4 Database Performance
- [ ] Replace `VulnRepo.get_all()` hardcoded `LIMIT 1000` with cursor-based pagination
- [ ] Set explicit transaction isolation: `READ COMMITTED` default, `SERIALIZABLE` for dedup writes
- [ ] Move binary artifacts (`scan_artifacts` BYTEA) to filesystem/S3, keep metadata in DB
- [ ] Add size limits on artifact storage to prevent DoS via large responses
- [ ] Add connection pooling metrics and monitoring

### 6.5 Container & Infrastructure
- [ ] Add `HEALTHCHECK` to Dockerfile
- [ ] Add Kubernetes readiness/liveness probes
- [ ] Add rate-limit backoff on intelligence APIs (Shodan, NVD, Censys) — free tier IP bans
- [ ] Add finding model missing fields: `cve_id`, `file_path`, `function_name`, `package_version`

---

## Pricing Model Suggestion

| Tier | Target Customer | Price | Includes |
|------|----------------|-------|----------|
| Free | Individual devs | $0 | 1 scan/month, SQLite, CLI only, community support |
| Starter | Small websites, Shopify stores | $29/month | 10 scans/month, dashboard, CI/CD, email alerts |
| Pro | Startups, mid-market | $199/month | Unlimited scans, PTaaS continuous monitoring, Jira integration, compliance reports |
| Enterprise | Large companies | Custom | Multi-tenant, SSO/SAML, grey-box, SLA, dedicated support, audit evidence packages |

---

## Success Metrics

- Phase 0 complete: all tests pass without Postgres, no hardcoded targets, fail-closed policy
- Phase 1 complete: first customer can sign up, run a scan from dashboard, get a report
- Phase 2 complete: business logic bugs found that Burp/Pentera miss (test against DVWA, Juice Shop, your own test app)
- Phase 3 complete: customer on $29/month plan getting weekly scans with change detection
- Phase 4 complete: CISO reads report without scheduling a debrief call
- Phase 5 complete: feature parity with a $200K/yr pentest team
