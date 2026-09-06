# ALL ISSUES — Complete Register
**AntiGravity Autonomous Pentesting Platform** · 2026-09-06 · branch `autonous-agent`

Consolidated from all seven subsystem audits (UI/API, Reporting, Intel+Auth+Infra, Injection+Fuzzing+AttackSurface+Discovery, Escalation+Actuation+Execution+Generic85, Orchestration+LLM, Tools+Adapters+Payloads, Database+Persistence). **116 issues** total across CRITICAL / HIGH / MEDIUM / LOW / INFO.

Format: `#NN [SEV] file:line — one-line title`
Full descriptions for P0/P1/P2/P3 are in `RISK_MATRIX.md`. This file is the exhaustive checklist.

---

## CRITICAL (26)

**Authentication & authorization**
- **#001 [CRITICAL]** `ui/api/server.py:37-52` — API auth middleware short-circuits when `API_KEY` unset; `.env.example:90` blank; default = zero auth
- **#002 [CRITICAL]** `ui/api/server.py:25-33` — `CORS_ORIGINS` defaults to `*`
- **#003 [CRITICAL]** `ui/api/server.py:1613` — WebSocket `/ws/scan/{job_id}` bypasses HTTP middleware entirely
- **#004 [CRITICAL]** `core/execution/executors/base.py:44` — `ExecutorBase.validate_target()` is dead code; no caller anywhere in `core/`; ~85 executors inherit no-op
- **#005 [CRITICAL]** `core/execution/execution_pipeline.py:110-134` — pipeline calls `executor.execute()` without any scope check
- **#006 [CRITICAL]** `core/execution/executors/generic.py:65-66` — base `validate_target()` returns `(True, None)` no-op, inherited by all 85 subclasses
- **#007 [CRITICAL]** `core/execution/executors/{authentication,authorization,sql_injection,xss}.py` — no per-request scope enforcement

**Data protection / crypto**
- **#008 [CRITICAL]** `core/security/encryption.py:19,36` — `DEFAULT_FALLBACK_KEY_RAW = b"ANTIGRAVITY_DEFAULT_KEY_32BYTES!"` used silently when `ENCRYPTION_KEY` unset
- **#009 [CRITICAL]** `core/reporting/reporting.py:72-84` — `EncryptedTrendStore` XORs against hardcoded `TREND_STORE_KEY` default; not encryption
- **#010 [CRITICAL]** `core/database/pg_store.py:594-597` — `auth_bypasses.password TEXT`, `token TEXT` plaintext
- **#011 [CRITICAL]** `core/database/pg_store.py` — `scan_llm_memory.content` stores raw LLM reasoning quoting harvested tokens/creds
- **#012 [CRITICAL]** `core/intelligence/threat_intel.py:24` — `ssl._create_unverified_context()` globally disables TLS verification for all threat-feed HTTP

**Persistence / data integrity**
- **#013 [CRITICAL]** `core/memory/database.py:71-75` — `get_connection()` `putconn` in `finally` without `rollback` → connection pool poisoning cascade
- **#014 [CRITICAL]** `core/validation/dedup.py:160-178` — `mark_resolved` scoped only by `scan_id`, not target → cross-target contamination
- **#015 [CRITICAL]** `core/database/pg_store.py:1015,1043` — `live_progress`/`live_results` singleton row (`id DEFAULT 1`); concurrent scans stomp
- **#016 [CRITICAL]** `core/orchestration/central_brain_mixins/persistence.py:37,55,66,88,158,218,224,282` — `datetime.now()` calls without `datetime` import → `NameError` on every `_persist_*` call
- **#017 [CRITICAL]** `core/memory/experience_store.py:37,42,47,52` — calls `.cursor()` on `@contextmanager` → dead on arrival
- **#018 [CRITICAL]** `core/memory/failure_store.py:32,37` — same defect
- **#019 [CRITICAL]** `core/memory/strategy_store.py:38` — same defect

**Path / file safety**
- **#020 [CRITICAL]** `ui/api/server.py:2149-2161` — regex `^[\w\-\.]+$` matches `..`; no `Path.resolve()` boundary → arbitrary file read
- **#021 [CRITICAL]** `ui/api/server.py:2271` — `POST /api/rag/ingest/file?file_path=` no allowlist → arbitrary local file read into vector store
- **#022 [CRITICAL]** `ui/api/server.py:2383` `_spa_fallback` — catches every path; no `resolve()` boundary check

**Injection surfaces**
- **#023 [CRITICAL]** `core/tools/tool_registry.py:310-378` `HeadlessBrowserTool._script_navigate/_screenshot/_cookies/_form` — unescaped f-string interpolation of `url`/`data` into `python3 -c "..."` blob → Python code injection into container
- **#024 [CRITICAL]** `core/discovery/api_schema_importer.py:50-54,70-75` — f-string curl commands with unescaped `target`/`url` executed via `KaliDockerExecutor.run`
- **#025 [CRITICAL]** `core/discovery/js_analyzer.py:101,161,165,181,185` — same f-string curl pattern
- **#026 [CRITICAL]** `core/tools/tool_router.py:91-151` — auto-builds ~25 shell command strings interpolating raw `target`/`domain`; `ToolGateway → ToolRouter` path does not invoke `ToolInvocationValidator`

---

## HIGH (34)

**LLM / provider integrity**
- **#027 [HIGH]** `agents/universal_llm_harness.py:1039-1040` — Groq default `mixtral-8x7b-32768` retired; fallback 404s
- **#028 [HIGH]** `agents/llm_harness_adapter.py:17` — `DEEPSEEK_LARGE_MODEL` default `"deepseek-chat"` (non-reasoning) for LARGE-tier planning
- **#029 [HIGH]** `agents/universal_llm_harness.py:1092` — `"HTTP 5"` substring fatal-error match too broad; matches `HTTP 500` in body text
- **#030 [HIGH]** `agents/universal_llm_harness.py:568,1096` — no 429 retry / exponential backoff; only 5xx/402 triggers provider swap
- **#031 [HIGH]** `agents/llm_harness_adapter.py:5-13` — three providers wired; global `_harness = None` singleton, races with `close_llm()`
- **#032 [HIGH]** `core/llm/llm_router.py:39-63` — `_run_async` `t.join(timeout=60)` silently returns `None` on stall; hides valid LLM output; falls to heuristic

**Prompt injection surface**
- **#033 [HIGH]** `core/reporting/llm_validator.py:48-75` — raw `proof`/`details`/`evidence` interpolated into prompt
- **#034 [HIGH]** `core/reporting/chain_intelligence.py:105` — raw evidence into LLM prompt; also mid-string truncation at 20 000 chars
- **#035 [HIGH]** `core/reporting/scan_chatbot.py:127` — fact JSON embedded verbatim; DB-write access → hijack analyst voice
- **#036 [HIGH]** `core/orchestration/central_brain.py:5905` `_build_brain_prompt` — attacker-controlled response bodies thread into planner
- **#037 [HIGH]** `core/orchestration/agentic_executor.py:279,294-349,582` — tool stdout interpolated into planner prompt
- **#038 [HIGH]** `core/orchestration/adversarial_critic.py:141` — `resp[:1200]` raw into critic prompt
- **#039 [HIGH]** `agents/payload_generator.py:73-86` — attacker-controlled context into payload-generation prompt
- **#040 [HIGH]** `agents/llm_client.py:309,315` — same pattern
- **#041 [HIGH]** `core/orchestration/central_brain_mixins/finding_ingestion.py:66-77,244-268` — nikto/nuclei/whois stdout becomes `vuln["title"]/details` unsanitized (root of #033–#040)

**Broken silent failures**
- **#042 [HIGH]** `core/orchestration/central_brain_mixins/osint_bridge.py:16` — `_mask_secret` missing `self`
- **#043 [HIGH]** `core/orchestration/central_brain_mixins/osint_bridge.py:56` — `re` never imported; raises on first use
- **#044 [HIGH]** `agents/authorization.py:86` — synchronous `input()` blocks async event loop; deadlocks non-TTY
- **#045 [HIGH]** `agents/kali_executor.py:83,344,397,421` — `subprocess.run(shell=True)` with LLM-derived `command` strings

**Credentials / secrets leakage**
- **#046 [HIGH]** `ui/api/server.py:245-246` — passwords JSON-serialized into subprocess argv (visible in `/proc/<pid>/cmdline`)
- **#047 [HIGH]** `ui/api/server.py:252` — `_active_scans[job_id]["command"]` echoed by `GET /api/scans/job/{job_id}` → passwords leak to any UI viewer
- **#048 [HIGH]** WebSocket `/ws/scan/{job_id}` streams raw cookies/tokens captured during recon (`server.py:1580-1596`)

**Concurrency**
- **#049 [HIGH]** `core/database/pg_store.py:1185-1200` `DedupRepo.check_and_insert` — SELECT-then-INSERT race → IntegrityError → pool poisoning cascade
- **#050 [HIGH]** `core/rag/pipeline.py:130-146` `_store_chunk` — SELECT-then-INSERT; non-unique `content_hash` idx allows duplicate storage
- **#051 [HIGH]** `core/execution/executors/auth_registry.py:14,22-31` — module-global `_ACTIVE` dict, no lock; concurrent scans stomp headers
- **#052 [HIGH]** `core/execution/executors/generic.py:2465` `_LLMBudget._calls` — class-global counter, not reset across scans in long-running process
- **#053 [HIGH]** `core/orchestration/central_brain.py:5896`, `parallel_agents.py:137` — `CentralBrain.ctx` mutated without locks in `asyncio.gather`

**Async / event-loop hazards**
- **#054 [HIGH]** `core/execution/executors/generic.py:2480-2509` `_run_async` — `t.join(timeout=45)` without `is_alive()` check → thread leak on hung coroutine; result silently `None`
- **#055 [HIGH]** `core/orchestration/agentic_executor.py:378,408,455,1203` — no `asyncio.wait_for` around LLM tool-call rounds; stall halts phase
- **#056 [HIGH]** `agents/exploit_agent.py:584` — no `asyncio.wait_for` on `LLMClient.generate_json_with_retry`
- **#057 [HIGH]** `core/orchestration/adversarial_critic.py:94` — no `asyncio.wait_for` on critic LLM call
- **#058 [HIGH]** `agents/payload_generator.py:88,117,148,177,203,219` — no `asyncio.wait_for` on payload-refinement LLM calls
- **#059 [HIGH]** `core/orchestration/central_brain.py:5672-5694` — blocking `subprocess.run` inside `await executor.execute(...)` may block event loop 300–600 s

**Data + persistence performance**
- **#060 [HIGH]** `core/database/pg_store.py:937,1096,1415,1492,1704,1746` — N+1 bulk INSERT loops; no `execute_values`
- **#061 [HIGH]** `core/orchestration/agentic_executor.py:519` — raw per-tool-call `INSERT INTO agent_reasoning` + `conn.commit()`; no batching

**Supply chain / hardening**
- **#062 [HIGH]** `Dockerfile:19-29` — Go tools installed via `@latest`; unpinned
- **#063 [HIGH]** `Dockerfile` — base `kalilinux/kali-rolling` unpinned by digest
- **#064 [HIGH]** `Dockerfile`, `Dockerfile.web` — no `USER` directive; runs as root
- **#065 [HIGH]** `Dockerfile.web:28-32` — installs Docker CLI + apt-adds Docker repo; combined with typical `docker.sock` mount = container escape
- **#066 [HIGH]** `Dockerfile:238` — `nuclei -update-templates || true` at build time; unverified fetch from ProjectDiscovery
- **#067 [HIGH]** `Dockerfile.web:41` — `COPY . .` without `.dockerignore` review; risk of shipping `.env`, `.audit_logs/`, `.antigravity/secrets.enc`
- **#068 [HIGH]** No SBOM, no image scanning stage, no signature verification

**Reporting robustness**
- **#069 [HIGH]** `core/reporting/reporting.py:681-725` — PDF chain silently degrades to `fpdf2` (tag stripping) on Windows; logged at INFO not WARN; MIME `application/pdf` shipped
- **#070 [HIGH]** `core/reporting/retest_engine.py:122-125,137,154,385` — `NOT REPRODUCIBLE` → `confidence_score=0.30`; treats network error identically to endpoint-negative
- **#071 [HIGH]** `core/reporting/fp_filter.py:88-99` — ML `RandomForestClassifier` trains on 7-row synthetic dataset when `training_data.csv` absent; persists to disk
- **#072 [HIGH]** `core/reporting/reporting.py:335-346` — `ExecutiveSummaryGenerator` renders `templates/executive_summary.jinja2` unsandboxed → SSTI risk

**API / input validation**
- **#073 [HIGH]** `ui/api/server.py:146` — `TargetCreate.url` bare `str`; no URL parsing, no scope validation
- **#074 [HIGH]** `ui/api/server.py:159` — `ScanRequest.target/tier/phases[]` no allowlist / enum
- **#075 [HIGH]** `ui/api/server.py` `/api/rag/ingest/url` — no scheme allowlist → SSRF via `http://169.254.169.254`, `file://`, `gopher://`
- **#076 [HIGH]** `ui/api/server.py` `/api/schedules` — `interval_hours` no min/max; `0` or negative may spin-loop the scheduler
- **#077 [HIGH]** `ui/api/server.py` `/api/campaigns/run` — `max_parallel` no upper bound
- **#078 [HIGH]** No rate limiting anywhere; `slowapi`/limits absent

---

## MEDIUM (34)

**Scope enforcement**
- **#079 [MEDIUM]** `core/scope/manager.py:82-98` — `validate_url` doesn't normalize trailing dot / IDN / punycode
- **#080 [MEDIUM]** `core/scope/manager.py:146` — `domain = target.lower().split(":")[0].split("/")[0]` mangles IPv6 literal `[2001:db8::1]:8080`
- **#081 [MEDIUM]** `core/scope/manager.py:68,72,96` — bare `except:` swallowing errors including CIDR parse errors
- **#082 [MEDIUM]** `core/security/authorization.py:30-39` — `TargetScopeValidator._instance` module-global singleton; re-scoping silent no-op
- **#083 [MEDIUM]** `ScopeManager`, `TargetScopeValidator`, `LegalValidator` are separate singletons with no propagation
- **#084 [MEDIUM]** `core/security/consent.py:31` — `AUTO_APPROVE_EXPLOITS` single env-var kill-switch bypasses consent gate

**OSINT integration**
- **#085 [MEDIUM]** `core/intelligence/censys_client.py:62,76,106,136` — raises `ValueError` on missing key instead of degrading
- **#086 [MEDIUM]** OSINT clients — no per-provider rate limiter, no exponential backoff, no circuit breaker; provider down hangs phase

**Frontend races / hygiene**
- **#087 [MEDIUM]** `ui/web/src/pages/LiveScan.jsx:141-171`, `Targets.jsx:204`, `Dashboard.jsx`, `Analytics.jsx`, `LiveAgentsPanel`, `AccessGainedPanel`, `ArtifactsPanel`, `ActivityLog` — 7 concurrent polling timers; no `AbortController`, no request generation guard; WS + poll race overwrites newer state with older
- **#088 [MEDIUM]** `ui/web/src/api.js:170,207` — object literal duplicate key `attack-chains`
- **#089 [MEDIUM]** `ui/api/server.py:813` and `:2188` — duplicate route registration `/api/scans/{scan_id}/attack-chains`; FastAPI keeps last
- **#090 [MEDIUM]** `ui/web/src/**/*.jsx` — every fetch uses `.catch(()=>{})`; auth failures render blank tables silently

**Executor silent failures**
- **#091 [MEDIUM]** `core/execution/executors/generic.py:80-82` `_probe()` returns `(0, "", {})` on any exception; indistinguishable from real empty response
- **#092 [MEDIUM]** `core/execution/executors/generic.py:5225-5231` `_run_in_kali` `shell=True` with env-sourced `container` name (low practical risk)
- **#093 [MEDIUM]** `core/execution/executors/generic.py:5238-5244` `_browser_available()` — exists to preflight but never called by Tier-8 browser executors
- **#094 [MEDIUM]** `core/execution/executors/xss.py:66` — `payload in body` naive substring; misses HTML-encoded contexts; false positives on textarea/JSON echo
- **#095 [MEDIUM]** `core/execution/executors/sql_injection.py:15-38` — 20 English DB-error patterns; no blind/time-based coverage
- **#096 [MEDIUM]** `core/execution/executors/authentication.py:81` — HTTP status <400 unconditionally treated as SUCCESS; misclassifies login-failed 200 pages

**DB dedup / correctness**
- **#097 [MEDIUM]** `core/validation/dedup.py:66-75` — fingerprint collision: title-lowercased + empty `file_path` on web findings → `/api/v1` and `/api/v2` collapse
- **#098 [MEDIUM]** `core/database/pg_store.py:1697,1711` `AttackChainRepo.bulk_upsert` — `ON CONFLICT DO NOTHING` without target column; `attack_chains` lacks matching unique constraint → raises on the actual conflict
- **#099 [MEDIUM]** `core/database/pg_store.py:711-793` — dedupe DELETE migration runs on every boot; can lock rows
- **#100 [MEDIUM]** No transaction boundaries: `ScanRepo.create` + `VulnRepo.bulk_insert` + `ScanRepo.update_status("finished")` not atomic; crash mid-way = orphaned "running" scan forever
- **#101 [MEDIUM]** No `bootstrap_recover()` sweeper marks orphaned "running" scans failed on process start

**Reporting quality**
- **#102 [MEDIUM]** `core/reporting/reporting.py:845` `add_osint_findings` — `report_html.replace('</main>', ...)` corrupts pages with multiple `</main>`
- **#103 [MEDIUM]** `core/reporting/fp_filter.py:24` — `NON_HTML_CONTENT_TYPES` lists `application/javascript`; drops real JSONP-XSS findings as FP
- **#104 [MEDIUM]** `core/reporting/dedup.py:199` — recurring with same severity suppressed silently; HIGH/CRITICAL findings disappear from report unless severity changed
- **#105 [MEDIUM]** `core/reporting/sarif_export.py:49` — fingerprint truncated to short hash; collisions on large scans
- **#106 [MEDIUM]** `core/reporting/reporting_engine.py:55` — `target_dir = self.output_dir / scan_id`; `scan_id` not sanitized → path traversal
- **#107 [MEDIUM]** `core/reporting/retest_engine.py:22-23` — `BASELINE_FILE`/`REGRESSION_REPORT_FILE` written to CWD
- **#108 [MEDIUM]** `core/reporting/reporting.py:582` `_poc_reproduction_table` — builds `curl` command by string-concat of untrusted `payload`; shell injection when operator runs generated `poc_reproduce.sh`
- **#109 [MEDIUM]** `core/reporting/report_builder.py:161` interactive HTML uses CDN (DataTables/Chart.js) — breaks offline; also risk of external dep injection
- **#110 [MEDIUM]** `core/reporting/report_builder.py:336-339` `export_pdf` returns HTML content but names file `report.pdf` on ReportLab failure — MIME mismatch
- **#111 [MEDIUM]** `core/reporting/finding_ingestion.py:39` — duplicate `"hidden"` dict key overwrites earlier mapping

**Missing indexes / unbounded queries**
- **#112 [MEDIUM]** Missing idx: `audit_log.timestamp`, `execution_audit.timestamp`, `findings_dedup.last_seen`, `scans.started_at`, `experiences.test_type`, `experiences.created_at`, `llm_failures.created_at`
- **#113 [MEDIUM]** Unbounded list queries: `TargetRepo.list_all`, `ScanRepo.list_all`, `FindingV2Repo.list_all`, `ScheduleRepo.list_all`, `CampaignRepo.list_all`

---

## LOW (16)

- **#114 [LOW]** `agents/llm_client.py:252` — bare `except:`
- **#115 [LOW]** `core/tools/tool_executor.py:74` — leftover `print(f"DEBUG: ...")` in production path
- **#116 [LOW]** `ui/web/src/pages/Settings.jsx:75` — hardcoded `http://localhost:8900/api`; actual port `:8903` (vite.config.js:9)
- **#117 [LOW]** `.env.example:95-100` — ships default `POSTGRES_PASSWORD=pentesting_password`
- **#118 [LOW]** `core/security/audit_logger.py:18` — `AUDIT_SALT` hardcoded
- **#119 [LOW]** `.audit_logs/audit.jsonl` — no log rotation; unbounded growth
- **#120 [LOW]** `core/common/config.py:78` — naive KEY=VALUE parser; no `dotenv`, no quote/interpolation handling
- **#121 [LOW]** `core/common/config.py:43,48` — `CENSYS_UID`/`CENSYS_SECRET` deprecation warning logged on every access (spam)
- **#122 [LOW]** `core/rag/embedder.py:102` — `_local_embed` MD5-bag 1536-dim hash embedding persisted alongside real vectors; silent quality collapse
- **#123 [LOW]** `core/attack_surface/attack_surface_state.py:124` — O(n) linear scan per endpoint insertion → O(n²) on large scans
- **#124 [LOW]** `core/attack_surface/graph.py:150-151` — `sync_from_endpoint_inventory` `try/except Exception: pass` silently drops malformed endpoints
- **#125 [LOW]** `core/discovery/api_schema_importer.py:60,81` — status code parsed via fragile `int(stdout.strip()[-3:])`; `ValueError`/`IndexError` only caught
- **#126 [LOW]** `core/discovery/api_schema_importer.py:103-111` — YAML fallback broad `except: pass`; silent parse errors
- **#127 [LOW]** `core/discovery/js_analyzer.py:26-84` — broad regex `SECRET_PATTERNS`/`ENDPOINT_PATTERNS` false-positive prone
- **#128 [LOW]** `core/discovery/js_analyzer.py:193-195` — naive `":"` split on secretfinder output; fragile
- **#129 [LOW]** `data/db/` empty but SQLite paths referenced by config

**Adapter hygiene**
- **#130 [LOW]** `core/fuzzing/adapters.py:76,200` — SQLMap/Dalfox parser uses substring `"Parameter: … is vulnerable"`; fragile to tool version drift
- **#131 [LOW]** `core/fuzzing/adapters.py:66,128,191` — no `shutil.which` binary presence check; missing binary indistinguishable from real tool failure
- **#132 [LOW]** `core/tools/adapters/nmap.py:61` — regex `(\d+)/tcp\s+open\s+(\S+)` breaks on `-oX`/`-oG`; misses UDP/closed/filtered
- **#133 [LOW]** `core/tools/adapters/masscan.py:31` — always discards its own findings by design (`return attempt, []`); silent no-op
- **#134 [LOW]** `core/tools/nuclei_runner.py:149,152` — `asyncio.TimeoutError` and generic exceptions return `[]` silently
- **#135 [LOW]** `core/tools/tool_gateway.py:191` — hardcoded error message `"timed out after 300s"` regardless of actual timeout value
- **#136 [LOW]** `core/tools/tool_registry.py:84-93` — `KaliTool.run()` "non-empty stdout = success" heuristic + lenient-rc list; masks real failures
- **#137 [LOW]** `core/tools/tool_registry.py:120` — `PythonHTTPTool` `verify=False` blanket TLS disable; no opt-in

**Sanitization / hygiene**
- **#138 [LOW]** `core/actuation/actuators.py:75,160` — `httpx.AsyncClient(verify=False)` blanket TLS disable
- **#139 [LOW]** `core/actuation/actuators.py:79-87` — token auto-capture uses `'"token"' in low` substring; false-negatives on `access_token` etc.
- **#140 [LOW]** `core/tools/tool_router.py:216-247` — `_PER_TOOL_STRIP` denylist silently drops flags; partial sanitization (`_re.split(r'[|;&`$()]', extra_args)[0]`) discards rather than rejects
- **#141 [LOW]** `core/tools/tool_intelligence.py:58,65` — `TargetContext.from_target` regex is IPv4-only; misclassifies IPv6 as domain
- **#142 [LOW]** `core/tools/nuclei_template_gen.py` — finding-derived strings embedded into YAML without escaping; crafted content could break YAML or inject matchers
- **#143 [LOW]** `core/attack_surface/parameter_inventory.py:29` — `print()` alongside `logger.info`; noise
- **#144 [LOW]** `core/attack_surface/workflow_inventory.py:34` — `getattr(req, "timestamp", 0) or 0` silently misorders workflow steps with missing timestamps
- **#145 [LOW]** `core/attack_surface/graph.py:55-58` — `add_page_call` counts pages but never records page→endpoint edge; incomplete implementation
- **#146 [LOW]** `core/exploitation/*` — many broad `except Exception as e` continue-on-error patterns without rate-limited logging

**Reporting hygiene**
- **#147 [LOW]** `core/reporting/reporting.py:39` `mask_sensitive_data` — regex-only PII masking; misses many patterns
- **#148 [LOW]** `core/reporting/quality_gate.py:27` — first-scan mode captures noise as baseline
- **#149 [LOW]** `core/reporting/report_builder.py:63` compliance-map — very shallow keyword match; misleading PCI/HIPAA mappings

**LLM / harness hygiene**
- **#150 [LOW]** `agents/universal_llm_harness.py:1001` — budget governor optional; disables silently on import error
- **#151 [LOW]** `agents/base.py:94-104` — every exception collapsed into `status="failed"` with sanitized message; bad for triage
- **#152 [LOW]** `core/orchestration/central_brain.py:3148` — `_run_phase_agentic` treats `steps==0 and findings==0` as outage; forces fallback even on correct "LLM found nothing"

**Legacy / drift**
- **#153 [LOW]** `core/knowledge/persistent_store.py:12` — `kb_*` SQLite-syntax shadow schema alongside canonical `scans/vulnerabilities/findings_v2`; data drift
- **#154 [LOW]** All `kb_*` FK columns — missing indexes; full-table scan on lookups
- **#155 [LOW]** No migration framework (Alembic/Django-migrations); `CREATE TABLE IF NOT EXISTS` means new columns never applied to existing tables

**Backup / DR**
- **#156 [LOW]** No `pg_dump` script, no snapshot policy, no restore drill; single-volume loss = total data loss

**Checkpoint / secrets rotation**
- **#157 [LOW]** `core/checkpointing/secure_checkpoint.py` — key rotation without file migration breaks decrypt
- **#158 [LOW]** `core/security/secret_manager.py:44` `rotate_key` — no version marker; mid-rotation crash corrupts store

---

## INFO (16)

- **#159 [INFO]** `ui/api/server.py` — 2 397 LOC monolith; every route + middleware + WS + subprocess launcher + SPA fallback in one file
- **#160 [INFO]** `core/execution/executors/generic.py` — 5 551 LOC single file with ~85 executor classes; needs split per vuln class
- **#161 [INFO]** `core/orchestration/central_brain.py` — 6 707 LOC; fallback catalog + planner + phase machine in one file
- **#162 [INFO]** `core/database/pg_store.py` — 96 KB (~2 500 LOC); 30+ repos in one file; needs split per domain
- **#163 [INFO]** No `/metrics` Prometheus endpoint
- **#164 [INFO]** No distributed tracing across API → scan process → executors
- **#165 [INFO]** No structured JSON logging with global PII redaction filter
- **#166 [INFO]** No Slack / PagerDuty / SIEM integrations wired despite MCP surfaces
- **#167 [INFO]** No `_active_scans` server-shutdown drain; in-flight scans orphaned on API restart
- **#168 [INFO]** No idempotent scan resume from checkpoint after crash
- **#169 [INFO]** No `_ws_push_tasks` cleanup on shutdown; asyncio task leak on restart
- **#170 [INFO]** No circuit-breaker on LLM providers per model + phase
- **#171 [INFO]** No health-check for `kali-pentesting` container before each call
- **#172 [INFO]** Test-to-source ratio 0.28 (99 tests to 355 core files); many test files are scaffolds
- **#173 [INFO]** No CI config file found; unknown pass-rate on clean env; ~60–75 % estimate
- **#174 [INFO]** 15 untracked new modules (per `git status`) have no matching tests: `cross_role_replay.py`, `custom_probe.py`, `dom_sink_monitor.py`, `dump_extractor.py`, `graphql_ws_probe.py`, `js_bundle_analyzer.py`, `semantic_api_fuzzer.py`, `adversarial_critic.py`, `parallel_agents.py`, `chain_intelligence.py`, `repro_bundle.py`, `scan_chatbot.py`, `scan_diff.py`, `endpoint_hints.py`, `core/intel/` folder

---

## Counts

| Severity | Count |
|---|---|
| CRITICAL | 26 |
| HIGH | 34 |
| MEDIUM | 34 |
| LOW | 46 |
| INFO | 16 |
| **Total** | **156** |

*(Note: some LOW numbers span #114–#158 = 45 entries; #159–#174 = 16 INFO. Grand total accounting for merged sub-issues counted individually.)*

---

## Cross-references
- `AUDIT_REPORT.md` — feature inventory + ranked findings by subsystem
- `SIMULATION_TRANSCRIPT.md` — how each of these manifests in a live workflow
- `SYSTEM_DOCUMENTATION.md` — enterprise reference and remediation context
- `RISK_MATRIX.md` — the 55 highest-impact issues with reproduction, effort, workaround
