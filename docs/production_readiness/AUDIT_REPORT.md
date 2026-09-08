# AUDIT REPORT — Production Readiness
**AntiGravity Autonomous Pentesting Platform**
Branch: `autonous-agent` · Commit head: `1f4784c` · Audit date: 2026-09-06
Auditor stance: Senior architect + senior AI engineer, adversarial. Assume nothing works.

---

## 0. Executive verdict

**NOT PRODUCTION READY.** Ship-blocking issues in five layers: authentication (no default gate), authorization (three overlapping scope validators, per-request enforcement missing across ~85 offensive executors), persistence (pool poisoning, plaintext credentials), reporting (fake XOR "encryption", cross-target dedup contamination), and supply chain (unpinned Kali rolling base + `go install @latest` + root containers with docker CLI mounted).

**Go-live estimate:** 4–6 engineer-weeks focused on P0/P1 items in `RISK_MATRIX.md` before a controlled internal beta. External-facing deployment requires additionally: pen-test of the platform itself, threat model sign-off, SOC 2 / ISO 27001 mapping if regulated customers are in scope.

**What works:** the offensive capability set is deep and well-decomposed; the reporting pipeline has multiple fallback paths; the RAG + LLM planner has a deterministic fallback and rich observability tables.

**What does not:** every production deployment gate — authn, authz enforcement, secret hygiene, data protection, resilience, supply chain, telemetry, backup — is unset, silently degraded, or subtly broken.

---

## 1. File structure & components

Total source files (excluding `node_modules`, `.git`, `__pycache__`, `venv`): **558**.

```
outputs/
├── agents/                    9  files  ~150 KB  LLM harness, exploit agent, Kali executor
├── core/
│   ├── access_control/       (target-app IDOR/RBAC probes)
│   ├── actuation/            4  files  ~30 KB   HTTP + browser "hands" for LLM
│   ├── adaptation/, analysis/, attack_surface/, authentication/  (target-side session mgmt)
│   ├── checkpointing/        SecureCheckpoint (env-keyed)
│   ├── cloud/, common/, compliance/, convergence/, coverage/
│   ├── database/pg_store.py  96 KB   40+ tables, 30+ repos
│   ├── decisions/, defensive/, discovery/, domain/, economics/, error/, escalation/
│   ├── evidence/oracle.py    10 oracle classes (differential/timing/reflection/DOM/OOB)
│   ├── execution/executors/  generic.py 5,551 LOC — 85 vuln-class executors
│   ├── exploitation/         29 files  ~230 KB  chain, credentials, GraphQL/WS, JWT, SSRF metadata, JS analysis
│   ├── findings/, fuzzing/, hypothesis/, identity/, injection/, intel/, intelligence/
│   ├── knowledge/            legacy `kb_*` SQLite-style schema (drift risk)
│   ├── learning/, llm/, memory/database.py (broken singletons — see §5)
│   ├── monitoring/, orchestration/central_brain.py (planner + brain mixins), parallel_agents.py
│   ├── prompts/              brain/ + prompt_variants/ + templates/
│   ├── rag/                  pgvector + HNSW + hash-embedding fallback
│   ├── reporting/            24 files  ~200 KB  HTML/PDF/JSON/MD/SARIF + LLM validator + retest
│   ├── scheduling/, scope/manager.py, scoring/, security/, skills/
│   ├── tools/                27 files  ~250 KB  tool adapters + rate limiter + registry + gateway
│   ├── validation/dedup.py, verification/critic_agent.py, workflows/
├── ui/
│   ├── api/server.py         93 KB   ~110 endpoints, monolith
│   └── web/                   Vite/React 19 SPA, no shared store
├── data/db/                  EMPTY  (SQLite paths referenced but no files)
├── payloads/, reports/, logs/, .antigravity/, .audit_logs/
├── Dockerfile (Kali)         root user, unpinned rolling base
├── Dockerfile.web            root user, mounts docker CLI + apt-adds Docker repo
├── requirements.txt          aiohttp/anthropic/boto3/psycopg2/playwright/weasyprint/xhtml2pdf/etc.
└── .env / .env.example       4 KB  ~40 env vars
```

### Architectural role by component

| Component | Type | Responsibility | Failure impact |
|---|---|---|---|
| `ui/api/server.py` | API monolith | HTTP entrypoint, scan launcher, WS broadcaster, SPA fallback | CRITICAL |
| `agents/universal_llm_harness.py` (50 KB) | LLM harness | Plan+dispatch loop, tool calls, provider switching | CRITICAL |
| `agents/exploit_agent.py` (53 KB) | Agent | Objective-driven exploitation loop | HIGH |
| `agents/kali_executor.py` | Subprocess | Runs tools inside `kali-pentesting` Docker container | CRITICAL (SPOF) |
| `core/orchestration/central_brain.py` | Planner | Phase orchestration, deterministic fallback, scan lifecycle | CRITICAL |
| `core/database/pg_store.py` | Data layer | Every persistence op | CRITICAL |
| `core/memory/database.py` | Conn pool | Class-level ThreadedConnectionPool | CRITICAL (SPOF) |
| `core/rag/pipeline.py` | RAG | pgvector HNSW retrieval + hash fallback | MEDIUM |
| `core/scope/manager.py` + `core/security/authorization.py` | Authz | Scope validation — 3 disjoint validators | CRITICAL |
| `core/reporting/reporting.py` | Report | HTML/PDF assembly, XOR trend store, LLM exec-summary | HIGH |
| `core/execution/executors/generic.py` | Executor | 85 vuln-class HTTP probes, no per-request scope | CRITICAL |
| `core/actuation/actuators.py` | Agent tool | HTTP/JWT/upload "hands" — scope-checked (positive exception) | MEDIUM |
| `ui/web/src/pages/ScanDetail.jsx` (68 KB) | Frontend | Single-view catchall for scan results | MEDIUM |

---

## 2. Feature inventory (representative — full catalog in `SYSTEM_DOCUMENTATION.md`)

Legend: ✓ = production-quality; ⚠ = works but has significant reliability or correctness caveats; ✗ = broken / dead code / disabled by default.

| # | Feature | File:Line | Inputs (validated?) | Outputs / Errors | Callers | Async | Errors handled | Status |
|---|---|---|---|---|---|---|---|---|
| 1 | Scan launch | `ui/api/server.py:1247` `POST /api/scans/run` | `ScanRequest{target,tier,phases,credentials[]}` — **no URL/scope validation** | `{job_id}`; subprocess argv leaked in `_active_scans` | LiveScan.jsx | Yes | Broad `try/except` | ⚠ |
| 2 | WebSocket live feed | `ui/api/server.py:1613` `WS /ws/scan/{job_id}` | subprotocol string only | log lines | api.js | Yes | reconnect on client | ✗ (bypasses API-key middleware) |
| 3 | Evidence file serve | `ui/api/server.py:2149` `GET /api/evidence/{filename}` | regex `^[\w\-\.]+$` — **`..` matches** | file bytes | ScanDetail | Yes | none | ✗ (path traversal) |
| 4 | RAG file ingest | `ui/api/server.py:2271` `POST /api/rag/ingest/file?file_path=` | arbitrary local path | content chunks | none in UI | Yes | none | ✗ (arbitrary read) |
| 5 | Kill-all scans | `ui/api/server.py` `POST /api/scans/kill-all` | none | ok | Settings.jsx | Yes | broad | ⚠ (unauth by default + no rate limit) |
| 6 | Central brain plan | `core/orchestration/central_brain.py` `plan_next` | scan state, LLM tier | `List[Task]` | scan loop | Yes | falls to deterministic | ⚠ |
| 7 | LLM harness call | `agents/llm_harness_adapter.py:17` `chat` | prompt, tier | text | brain, validators | Yes | provider fallback | ⚠ (LARGE tier defaults to non-reasoning `deepseek-chat`) |
| 8 | Escalation gate | `core/escalation/escalation_gate.py` `request_approval` | action, risk | approval | agent loop | Yes | fail-closed on timeout | ✓ |
| 9 | Executor pipeline | `core/execution/execution_pipeline.py:110` `execute` | `SecurityExperiment` | `ExecutionResult` | brain | Yes | broad | ⚠ (no per-experiment scope check) |
| 10 | Base executor `validate_target` | `core/execution/executors/base.py:44` | endpoint, identity | `(bool, str)` | **NONE** | — | — | ✗ (dead code, ~85 subclasses inherit and none override with real check) |
| 11 | HTTP actuator | `core/actuation/actuators.py:63` `http_request` | method/path/body | JSON | agent_loop, LLM | Yes | broad | ⚠ (`verify=False`) |
| 12 | Browser actuator | `core/actuation/browser_actuator.py:99` `run_actions` | actions[] | JSON | agent_loop | Yes | broad | ⚠ |
| 13 | Actuator scope check | `core/actuation/actuators.py:53` `_in_scope` | url | bool | http_request/upload | No | fail-closed | ✓ (rare positive) |
| 14 | Findings insert | `core/database/pg_store.py:937` `VulnRepo.bulk_insert` | dicts | rowcount | brain, reporter | No | swallowed | ⚠ (N+1) |
| 15 | Dedup fingerprint | `core/validation/dedup.py:56` | vuln dict | hash | classify | No | — | ⚠ (title-lowercased; `file_path` empty for web = collisions) |
| 16 | Dedup mark_resolved | `core/validation/dedup.py:160` | scan_id | rows | classify | No | — | ✗ (no target scoping → cross-target contamination) |
| 17 | LLM validator | `core/reporting/llm_validator.py:218` `validate_findings` | list of findings | verdicts | quality gate | Yes | LLM circuit-breaker | ⚠ (prompt injection via `proof`/`details` unescaped) |
| 18 | ML FP filter | `core/reporting/fp_filter.py:222` | features | probability | validator | No | broad | ✗ (default trains on 7 synthetic rows; persists to disk) |
| 19 | Retest engine | `core/reporting/retest_engine.py:360` `retest_findings` | findings | rows | quality gate | Yes | broad | ⚠ (network error → `UNCONFIRMED` @ 0.30 confidence) |
| 20 | Chain intelligence | `core/reporting/chain_intelligence.py:90` `synthesize_chains` | scan_id | chains | reporter | Yes | broad | ⚠ (raw evidence into LLM prompt) |
| 21 | Repro bundle | `core/reporting/repro_bundle.py:120` | findings | zip files | reporter | No | broad | ✓ (title sanitized) |
| 22 | PDF export chain | `core/reporting/reporting.py:681` | HTML | `.pdf` | reporter | No | logged @ INFO only | ⚠ (WeasyPrint → xhtml2pdf → pdfkit → fpdf2 silent degrade on Windows) |
| 23 | SARIF export | `core/reporting/sarif_export.py:35` | findings | SARIF 2.1.0 | reporter | No | — | ✓ |
| 24 | Trend store | `core/reporting/reporting.py:72` `EncryptedTrendStore` | dict | file | reporter | No | broad | ✗ (XOR with hardcoded default key; not encryption) |
| 25 | Executive summary | `core/reporting/reporting.py:283` | findings | HTML | reporter | No | broad | ⚠ (Jinja2 not sandboxed) |
| 26 | Scope validate URL | `core/scope/manager.py:82` | url | bool | brain | No | fail-closed | ⚠ (trailing dot/IDN not normalized) |
| 27 | TargetScopeValidator | `core/security/authorization.py:27` singleton | host/ip | bool | actuators | No | fail-closed | ⚠ (disjoint from ScopeManager) |
| 28 | LegalValidator | `core/security/legal_validator.py` | SOW dates/hashes | bool | brain | No | fail-closed | ⚠ (audit-only) |
| 29 | Secret decrypt | `core/security/encryption.py:36` | .antigravity/secrets.enc | dict | secret_manager | No | falls to default key | ✗ (hardcoded `DEFAULT_FALLBACK_KEY_RAW`) |
| 30 | Audit log append | `core/security/audit_logger.py` | event | JSONL | many | No | broad | ⚠ (no rotation, unbounded) |
| 31 | DB connection pool | `core/memory/database.py:65` `get_connection` | — | conn | all repos | No | **no rollback in finally** | ✗ (pool poisoning) |
| 32 | KnowledgeStore init | `core/knowledge/persistent_store.py:12` | — | inst | brain | No | — | ✗ (not a singleton — re-runs schema+dedupe migration on every construction) |
| 33 | RAG ingest chunk | `core/rag/pipeline.py:130` `_store_chunk` | text | rowid | ingest | No | broad | ⚠ (SELECT-then-INSERT race) |
| 34 | Live progress upsert | `core/database/pg_store.py:1015` | scan_id, data | id=1 row | brain | No | broad | ✗ (singleton row: concurrent scans overwrite) |
| 35 | Live agents panel | `core/database/pg_store.py:626` schema | rows | rows | UI | No | swallowed | ⚠ |
| 36 | Auth bypass store | `core/database/pg_store.py:594` | login artifacts | rows | brain | No | swallowed | ✗ (plaintext password/token columns) |
| 37 | OSINT / threat intel | `core/intelligence/threat_intel.py:24` | domain/IP | dict | recon | Yes | broad | ✗ (`ssl._create_unverified_context()` globally) |
| 38 | Censys client | `core/intelligence/censys_client.py:32` | domain | dict | recon | Yes | `raise ValueError` when key missing | ⚠ (should degrade, not crash) |
| 39 | Nuclei runner | `core/tools/nuclei_runner.py:64` | targets, templates | JSONL | tool_router | Yes | broad | ⚠ |
| 40 | Kali docker exec | `agents/kali_executor.py` `.run` | cmd, timeout | stdout/stderr | discovery, actuators, reporter | Yes | broad | ⚠ (single named container = SPOF) |
| 41 | SQLMap adapter | `core/fuzzing/adapters.py:23` | endpoint | ToolResult | fuzzer | No | 30s timeout | ⚠ (no binary-presence check, substring parse) |
| 42 | API schema importer | `core/discovery/api_schema_importer.py:45` | target | endpoints | brain | Yes | broad | ✗ (f-string curl cmd — shell injection into container exec) |
| 43 | JS analyzer | `core/discovery/js_analyzer.py` | html/URLs | endpoints/secrets | brain | Yes | broad | ✗ (same f-string curl pattern) |
| 44 | Escalation gate webhook | `core/escalation/escalation_gate.py:257` | url | — | approval | Yes | broad, silent | ✓ |
| 45 | Frontend polling | `ui/web/src/pages/LiveScan.jsx:141` | — | state | many pages | Yes | `.catch(()=>{})` | ⚠ (races WS writes) |

The full 200-row feature catalog is in `SYSTEM_DOCUMENTATION.md §3`.

---

## 3. Dependency graph — critical edges

```
                        ┌────────────────────────────┐
   Browser (React) ───► │ ui/api/server.py (monolith)│ ◄─── WS /ws/scan/{job_id} (NO AUTH)
                        └───────────┬────────────────┘
                                    │ spawn subprocess (shell=False)
                                    ▼
   .antigravity/*  ◄──── agents/exploit_agent.py ─── central_brain.py ───► LLM (deepseek/groq/ollama)
                            │           │                 │
                            │           │                 ├──► ScopeManager  ─┐
                            │           │                 ├──► TargetScopeVal ├── 3 disjoint singletons
                            │           │                 └──► LegalValidator ┘
                            │           │
                            ▼           ▼
                   agents/kali_executor.py       core/execution/executors/generic.py (85 classes)
                            │                                  │
                            │                                  │  urllib.request.urlopen (no scope gate)
                            ▼                                  ▼
                   docker exec kali-pentesting            live target endpoints
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
        nmap, nuclei,   playwright     hashcat, hydra
        ffuf, sqlmap    (chromium)
                                                  ▲
                                                  │ tools invoked by tool_router
                                                  │
                    core/tools/tool_router.py, tool_registry.py, tool_gateway.py

                        ┌────────────────────────────┐
                        │ core/memory/database.py    │  ─── ThreadedConnectionPool (min=5,max=20)
                        │  get_connection() @ctx     │      NO rollback in finally
                        └───────────┬────────────────┘
                                    │
                        ┌───────────▼────────────┐
                        │ PostgreSQL 40+ tables  │  ── ON DELETE CASCADE from scans to 6 tables only
                        │ pgvector HNSW          │  ── 20+ tables have no FK to scans
                        └───────────┬────────────┘
                                    │
                        ┌───────────▼────────────┐
                        │ core/knowledge/kb_*    │  Legacy SQLite-syntax parallel schema (drift)
                        └────────────────────────┘
```

### Circular imports and dangling references
- No true Python circular import errors on boot (verified — server starts).
- Dangling: `ExecutorBase.validate_target()` (`core/execution/executors/base.py:44`) — declared, implemented by every executor, called by nothing.
- Dangling: `_browser_available()` (`core/execution/executors/generic.py:5238`) — never called by the Tier-8 browser executors that it exists to preflight.
- `core/knowledge/persistent_store.py` `kb_*` tables ingest data but modern code paths write to `findings_v2`, `vulnerabilities` — `kb_*` reads are minimal, effectively write-only shadow schema.
- `api.js` exports the `attack-chains` key twice (duplicate ES object literal key).
- `ui/api/server.py:813` and `:2188` both register `/api/scans/{scan_id}/attack-chains` — FastAPI uses last; first is dead code.

---

## 4. Critical findings ranked

### P0 — Production blockers (10)
1. **API auth off by default** — `ui/api/server.py:44` `if not _API_KEY: return await call_next(request)`. Fresh deploy on `0.0.0.0:8903` is completely open. CORS defaults to `*`. WS bypasses even that.
2. **Per-request authorization missing across ~85 executors** — `ExecutorBase.validate_target()` is dead code; `execution_pipeline.py:110` calls executor without any scope check; every executor in `generic.py` inherits a `(True, None)` no-op. Only `core/actuation/actuators.py` and `browser_actuator.py` enforce scope per call.
3. **DB connection pool poisoning** — `core/memory/database.py:71-75` uses `putconn` in `finally` without `rollback`. Any transient exception poisons the pool of 20 with aborted transactions; subsequent borrowers get `InFailedSqlTransaction` → cascading failure across all repos.
4. **Hardcoded encryption fallback** — `core/security/encryption.py:19` `DEFAULT_FALLBACK_KEY_RAW = b"ANTIGRAVITY_DEFAULT_KEY_32BYTES!"`. When `ENCRYPTION_KEY` is unset (default), the entire `.antigravity/secrets.enc` store is decryptable from source.
5. **Fake "encryption" of trend store** — `core/reporting/reporting.py:72` XOR against `TREND_STORE_KEY` default `"AntiGravityTrendSecretKey2026"`. Two known-plaintext bytes recover the key.
6. **Plaintext credentials in DB** — `core/database/pg_store.py:594` `auth_bypasses.password TEXT`, `token TEXT`. Passwords and JWTs stored unencrypted.
7. **Cross-target dedup contamination** — `core/validation/dedup.py:160` `mark_resolved` scoped only by `scan_id`, not by target. Scanning target B silently marks every open finding on target A as `RESOLVED`.
8. **TLS verification globally disabled** — `core/intelligence/threat_intel.py:24` `ssl._create_unverified_context()`. All threat-feed intel is MITM-injectable → decisioning corruption.
9. **Path traversal on `/api/evidence/{filename}`** — `ui/api/server.py:2149` regex `^[\w\-\.]+$` matches `..`; no `Path.resolve()` boundary check.
10. **Arbitrary file read via `POST /api/rag/ingest/file?file_path=`** — `ui/api/server.py:2271`. Attacker reads `.env`, `secrets.enc`, `id_rsa`.

### P1 — High severity (15)
11. **Unauthenticated WebSocket** — `ui/api/server.py:1613` `/ws/scan/{job_id}` bypasses HTTP middleware; live logs contain raw tokens/cookies captured during recon.
12. **Credentials leaked via subprocess argv** — `ui/api/server.py:245` passwords JSON-serialized into argv; `_active_scans[job_id]["command"]` is returned by `GET /api/scans/job/{job_id}`.
13. **Prompt injection into LLM validator** — `core/reporting/llm_validator.py:48-75` interpolates `proof`, `details`, `evidence` unescaped; attacker-controlled response body can flip verdict to false-positive.
14. **Retest engine downgrades on network error** — `core/reporting/retest_engine.py:122` treats `network_error` and `endpoint_returned_negative` identically → confirmed findings drop to 0.30 confidence on transient WAF/proxy 500s.
15. **ML FP filter trained on 7 synthetic rows** — `core/reporting/fp_filter.py:88`. Persists to `data/models/fp_model.joblib`; noise-model can relegate real findings to LOW.
16. **PDF silently degrades to plain text on Windows** — WeasyPrint requires libgobject/cairo; fallback chain lands at fpdf2 which strips tags. Logged at INFO, not WARN. `report.pdf` shipped is a text dump with no tables.
17. **Rolling Kali base + unpinned `go install @latest`** — `Dockerfile:19-29`. Every rebuild ships a different toolchain; supply chain unauditable.
18. **Containers run as root; web container mounts Docker CLI** — RCE in the API escapes to host trivially via `docker.sock` or `docker exec`.
19. **`KnowledgeStore()` / `MemoryDatabase()` are NOT singletons** — constructing them re-runs `_init_schema()` and the dedupe DELETE migration (`pg_store.py:711`). Called from `core/orchestration/central_brain.py:476`.
20. **Broken SQLite-syntax memory stores** — `core/memory/experience_store.py`, `failure_store.py`, `strategy_store.py` call `.cursor()` on a context manager → `AttributeError` on every call. Dead on arrival.
21. **N+1 bulk writes** — `pg_store.py:937,1096,1415,1492,1704,1746`. Uses `execute_values` nowhere; a 500-finding scan makes 500 round trips.
22. **`ScopeManager` and `TargetScopeValidator` are independent singletons** — scope updates to one don't propagate to the other; enforcement inconsistency across the codebase.
23. **`SELECT-then-INSERT` race** — `pg_store.py:1185` `DedupRepo.check_and_insert`. Two threads both INSERT → IntegrityError → poisoned connection (compounds with #3).
24. **Shell injection surface in discovery** — `core/discovery/api_schema_importer.py:50-54`, `js_analyzer.py:101,165,185` build curl commands with f-strings including user-controlled URLs, executed via `KaliDockerExecutor.run`.
25. **RAG `pipeline._store_chunk` race** — `core/rag/pipeline.py:130` SELECT-then-INSERT; non-unique hash idx allows duplicate storage under concurrent ingest.

### P2 — Medium severity (12)
26. Race conditions in frontend polling vs WS (`LiveScan.jsx:141`) — WS write can be overwritten by delayed poll response; no `AbortController` anywhere.
27. Duplicate route `/api/scans/{scan_id}/attack-chains` (`server.py:813` and `:2188`).
28. Duplicate key `attack-chains` in `api.js` exported object.
29. Silent failures in `_probe()` (`generic.py:80-82`) return `(0, "", {})` on any exception — indistinguishable from real empty responses.
30. `_run_async` (`generic.py:2480`) thread leak on hung coroutine (45s join, no `is_alive` check).
31. `_LLMBudget._calls` (`generic.py:2465`) never resets across scans in a long-lived process.
32. `_run_in_kali` shell=True (`generic.py:5231`) — low practical risk (env-sourced container name) but bad hygiene.
33. Missing indexes on hot-path ORDER BY columns: `audit_log.timestamp`, `execution_audit.timestamp`, `findings_dedup.last_seen`, `scans.started_at`, `experiences.*`.
34. Unbounded list queries: `TargetRepo.list_all`, `ScanRepo.list_all`, `FindingV2Repo.list_all`.
35. No log rotation for `.audit_logs/audit.jsonl` — unbounded growth.
36. No backup script for Postgres; `data/db/` empty; single-volume-loss = total data loss.
37. `.env.example` ships default `POSTGRES_PASSWORD=pentesting_password`.

### P3 — Low / hygiene (10)
38. Hardcoded API-URL in `Settings.jsx:75` diverges from real port (`vite.config.js` targets 8903, UI says 8900).
39. Every fetch uses `.catch(()=>{})` — auth failures render as blank tables silently.
40. `add_osint_findings` uses `report_html.replace('</main>', osint_html+'</main>')` — corrupts pages with multiple `</main>` (`reporting.py:845`).
41. `sarif_export` fingerprint truncated to short hash → collisions on large scans.
42. `NON_HTML_CONTENT_TYPES` in `fp_filter.py:24` lists `application/javascript`, dropping real JSONP-XSS findings.
43. `_get_field` misuses in `poc_generator.py`.
44. Console output uses `print()` alongside `logger.info` in `parameter_inventory.py:29`.
45. `chain_intelligence.py:105` truncates JSON mid-string into LLM prompt.
46. `dedup.py:66-75` fingerprint collision: title-lowercased and `file_path` empty for web findings → `/api/v1` and `/api/v2` collide.
47. `AttackChainRepo.bulk_upsert` `ON CONFLICT DO NOTHING` without target column — raises on the actual conflict.

---

## 5. Single points of failure (SPOF)

| # | SPOF | Location | Cascading impact | Mitigation |
|---|---|---|---|---|
| 1 | `DatabaseManager._pool` | `core/memory/database.py:21` | Pool poisoning kills all repos | Add `rollback` in `finally`; add health check |
| 2 | Single `kali-pentesting` container | `.env:80` | Every offensive tool call fails; brain wedges on `DOCKER_TIMEOUT=1200` | Named pool of containers + healthcheck |
| 3 | DeepSeek as sole default LLM provider | `.env.example:12` | LLM planner degrades to deterministic fallback; retest/validation no-ops | Configure Groq / Ollama fallback explicitly |
| 4 | `TargetScopeValidator._instance` singleton | `core/security/authorization.py:30` | First accessor wins; re-scoping silent no-op | Repository-of-record pattern |
| 5 | `pgvector` extension | `pg_store.py` `_init_extensions` | If missing, `rag_documents` DDL silently fails; RAG dead, rest of app runs | Startup preflight |
| 6 | `.audit_logs/audit.jsonl` single file | `core/security/audit_logger.py` | Corruption breaks tamper-evidence chain | Rotate; ship to WORM sink |
| 7 | `live_progress` / `live_results` (id=1) row | `pg_store.py:1015` | Concurrent scans overwrite each other's progress | Per-scan row keyed by `scan_id` |
| 8 | `ui/api/server.py` monolith | 93 KB single file | Bug in any route can crash whole API | Split into APIRouters |
| 9 | `_pipeline` global in `core/rag/pipeline.py:24` | Module-level | Not thread-safe; race on first init | `threading.Lock` around init |
| 10 | `ExecutorBase.validate_target` dead | `base.py:44` | No per-request scope enforcement → out-of-scope scanning possible | Wire into `execution_pipeline._execute` |
| 11 | ReportLab as only real PDF path on Windows | `reporting.py:681` | Import failure → `.pdf` becomes tag-stripped text | Preflight; ship native libs |
| 12 | `agents/llm_harness_adapter.py:17` DEEPSEEK_LARGE_MODEL default `deepseek-chat` | Non-reasoning model for LARGE-tier tasks | JSON planning failures | Change default to `deepseek-reasoner` |

---

## 6. Concurrency & race condition analysis

| Site | Race | Consequence | Fix |
|---|---|---|---|
| `DedupRepo.check_and_insert` (`pg_store.py:1185`) | SELECT-then-INSERT | `IntegrityError` poisons pool | `INSERT … ON CONFLICT (signature) DO UPDATE` |
| `RAGPipeline._store_chunk` (`pipeline.py:130`) | SELECT-then-INSERT | Duplicate chunks | Unique index + `ON CONFLICT DO NOTHING` |
| `live_progress`/`live_results` (id=1) | Two scans upsert same row | Progress bar shows the wrong scan | Key by `scan_id` |
| `auth_registry._ACTIVE` (`executors/auth_registry.py:14`) | No lock | Header bleed across concurrent scans | `threading.Lock` |
| `_LLMBudget._calls` (`generic.py:2465`) | Class-level counter | Under-count across scans in long-running process | Per-scan budget instance |
| Frontend WS + poll (`LiveScan.jsx:141`) | Poll response arrives after WS update | Newer data overwritten by older | Request generation + `AbortController` |
| `ConnectionManager` (`server.py:1520`) | In-memory subscriber set, no lock | Late unsubscribe races broadcast | `asyncio.Lock` per job_id |
| `_ws_push_tasks` (`server.py:1561`) | No cleanup on shutdown | Task leak | Track and cancel on lifespan close |
| `escalation_gate` queue file (`escalation_gate.py:148`) | Cross-process rewrite | Lost updates between agent + operator | fcntl or DB queue |
| `TrendStore` (`reporting.py:72`) | Reader/writer XOR file | Truncation | atomic replace |

**No `asyncio.Lock` / `threading.Lock` audit systematically:** grep returned <10 lock usages across 558 files. This is far too few for a system with claimed multi-tenant / campaign parallelism (`CampaignRequest.max_parallel`).

---

## 7. Data consistency analysis

Non-transactional multi-step writes discovered:
- **Scan lifecycle** — `ScanRepo.create` + `VulnRepo.bulk_insert` + `ScanRepo.update_status`("finished") are three separate transactions. A crash between them yields a scan with `status="running"` forever and partial findings. No compensating cleanup on boot.
- **Findings + dedup + audit** — `VulnRepo.bulk_insert` then `DedupRepo.classify` then `AuditRepo.log_event` — no atomicity. Dedup could mark findings resolved, then vuln insert fails, leaving inconsistent state.
- **Attack chain regeneration** — DELETE old + INSERT new not wrapped in a transaction (`pg_store.py:1697`); a crash mid-write leaves partial chains.

Recovery: none. No `bootstrap_recover()` sweeper marks orphaned "running" scans failed on process start. Confirm by grepping — no such recovery routine exists.

---

## 8. Deployment gates — what must be true before shipping

Full gate list in `SYSTEM_DOCUMENTATION.md §10`. Minimum bar:

1. **Auth**: `API_KEY` required at boot (refuse to start if unset); `X-API-Key` sent by `api.js`; WebSocket enforces same key via subprotocol or handshake.
2. **CORS**: `CORS_ORIGINS` explicit allowlist, no `*`.
3. **Authz**: `ExecutorBase.validate_target()` wired into `execution_pipeline._execute` and called before every executor. `ScopeManager`, `TargetScopeValidator`, `LegalValidator` unified behind a single façade.
4. **Data protection**: `auth_bypasses.password/token` encrypted with `cryptography.Fernet` (real key). `ENCRYPTION_KEY` hard-required. `TrendStore` replaced. TLS verification restored in `threat_intel.py`.
5. **Persistence**: connection pool `rollback` in `finally`. `KnowledgeStore`/`MemoryDatabase` as real singletons. `execute_values` for bulk. Broken SQLite-syntax stores fixed or removed.
6. **Supply chain**: pinned base image digest, pinned Go tool versions, container runs as `USER app`, no docker.sock mount.
7. **Backup**: automated `pg_dump` + tested restore.
8. **Telemetry**: log rotation on `.audit_logs`, structured logging with PII redaction wrapper, `/metrics` Prometheus endpoint.
9. **Migrations**: Alembic or equivalent; `CREATE TABLE IF NOT EXISTS` replaced with versioned migrations.
10. **Rate limiting**: `slowapi` on `/api/scans/run`, `/api/scans/kill-all`, `/api/rag/ingest/*`.

---

## 9. Test coverage estimate

- Source `.py` files under `core/`: 355
- Test files `tests/test_*.py`: 99
- Ratio ≈ 0.28 test files per source file
- No coverage report artifact, no CI config file discovered
- Estimate: 60–75 % green on a clean environment; many `test_moduleX_Y_*.py` are scaffolds

Untracked new modules with **no matching tests**:
- `core/exploitation/cross_role_replay.py`
- `core/exploitation/custom_probe.py`
- `core/exploitation/dom_sink_monitor.py`
- `core/exploitation/dump_extractor.py`
- `core/exploitation/graphql_ws_probe.py`
- `core/exploitation/js_bundle_analyzer.py`
- `core/exploitation/semantic_api_fuzzer.py`
- `core/orchestration/adversarial_critic.py`
- `core/orchestration/parallel_agents.py`
- `core/reporting/chain_intelligence.py`
- `core/reporting/repro_bundle.py`
- `core/reporting/scan_chatbot.py`
- `core/reporting/scan_diff.py`
- `core/common/endpoint_hints.py`
- `core/intel/` (entire folder)

These are actively worked-on modules (per `git status`) with 0 % test coverage.

---

## 10. What to fix first (industry-ready sequencing)

**Week 1 — Stop-the-bleed**
- Wire `validate_target()` into the execution pipeline (P0-2)
- Require `API_KEY` at boot; ship `X-API-Key` from `api.js` (P0-1)
- Fix connection pool `rollback` (P0-3)
- Replace XOR trend store with Fernet (P0-5)
- Sanitize evidence-file path (P0-9)
- Remove `/api/rag/ingest/file?file_path=` or allowlist under a base dir (P0-10)

**Week 2 — Data safety**
- Encrypt `auth_bypasses.password/token`; drop plaintext columns (P0-6)
- Scope `mark_resolved` by target (P0-7)
- Restore TLS verification in threat intel (P0-8)
- Fix hardcoded encryption fallback — hard-fail (P0-4)
- Consolidate three scope validators (P1-22)

**Week 3 — Resilience**
- Fix broken SQLite-syntax memory stores (P1-20)
- Fix KnowledgeStore singleton (P1-19)
- `execute_values` for bulk writes (P1-21)
- Per-`scan_id` `live_progress` rows (SPOF-7)
- Alembic migrations, PG backup + restore drill

**Week 4 — Supply chain + observability**
- Pin Docker base + Go tools; drop root; healthchecks (P1-17, P1-18)
- Rate limiting via `slowapi`
- Log rotation + PII redaction wrapper
- `/metrics` Prometheus endpoint, dashboards for pool utilization, LLM error rate, per-scan latency

**Weeks 5–6 — External pen-test of the platform itself + threat-model review + SOC 2 mapping (if applicable).**

Detailed risk-scored fix inventory in `RISK_MATRIX.md`.
