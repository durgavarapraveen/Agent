# SYSTEM DOCUMENTATION — AntiGravity Autonomous Pentesting Platform
Version audited: branch `autonous-agent` · commit `1f4784c` · 2026-09-06
Purpose: enterprise reference for on-call, security engineering, and incident response.

---

## 1. Architecture overview

### 1.1 Deployment topology (target)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              Private VPC                                     │
│                                                                              │
│    ┌────────────────┐         ┌──────────────────┐        ┌──────────────┐   │
│    │  Reverse proxy │         │  ui/api monolith │        │ PostgreSQL   │   │
│    │  (nginx/ALB)   │─http/ws─│  FastAPI :8903   │───pg───│ 15 + pgvector│   │
│    │  + WAF + rate  │         │  + SPA fallback  │        │ 40+ tables   │   │
│    └───────┬────────┘         └────────┬─────────┘        └──────┬───────┘   │
│            │                           │                         │           │
│            │                           │ subprocess              │ backup    │
│            │                           ▼                         ▼           │
│    ┌───────┴────────┐         ┌──────────────────┐        ┌──────────────┐   │
│    │ Operator SPA   │         │ Scan process     │        │ S3 / WORM    │   │
│    │ (React 19)     │         │ CentralBrain     │        │ audit + bak  │   │
│    └────────────────┘         │ + LLM harness    │        └──────────────┘   │
│                               │ + Executors      │                           │
│                               └────┬─────────────┘                           │
│                                    │ docker exec                             │
│                                    ▼                                         │
│                          ┌──────────────────────┐                            │
│                          │ kali-pentesting       │                           │
│                          │ container            │                            │
│                          │ nmap, nuclei, ffuf,  │                            │
│                          │ sqlmap, hashcat,     │                            │
│                          │ playwright, ...      │                            │
│                          └──────────┬───────────┘                            │
│                                     │ scoped egress                          │
└─────────────────────────────────────┼────────────────────────────────────────┘
                                      ▼
                              Authorized target scope
                              + external OSINT APIs
                              (Shodan, Censys, VT,
                               AbuseIPDB, NVD, ...)
                                      ▲
                                      │
                                      │ LLM API
                                      ▼
                              DeepSeek / Groq / Ollama
```

### 1.2 Runtime request path (scan lifecycle)

```
Browser SPA
    │
    │ 1. POST /api/scans/run  ScanRequest{target,tier,phases,credentials}
    ▼
FastAPI middleware (API-key check — bypassed if not set)
    │
    ▼
server.py:1247  create job_id, subprocess.Popen(cmd, shell=False)
    │
    ├───► ws_scan_feed opens /ws/scan/{job_id}
    │
    ▼
CentralBrain.run_main_loop
    │
    ├───► ScopeManager.validate_plan()
    ├───► LegalValidator.check()
    │
    ▼  for phase in phases:
    │
    ├───► AgenticExecutor.execute(objective, phase)
    │     │
    │     ├───► UniversalLLMHarness.generate_with_tools()
    │     │     ├── DeepSeek → Groq → Ollama fallback
    │     │
    │     ├───► for tool_call in response.tool_calls:
    │     │     ├── ToolInvocationEngine.invoke()
    │     │     │     ├── ToolGateway.execute()
    │     │     │     │     ├── ToolRouter.route_and_execute() (auto-build cmd)
    │     │     │     │     └── KaliTool.run(command, timeout)
    │     │     │     │           └── KaliDockerExecutor.run(shell=True)
    │     │     │     │                 └── docker exec kali-pentesting <cmd>
    │     │     │
    │     │     └── finding_ingestion.parse_tool_output(stdout) → ctx.vulns
    │     │
    │     └───► central_brain_mixins.persistence._persist_vulnerabilities(ctx)
    │           [BROKEN — NameError on datetime; findings silently unpersisted]
    │
    ├───► CentralBrain._run_agent_exploitation()
    │     └── asyncio.gather(UniversalExploitAgent.execute(vuln) for vuln in ctx.vulns)
    │
    ├───► RetestEngine.retest_findings(findings)
    ├───► FalsePositiveFilter.should_report_finding(finding) [ML on synthetic data]
    ├───► LLMFindingValidator.validate_findings(findings) [prompt injection surface]
    ├───► DedupStore.classify(findings)  [+ mark_resolved — cross-target contamination]
    │
    ▼
EnterpriseReporter.build_html() → build_pdf() (Weasy→xhtml2pdf→pdfkit→fpdf2)
SARIFExporter.export()
RepBundleGenerator.generate_bundles_for_scan()
    │
    ▼
Postgres (findings_v2, scan_artifacts, scan_history, etc.)
    │
    ▼
Frontend polls + WS receives progress → ScanDetail.jsx renders
```

---

## 2. Component directory

| Name | Type | Purpose | Key files | Depends on | Failure impact |
|---|---|---|---|---|---|
| API monolith | FastAPI backend | HTTP + WS entrypoint, scan launcher, SPA fallback | `ui/api/server.py` (93 KB, 2 400 LOC) | Postgres, subprocess | **CRITICAL** — single failure kills all external access |
| React SPA | Frontend | Operator UI | `ui/web/src/{App.jsx,api.js,pages/*,components/*}` (React 19, Vite) | API monolith | HIGH |
| Central brain | Orchestrator | Phase state machine, planner, fallback modes | `core/orchestration/central_brain.py` (6 707 LOC) + `central_brain_mixins/` | LLM harness, DB, tool router | CRITICAL |
| LLM harness | AI infra | Multi-provider abstraction (DeepSeek/Groq/Ollama), tool-calling | `agents/universal_llm_harness.py` (1 230 LOC) + `llm_harness_adapter.py` | httpx, DeepSeek API | CRITICAL — no true fallback in practice |
| Agentic executor | Agent | ReAct-style planner+dispatch loop | `core/orchestration/agentic_executor.py` (2 763 LOC) | LLM harness | HIGH |
| Exploit agent | Agent | Objective-driven per-vuln exploitation | `agents/exploit_agent.py` (1 296 LOC) | LLM, Kali container | HIGH |
| Adversarial critic | Agent | Two-LLM attacker+critic wrapper | `core/orchestration/adversarial_critic.py` | LLM | MEDIUM |
| Parallel agents | Concurrency | Bounded fan-out with live tracker | `core/orchestration/parallel_agents.py` | asyncio | MEDIUM |
| Kali executor | Subprocess | `docker exec` runner | `agents/kali_executor.py` | Docker, `kali-pentesting` container | CRITICAL — SPOF |
| Tool registry | Tools | Kali + Python tool wrappers | `core/tools/tool_registry.py` (28 KB) | Kali executor | CRITICAL |
| Tool gateway | Tools | Auth + cache + rate limit + retry | `core/tools/tool_gateway.py` | Registry, rate limiter | HIGH |
| Tool router | Tools | Auto-builds shell commands per tool | `core/tools/tool_router.py` (27 KB) | Registry | HIGH |
| Tool validation | Security | Scope + policy gate | `core/tools/tool_validation.py` | Scope validator | HIGH — but bypassed by gateway path |
| Executor pipeline | Execution | SETUP → EXECUTE → COLLECT → VALIDATE → RECORD | `core/execution/execution_pipeline.py` | Executors, finding store | CRITICAL |
| Generic executors | Execution | 85 vuln-class HTTP probes | `core/execution/executors/generic.py` (5 551 LOC) | urllib, Playwright | HIGH |
| Actuators | Agent tools | HTTP/JWT/upload agent hands, scope-checked | `core/actuation/actuators.py`, `browser_actuator.py`, `agent_loop.py` | httpx, scope validator | MEDIUM |
| Escalation gate | Governance | Fail-closed approval queue with webhook | `core/escalation/escalation_gate.py` | file queue, webhook | HIGH |
| Discovery | Recon | OpenAPI/GraphQL/JS schema import | `core/discovery/*.py` | curl via Kali exec | MEDIUM — shell injection risk |
| Fuzzing | Offensive | sqlmap/nuclei/dalfox wrappers | `core/fuzzing/*.py` | subprocess | MEDIUM |
| Exploitation | Offensive | 29 vuln-class modules (JWT, SSRF, GraphQL, WS, chain) | `core/exploitation/*.py` | httpx, Kali | HIGH |
| Attack surface | Model | In-memory graph of endpoints/params/identities | `core/attack_surface/*.py` | — | HIGH |
| Reporting | Post-scan | HTML/PDF/JSON/MD/SARIF + retest + validator + FP + trends + chatbot | `core/reporting/*` (24 files) | LLM, PDF chain | HIGH |
| Validation | Post-scan | Dedup + confidence + reachability | `core/validation/*.py` | Postgres | HIGH |
| Verification | Post-scan | Critic agent | `core/verification/critic_agent.py` | LLM | MEDIUM |
| Evidence | Model | 10 oracle classes (differential/timing/reflection/DOM/OOB) | `core/evidence/oracle.py` | — | MEDIUM |
| Scoring | Post-scan | Confidence calibrator | `core/scoring/confidence_scorer.py` | — | MEDIUM |
| RAG | AI infra | pgvector HNSW + hash fallback + ingest | `core/rag/` | Postgres pgvector, embedding API | MEDIUM |
| Knowledge | Legacy | Duplicate `kb_*` SQLite-style schema | `core/knowledge/persistent_store.py` | Postgres | LOW — write-only shadow |
| Memory | AI infra | Experience / failure / strategy stores | `core/memory/{database,experience_store,failure_store,strategy_store}.py` | Postgres | CRITICAL — 3 stores broken |
| Scope | Security | ScopeManager | `core/scope/manager.py` | policy config | CRITICAL |
| Security | Security | TargetScopeValidator, encryption, secrets, policy | `core/security/*.py` (10 files) | env, .env | CRITICAL |
| Authentication (target) | Auth | Target-side session manager (form/JWT/bearer) | `core/authentication/*.py` | httpx | MEDIUM |
| Access control | Offensive | IDOR/RBAC probes on target | `core/access_control/*.py` | actuator | MEDIUM |
| Intelligence | Recon | OSINT + threat intel + subdomain enum | `core/intelligence/*.py` (14 files) | Shodan/Censys/VT/etc APIs | MEDIUM |
| Persistence | Storage | Central DB layer with 30+ repos | `core/database/pg_store.py` (96 KB) | Postgres | CRITICAL |
| Connection pool | Infra | ThreadedConnectionPool | `core/memory/database.py` | Postgres | CRITICAL — poisoning bug |
| Checkpointing | Resilience | SecureCheckpoint | `core/checkpointing/secure_checkpoint.py` | env encryption key | MEDIUM |
| Scheduling | Ops | Recurring scan schedules | `core/scheduling/*.py` | Postgres | MEDIUM |
| Monitoring | Observability | Metrics, health | `core/monitoring/*.py` | — | LOW — no external export |

---

## 3. Feature catalog (top 60 features — full 200-row inventory in `AUDIT_REPORT.md §2`)

### 3.1 API surface (~110 endpoints — see [API reference](#5-api-endpoint-reference))
### 3.2 Orchestration
### 3.3 Execution
### 3.4 Exploitation
### 3.5 Reporting
### 3.6 Persistence
(Fully enumerated in AUDIT_REPORT.md; sample details for the highest-impact features below.)

**Feature: Scan launch (`POST /api/scans/run`)**
- Purpose: create an autonomous scan job.
- Location: `ui/api/server.py:1247` `create_scan_job`.
- Signature: `async def create_scan_job(body: ScanRequest, request: Request) -> {"job_id": str, "scan_id": str}`.
- Inputs:
  - `target: str` — no validation. Should be `HttpUrl` + scope check.
  - `tier: str` — no allowlist. Should be enum `{"PASSIVE","SAFE_ACTIVE","DEEP"}`.
  - `phases: List[str]` — no allowlist. Should be enum.
  - `credentials: List[Dict]` — passwords in cleartext, flow into argv (P1-12).
- Outputs: `{job_id, scan_id}` on success. On failure: 500 with exception string leaked.
- Error handling: broad try/except; failure sets `_active_scans[job_id]["status"] = "error"`.
- Logs: `logger.info(f"Scan started: {job_id}")` — no structured field, no PII redaction.
- Performance SLA: <100 ms handler; scan itself runs 5–90 min.
- Security: **no auth by default** (P0-1); no rate limit (P0-1); no input validation (P1-14).

**Feature: Central brain phase orchestration (`central_brain.py:1460` `run_main_loop`)**
- Purpose: drive scan through phases with deterministic fallback safety net.
- Signature: `async def run_main_loop(self, phases: List[str], objective: str) -> ScanResult`.
- Inputs: phases list, objective string.
- Outputs: `ScanResult` mutated on `self.ctx`.
- Error handling: ~50 broad excepts across phases. Each phase attempt: agentic → approach A (deterministic fallback) → approach B → legacy.
- Fallback triggers: LLM empty response (`central_brain.py:3376`); `steps==0 and findings==0` (`:3148`); failure streak (`:3849`); provider fatal error (harness `:1096`).
- ⚠ `_run_phase_agentic` over-triggers fallback: "LLM found nothing exploitable" is indistinguishable from "LLM broken."

**Feature: LLM harness `generate_with_tools`**
- Location: `agents/universal_llm_harness.py:1132`.
- Providers: DeepSeek (primary), Groq (secondary — default model retired), Ollama (tertiary — local only).
- Inputs: messages, tools (JSON schemas).
- Outputs: `LLMResponse{text, tool_calls[], usage, provider, model}`.
- Timeout: httpx `self.timeout = 180 s` on DeepSeek only. **No `asyncio.wait_for` at caller.**
- Fallback: on `HTTP 5*` or `402` in message → swap provider (`:1092`). No 429 retry/backoff.
- Cost/budget: `_LLMBudget` counter capped at 30 calls/scan (`generic.py:2461`) — but not reset across scans; class-level global.

**Feature: Tool routing (`ToolRouter.route_and_execute`)**
- Location: `core/tools/tool_router.py:25-356`.
- Auto-builds shell command strings per tool from raw `target` (unescaped). Sanitizes `extra_args` only.
- Executes via `KaliTool.run(command, timeout=600)` → `KaliDockerExecutor.run(shell=True)`.
- ⚠ Bypasses `ToolInvocationValidator` (only `ToolRegistry.execute()` invokes it).
- Timeout: gateway-side `asyncio.wait_for` at 900 s default, caller-overridable up to 1800 s.

**Feature: Execution pipeline (`execution_pipeline.py:110`)**
- Purpose: run a `SecurityExperiment` through 5 stages.
- ✗ **No per-request scope check.** `_setup` only checks capability/endpoint_id are non-empty.
- ✗ **`validate_target()` dead code across ~85 executors.**
- Recovery: sets `ExecutionStatus.FAILURE` + `EXECUTION_ERROR` on exception. No retry.

**Feature: Dedup + fingerprinting (`validation/dedup.py:56`)**
- Fingerprint: `sha256(CVE|file_path|function_name|package_version|host|title.lower|vuln_type)`.
- ⚠ Collision when `file_path` empty (all web findings) and `host` unchanged → `/api/v1` and `/api/v2` collapse.
- ✗ `mark_resolved` scoped only by `scan_id`, not target — cross-target contamination.

**Feature: LLM validator (`llm_validator.py:218`)**
- Inputs: findings list. LLM assesses `is_false_positive` and severity.
- Timeout: harness default.
- ⚠ Prompt injection via `proof`/`details`/`evidence` interpolation. Tool-confirmed override at line 138 mitigates for enumerated types only.

**Feature: PDF export chain (`reporting.py:681`)**
- `weasyprint → xhtml2pdf → pdfkit → fpdf2`.
- On Windows without libgobject: silently degrades to `fpdf2` (strips HTML tags).
- Logged at INFO; MIME `application/pdf` shipped regardless.

**Feature: SARIF export (`sarif_export.py:35`)**
- Standard SARIF 2.1.0 output — GitHub Advanced Security compatible.
- ✓ Works; fingerprint truncation may cause collisions on very large scans.

**Feature: Retest engine (`retest_engine.py:360`)**
- Idempotent re-probing of findings; uses stdlib `urllib` (no session cookies, no TLS control).
- ⚠ Confidence collapses to 0.30 on any network error → transient WAF/proxy 500 demotes real findings.

**Feature: RAG (`core/rag/pipeline.py`)**
- pgvector `vector(1536)` + HNSW index (`:81`).
- Embedding: OpenAI-compatible API if `EMBEDDING_API_URL`+key set; else `_local_embed` = MD5-bag hash embedding (semantically meaningless but persisted alongside real vectors).
- ⚠ SELECT-then-INSERT race in `_store_chunk`.

**Feature: Escalation gate (`escalation_gate.py`)**
- Fail-closed on timeout; atomic file writes; webhook notification.
- ✓ One of the better-designed governance components.
- ⚠ Cross-process race on queue file (no fcntl).
- ⚠ Uses `input()` blocking call for interactive prompt — deadlocks non-TTY.

**Feature: Attack surface graph (`attack_surface_state.py`)**
- In-memory dict-based state; dedup by normalized key.
- ⚠ O(n) linear scan per endpoint add → O(n²) on large scans.

**Feature: Escalation, actuator scope check (`actuators.py:53`)**
- ✓ One of only two places per-request scope enforcement is done consistently.
- Fail-closed.

---

## 4. Integration map

| Integration | Type | Auth | File | Timeout | Retry | Rate limit | Failure mode | Critical? |
|---|---|---|---|---|---|---|---|---|
| PostgreSQL | Database | user/pass | `core/memory/database.py` | Connect 10 s | None | Pool max 20 | ✗ Pool poisoning | **YES** |
| DeepSeek Chat/Reasoner | REST | Bearer API key | `agents/universal_llm_harness.py:568` | httpx 180 s | ⚠ Only on 5xx/402 (message substring) | None (provider-side) | Provider swap to Groq (retired model) | **YES** |
| Groq | REST | Bearer | `universal_llm_harness.py:860` | 10 s | None | None | ✗ Default model `mixtral-8x7b-32768` retired → 404 | HIGH |
| Ollama | REST | none | `universal_llm_harness.py:774` | 5 s | None | — | Local only; works if configured | MEDIUM |
| Embedding API | REST | Bearer | `core/rag/embedder.py` | httpx default | None | None | Falls to MD5 hash embedding (silent semantic collapse) | MEDIUM |
| Kali Docker container | subprocess | none | `agents/kali_executor.py:83` | Per-call | None | Adaptive limiter | ✗ Container down = every tool call fails | **YES SPOF** |
| Shodan / Censys / VT / AbuseIPDB | REST | API key each | `core/intelligence/*.py` | httpx default | None | None | Censys raises `ValueError` on missing key; others silently degrade | MEDIUM |
| NVD | REST | Optional key | `core/intelligence/vuln_intel/feeds.py:20` | httpx default | None | None | Offline mode default; falls back silently | LOW |
| abuse.ch / URLhaus | HTTP | none | `threat_intel.py:293` | httpx | None | None | ✗ Global TLS verification disabled | HIGH |
| Playwright (Chromium in container) | subprocess | none | `browser_actuator.py:99`, `generic.py:5310` | 120 s / 30 s | None | None | `_browser_available()` dead → no preflight | MEDIUM |
| GitHub OSINT | REST | Optional token | `intelligence/osint_engine.py` | httpx | None | Unauth 60/h | Silent throttle | LOW |
| Webhook (escalation notify) | REST | none | `escalation_gate.py:257` | httpx 10 s | None | — | Best-effort; silent | LOW |
| MITRE ATT&CK cache | REST | none | `pg_store.py mitre_cache` | httpx | None | — | Cached; safe | LOW |
| Slack / PagerDuty | — | — | Not wired | — | — | — | Not implemented | — |
| SIEM / Prometheus / Grafana | — | — | Not wired | — | — | — | Not implemented | **Deployment gap** |

---

## 5. API endpoint reference (highlights — 108 total; full list in AUDIT_REPORT.md §2 F0)

Legend: `auth = optional*` means enforced only when `API_KEY` env is set; default deployment = no auth.

| Method | Path | Auth | Purpose | Rate | Errors |
|---|---|---|---|---|---|
| POST | `/api/scans/run` | optional* | Launch scan (spawns subprocess) | none | 500 on subprocess fail |
| POST | `/api/scans/kill-all` | optional* | Terminate all running scans | none | — |
| POST | `/api/scans/job/{id}/stop` | optional* | Signal scan to stop | none | — |
| GET | `/api/scans/job/{id}` | optional* | Job state — **leaks credentials via `command` field** | none | 404 |
| GET | `/api/scans/job/{id}/logs?tail=` | optional* | Tail log | none | — |
| WS | `/ws/scan/{id}` | **NONE** | Live stdout stream | none | ✗ bypasses middleware |
| GET | `/api/scans/{id}` | optional* | Scan detail | none | 404 |
| GET | `/api/scans/{id}/vulnerabilities` | optional* | Findings | none | — |
| GET | `/api/scans/{id}/recon` | optional* | Recon data | none | — |
| GET | `/api/scans/{id}/attack-chains` | optional* | Chains **(duplicate registration @ 813, 2188)** | none | — |
| POST | `/api/scans/{id}/chat` | optional* | Per-scan LLM chatbot | none | 500 |
| GET | `/api/scans/{id}/artifacts?kind=` | optional* | List | none | — |
| GET | `/api/scans/{id}/artifacts/{id:int}?download=` | optional* | Download bytes | none | — |
| GET | `/api/evidence/{filename}` | optional* | **✗ Path traversal via `..`** | none | — |
| POST | `/api/rag/ingest/file?file_path=` | optional* | **✗ Arbitrary file read** | none | — |
| POST | `/api/rag/ingest/uploaded` | optional* | Multipart upload — no size limit | none | 500 OOM at ~2 GB |
| POST | `/api/rag/ingest/url` | optional* | Fetch URL — **SSRF risk** | none | — |
| POST | `/api/rag/query` | optional* | RAG retrieval | none | — |
| POST | `/api/targets` | optional* | Add target — no URL validation | none | 500 |
| DELETE | `/api/targets/{id:int}` | optional* | Delete | none | — |
| GET | `/api/audit-trail` | optional* | Hash-chained JSONL tail | none | — |
| GET | `/api/canonical/*` | optional* | Various JSON summaries | none | — |
| POST | `/api/schedules` | optional* | Recurring scan — no interval bound | none | — |
| POST | `/api/campaigns/run` | optional* | Multi-target — no `max_parallel` cap | none | — |
| GET | `/api/health` | none | Health check | — | — |
| GET | `/{full_path:path}` | none | SPA fallback — **potential FS read** | — | — |

**Full endpoint list**: 108 routes (35 GET, 40+ POST, 5 DELETE, 1 WS, 5 SPA). Split into 12 domains — should be moved into `APIRouter`s.

---

## 6. Database schema summary (highlights)

Full 40+ table catalog in `AUDIT_REPORT.md §5` and `pg_store.py` `_init_schema()` (line 152 onward).

**Core scan lifecycle**
- `targets(id PK, url UNIQUE, scope, notes, added_at, last_scanned)`
- `scans(scan_id PK, target, tier, status, started_at, finished_at, duration_seconds, agents_used, pid, exit_code, command, log_file, error, report_data JSONB, metadata JSONB)` — `idx_scans_target`, `idx_scans_status`
- `vulnerabilities(id PK, scan_id FK→scans CASCADE, finding_id UNIQUE, title, type, severity, status, target, location, details, proof, remediation, tool, cwe_id, cve_id, confidence_score, extra JSONB, created_at)` — `idx_vulns_scan`, `idx_vulns_severity`

**Findings v2**
- `findings_v2(finding_id PK, title, description, severity, affected_endpoint, state, evidence_ids TEXT[], extra JSONB)` — `idx_findings_v2_state`
- `findings_dedup(signature PK, tool, finding_type, data_repr, first_seen, last_seen, count, task_id)` — **missing idx on `last_seen`**

**Data protection issues**
- `auth_bypasses(id PK, scan_id FK CASCADE, host, method, login_url, technique, username, password TEXT, payload, token TEXT, response_status, response_snippet, role, severity, dedup_key)` — **passwords/tokens plaintext (P0-6)**
- `scan_llm_memory(id PK, scan_id FK CASCADE, phase, kind, content, tool, target, created_at)` — content may contain quoted secrets

**Live progress (singleton row bug)**
- `live_progress(id PK DEFAULT 1, scan_id, phase, progress, status, data JSONB, updated_at)` — **always upserts id=1 → concurrent scans stomp**
- `live_results` — same pattern

**RAG**
- `rag_documents(doc_id PK, content, metadata JSONB, source_type, source_ref, content_hash, embedding vector(1536), created_at)` — HNSW index, non-unique source/hash idx

**Legacy shadow schema**
- `kb_*` tables in `core/knowledge/persistent_store.py:19` — SQLite-flavored TIMESTAMP TEXT, no indexes. Drift risk.

**FK graph**
- 6 tables cascade from `scans`. 20+ tables lack FK → orphan risk on scan delete.

**Missing indexes**
- `audit_log.timestamp`, `execution_audit.timestamp`, `findings_dedup.last_seen`, `scans.started_at`, `experiences.test_type`, `experiences.created_at`, `llm_failures.created_at`, all `kb_*` FKs.

**No migration framework** — `CREATE TABLE IF NOT EXISTS` only. New columns never applied to existing tables. Manual dedup DELETE migration runs on every boot (`pg_store.py:711-793`).

**Backup**: none scripted. `data/db/` empty. Single-volume loss = total data loss.

---

## 7. Authentication & authorization

### 7.1 Model
- **Platform auth**: single-secret `X-API-Key` header check (`server.py:37-52`). No JWT, no session, no user table, no roles, no RBAC.
- **Default**: `API_KEY=` blank → middleware short-circuits. Zero auth.
- **Query-string acceptance** (`server.py:49`): `?api_key=…` leaks into web-server access logs and browser Referer headers.
- **WebSocket**: bypasses HTTP middleware entirely.
- **Target authorization** (may-I-scan-this): three overlapping systems:
  - `ScopeManager` (`core/scope/manager.py:10`)
  - `TargetScopeValidator` singleton (`core/security/authorization.py:27`)
  - `LegalValidator` (`core/security/legal_validator.py`)
  - Also present: `authorization_service.py`, `policy_validator.py`, `compliance_gate.py`, `consent.py`, `capability_registry.py`, `security_context.py`.

### 7.2 Enforcement matrix

| Point | Enforces? | File |
|---|---|---|
| API middleware | ✗ (bypassed if `API_KEY` unset) | `server.py:37` |
| WebSocket handshake | ✗ (bypasses middleware) | `server.py:1613` |
| Scan launch | Coarse — `auth_context.can_scan_target` (upstream) | `server.py:1247` |
| Executor pipeline | ✗ `validate_target()` dead code | `execution_pipeline.py:110` |
| Generic executors (85) | ✗ Inherit no-op `validate_target` from base | `generic.py:65` |
| SQLi / XSS executor | ✗ | `sql_injection.py`, `xss.py` |
| Actuator HTTP | ✓ `_in_scope` | `actuators.py:53` |
| Actuator browser | ✓ (navigate only) | `browser_actuator.py:86` |
| Tool registry path | ✓ via `ToolInvocationValidator` | `tool_validation.py:49` |
| Tool gateway path | ✗ Only coarse `can_scan_target` | `tool_gateway.py:145` |
| Discovery (curl subprocess) | ✗ Direct string interpolation | `api_schema_importer.py:50` |
| Escalation gate | ✓ Fail-closed on timeout | `escalation_gate.py` |
| Consent | Optional (env `AUTO_APPROVE_EXPLOITS`) | `consent.py:31` |

### 7.3 Consolidation plan
Move to a single **AuthorizationRepository** with pluggable **scope providers** (in-scope hosts, denylist, tier gate, legal-validator gate, capability gate). Every executor calls `AuthorizationRepository.check(action, target, context)` before firing. `validate_target()` becomes the enforced interface.

---

## 8. Configuration & environment

Full inventory in `AUDIT_REPORT.md §8` (from intel/auth agent). Highlights:

| Var | Required | Sensitive | Default | Purpose | Risk |
|---|---|---|---|---|---|
| `API_KEY` | ⚠ Should be | Yes | empty | HTTP auth | ✗ Off by default |
| `ENCRYPTION_KEY` | ⚠ Should be | Yes | empty → hardcoded fallback | Fernet-like secret store | ✗ Hardcoded fallback |
| `TREND_STORE_KEY` | No | Yes | `"AntiGravityTrendSecretKey2026"` | XOR "encryption" | ✗ Trivially broken |
| `DEEPSEEK_API_KEY` | Yes | Yes | empty | Primary LLM | HIGH |
| `GROQ_API_KEY` | No | Yes | empty | Fallback LLM (broken default model) | HIGH |
| `EMBEDDING_API_URL/KEY` | No | Yes | empty | RAG embeddings | Falls to hash MD5 |
| `SHODAN_API_KEY`, `CENSYS_PAT`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `NVD_API_KEY`, `GITHUB_TOKEN` | No | Yes | empty | OSINT | Censys raises on missing |
| `POSTGRES_HOST/PORT/DB/USER/PASSWORD`, `DATABASE_URL` | Yes | Yes | pentesting_user/pentesting_password | DB | ⚠ default creds |
| `CORS_ORIGINS` | No | No | `*` | CORS | ✗ Wide-open default |
| `API_HOST` | No | No | `0.0.0.0` | Bind | ⚠ Public bind |
| `API_PORT` | No | No | 8903 | Port | — |
| `AUTO_APPROVE_EXPLOITS` | No | No | off | Bypass consent | Risky if env leaked |
| `AUDIT_LOG_PATH` | No | No | `.audit_logs/audit.jsonl` | Audit sink | No rotation |
| `EXECUTION_MODE` | No | No | `agentic` | Brain mode | — |
| `REPORTS_ENABLED` | No | No | 0 | Write reports | Off in default |
| `SCAN_CLEANUP_ENABLED` | No | No | 1 | Delete scratch | — |
| `DOCKER_CONTAINER` | No | No | `kali-pentesting` | Kali container name | SPOF |
| `DOCKER_TIMEOUT` | No | No | 1200 | Timeout | Long |

**Config loader**: `core/common/config.py` — naive KEY=VALUE parser; no `dotenv`, no quote/interpolation handling.

---

## 9. State management

| State | Location | Init order | Persistence | Consistency | Cleanup |
|---|---|---|---|---|---|
| `CentralBrain.ctx` (`SharedContext`) | In-memory | Per-scan process | ⚠ Only findings via broken persistence mixin | ⚠ Mutated concurrently in `asyncio.gather` | Process exit |
| `_active_scans` dict | `server.py:164` | API boot | ⚠ Manual `_persist_scan_state` | ⚠ Iterated while mutated | Process exit |
| `_ws_push_tasks` | `server.py:1561` | On WS connect | — | — | ⚠ Not on shutdown |
| `ConnectionManager` subscribers | `server.py:1520` | On WS connect | — | ⚠ No lock | Manual disconnect |
| `_ACTIVE` auth (`auth_registry.py:14`) | Module global | On scan set | — | ✗ No lock; scans stomp | `clear_active_auth` |
| `_LLMBudget._calls` (`generic.py:2465`) | Class global | Import | — | ✗ Not reset across scans | — |
| `TargetScopeValidator._instance` | Class global | First access | — | ✗ First writer wins | — |
| `ScopeManager` policy | Instance | Per scan | — | Independent from `TargetScopeValidator` | — |
| Postgres pool | Class global | First use | — | ✗ Poisoning bug | Process exit |
| `RAGPipeline._pipeline` | Module global | First `_get_rag()` | — | ⚠ Race on init | — |
| React page state | `useState` | On mount | localStorage only for `ag_defaults` | ⚠ WS+poll race | Unmount |

**Persistence strategy**: Postgres for durable; in-memory for scan lifecycle. **No checkpointing of `ctx` mid-scan** → crash mid-scan = lost recon/findings even without persistence mixin bug.

---

## 10. Error handling matrix

| Layer | Error class | Catch site | Handling | User visible? | Logging |
|---|---|---|---|---|---|
| API middleware | Any 5xx | FastAPI default | Returns 500 with body | Yes | uvicorn access log |
| API handler | `ValueError`/`RuntimeError` | Broad try/except | 500 with exc str | Yes | logger.exception |
| Central brain phase | Any | ~50 broad excepts | Fall to fallback / continue | No | logger.exception |
| Agentic tool round | Any | `except Exception as e` | Return error observation | No | logger.debug |
| LLM harness | HTTP 5*/402 | Message substring | Provider swap | No | logger.warn |
| LLM harness | 429 | ✗ Not handled | Bubbles as generic exception | No | none |
| DB repo | `psycopg2.OperationalError` | Broad except | ✗ **connection returned unrolled back** | No | logger.error |
| Executor | Any | Broad except | Returns FAILURE status | No | logger.exception |
| Frontend fetch | Any | `.catch(()=>{})` | Silent | No | none |
| Kali executor | `TimeoutExpired` | Explicit catch | Returns timeout marker | No | logger.warn |
| Kali executor | `FileNotFoundError` | Generic except | Same as tool failure | No | logger.exception |
| Report render | PDF chain step fail | Explicit catches | Fall to next fallback | No | logger.info |
| Escalation timeout | asyncio.TimeoutError | Explicit | Fail-closed deny | Via UI | logger.warn |
| RAG store | Any | Broad except | Silent skip | No | logger.warn |

**Systemic pattern**: 80+ `except Exception: pass` sites across codebase. This is the primary reason silent failures (broken persistence mixin, broken memory stores, missing datetime import) go undetected.

---

## 11. Security checklist (current state)

| Control | Status | Location | Gap |
|---|---|---|---|
| API authentication | ✗ Off by default | `server.py:37` | Require `API_KEY` at boot |
| WS authentication | ✗ Bypassed | `server.py:1613` | Enforce via subprotocol |
| Authorization (per-request) | ✗ Missing across executors | `executors/base.py:44` | Wire `validate_target()` |
| Input validation | ✗ Bare `str` inputs | `server.py:146` | Pydantic `HttpUrl`, enums |
| CORS policy | ✗ `*` default | `server.py:25` | Explicit allowlist |
| CSRF | ✗ None | — | Token or SameSite cookies |
| Rate limiting | ✗ None | — | `slowapi` |
| Secrets management | ⚠ Fallback hardcoded | `encryption.py:19` | Hard-fail |
| Secret rotation | ✗ In-place; no versioning | `secret_manager.py:44` | Add version marker |
| Sensitive data in DB | ✗ Plaintext passwords | `pg_store.py:594` | Fernet at column level |
| TLS verification (LLM, targets) | ⚠ `verify=False` for actuators | `actuators.py:75` | Env toggle w/ warning |
| TLS verification (OSINT) | ✗ Globally disabled | `threat_intel.py:24` | Restore |
| SQL injection prevention | ✓ Parameterized `%s` | `pg_store.py:*` | — |
| Path traversal | ✗ `/api/evidence`, `/api/rag/ingest/file`, `scan_id` in reports | multiple | `Path.resolve()` boundary |
| Command injection | ⚠ Shell strings in discovery + tool_router + browser tool | multiple | shlex quote + allowlist regex |
| SSRF | ⚠ `POST /api/rag/ingest/url` no scheme allowlist | `server.py` | Scheme + private-IP block |
| Prompt injection | ✗ Raw evidence into LLM prompts | `llm_validator.py:48`, `chain_intelligence.py:105` | Escape / structured schema |
| XSS in report | ⚠ `report.replace('</main>', ...)` | `reporting.py:845` | Template placeholder |
| Jinja2 sandbox | ✗ `Template(...)` unsandboxed | `reporting.py:335` | `SandboxedEnvironment` |
| Dependency vulnerabilities | ✗ No SBOM, no scan | Dockerfile | Grype + SBOM |
| Container hardening | ✗ Root, no capdrop | Dockerfile | `USER app`, drop caps |
| Supply chain | ✗ Rolling base, unpinned `go install @latest` | Dockerfile:19-29 | Pin digest + versions |
| Docker socket exposure | ⚠ web container adds Docker CLI + apt repo | Dockerfile.web:28 | Rootless / podman-remote |
| Audit log integrity | ✓ SHA-256 hash chain | `audit_logger.py` | ⚠ `AUDIT_SALT` hardcoded; no rotation |
| PII redaction | ⚠ Manual `mask_sensitive_pii` — not wrapped around loggers | `audit_logger.py` | Logging filter |

---

## 12. Deployment checklist (gate before production)

Full sequenced week plan in `AUDIT_REPORT.md §10`. Minimum gates:

**Pre-flight**
- [ ] `API_KEY` set, non-default; startup refuses if empty
- [ ] `ENCRYPTION_KEY` set, non-default; hardcoded fallback removed
- [ ] `TREND_STORE_KEY` replaced with Fernet
- [ ] `CORS_ORIGINS` explicit allowlist
- [ ] Postgres credentials rotated; not `.env.example` defaults
- [ ] `DEEPSEEK_LARGE_MODEL=deepseek-reasoner` and `GROQ_MODEL` set to a live model
- [ ] Docker base image digest pinned; Go tools pinned to versions
- [ ] Containers run as `USER app`, capabilities dropped, no docker.sock mount
- [ ] `nuclei -update-templates` verified in build; templates cached signed
- [ ] SBOM generated (Grype/Syft); no known critical CVEs
- [ ] Frontend `api.js` sends `X-API-Key` header

**Runtime**
- [ ] `slowapi` rate limits on `/api/scans/run`, `/api/scans/kill-all`, `/api/rag/ingest/*`
- [ ] WebSocket handshake enforces API key
- [ ] `validate_target()` wired into `execution_pipeline._execute`
- [ ] `mark_resolved` scoped by target
- [ ] Path validators on `/api/evidence`, RAG ingest-file
- [ ] Connection pool `rollback` in `finally`
- [ ] Bootstrap sweeper marks orphaned "running" scans failed on startup
- [ ] Per-`scan_id` `live_progress`/`live_results` rows
- [ ] `bulk_insert` uses `execute_values`
- [ ] Broken memory stores fixed (`experience_store`, `failure_store`, `strategy_store`)
- [ ] `KnowledgeStore` / `MemoryDatabase` as real singletons
- [ ] Fixed broken `persistence.py` (`datetime` import)
- [ ] Fixed broken `osint_bridge.py` (`re` import, `self`)

**Migrations**
- [ ] Alembic (or equivalent) versioned migrations
- [ ] `_init_schema` on-boot removed for existing DBs
- [ ] Dedupe migration idempotent + explicit trigger

**Data protection**
- [ ] `auth_bypasses.password/token` encrypted via Fernet at column level
- [ ] `.audit_logs/audit.jsonl` rotated + shipped to WORM sink
- [ ] Structured logger with PII-redaction filter wrapped globally

**Observability**
- [ ] `/metrics` Prometheus endpoint (pool utilization, LLM error rate, per-phase latency, scan counters)
- [ ] Dashboards (Grafana) for above
- [ ] Structured JSON logs shipped to central sink (ELK / Loki)
- [ ] Alerts on: pool exhaustion, LLM 5xx > 1%, scan failures > 10%, container restart
- [ ] Distributed tracing across API → scan process → executors

**Resilience**
- [ ] Postgres HA (streaming replication + failover) or managed RDS
- [ ] Automated `pg_dump` + off-host retention + restore drill (quarterly)
- [ ] Container healthcheck + restart policy; pool of Kali containers
- [ ] Circuit breaker on LLM providers with exponential backoff on 429/5xx
- [ ] Idempotent scan resume from checkpoint after crash

**Governance**
- [ ] Threat model reviewed and approved
- [ ] External platform pen-test complete
- [ ] SOC 2 / ISO 27001 controls mapping (if regulated customers)
- [ ] Data retention policy documented
- [ ] Incident response runbook (§14) reviewed
- [ ] Change management for scope updates → single source of truth

---

## 13. Known issues & limitations

Priority-ordered inventory in `RISK_MATRIX.md`. Summary:

- 10 P0 production blockers (auth, authz, persistence, encryption, data contamination).
- 15 P1 high-severity issues (WS auth, credential leaks, prompt injection, retest downgrade, FP filter synthetic training, supply chain, root containers, N+1, races, shell injection).
- 12 P2 medium.
- 10 P3 low/hygiene.

**Incomplete features**:
- Multi-tenant / multi-scan concurrency (`live_progress` singleton row, `_ACTIVE` auth global, `_LLMBudget` global, `ScopeManager` per-scan).
- Broken persistence mixin: recon and vuln findings likely not persisted via this path (NameError).
- Broken memory stores: adaptive learning silently disabled.
- Broken Groq fallback: retired default model.
- Dead code: `validate_target()`, `_browser_available()`, `_tool_exists()`.
- Duplicate route registrations and duplicate JS object keys.
- Legacy `kb_*` shadow schema — data drift between it and `findings_v2`.

**Performance bottlenecks**:
- O(n²) endpoint dedupe in `attack_surface_state.py:124` on large scans.
- N+1 bulk writes across 6 sites.
- 40+ unbounded `SELECT * ... ORDER BY ...` list queries.
- Missing indexes on 7+ hot ORDER BY / filter columns.
- Every `KnowledgeStore()` construction re-runs `_init_schema` + dedupe DELETE migration.

**Tech debt (prioritized)**:
1. Split `ui/api/server.py` (93 KB) into `APIRouter`s per domain.
2. Split `core/execution/executors/generic.py` (5,551 LOC) into per-vuln-class modules.
3. Split `core/orchestration/central_brain.py` (6,707 LOC) — extract fallback catalog into config.
4. Remove `core/knowledge/persistent_store.py` legacy shadow schema.
5. Consolidate 8 auth/scope/consent modules into one repository-of-record.

---

## 14. Incident response guide

### If the API returns 500 across the board
1. Check Postgres reachability: `psql $DATABASE_URL -c 'select 1'`.
2. Check connection pool state: `psql -c "select state, count(*) from pg_stat_activity where datname='$POSTGRES_DB' group by 1"`. Look for `idle in transaction (aborted)`.
3. **Likely cause**: pool poisoning bug (`core/memory/database.py:71-75`). Restart the API process to reset the pool. **Long-term fix**: add `conn.rollback()` in `finally` before `putconn`.
4. Grep logs for `InFailedSqlTransaction`.

### If scans stall in "running" forever
1. Check subprocess: `ps aux | grep scan_ | head`.
2. Check log file: `tail -f logs/scans/<scan_id>.txt`.
3. If dead process: manually `UPDATE scans SET status='error', error='orphaned' WHERE scan_id=... AND status='running'`.
4. **Long-term fix**: bootstrap sweeper on API start.

### If the WebSocket floods reconnect
1. Check `_ws_push_tasks` count via a debug endpoint (add if missing).
2. Likely: broken subscriber cleanup (`server.py:1520`). Restart API.

### If LLM planning always empty / uses deterministic fallback
1. Check DeepSeek API health (`curl -H 'Authorization: Bearer $KEY' https://api.deepseek.com/v1/models`).
2. Check `DEEPSEEK_LARGE_MODEL` — should be `deepseek-reasoner` not `deepseek-chat`.
3. Check `LLM_PROVIDER` fallback: Groq model probably retired; verify.
4. Check budget: `_LLMBudget._calls` may have exceeded 30 (not reset across scans in long-running process).

### If Kali container down mid-scan
1. `docker ps | grep kali-pentesting`.
2. Restart: `docker start kali-pentesting`.
3. All in-flight scans continue but every tool call fails until restart. Consider adding container healthcheck + restart policy.

### If reports come out as plain text (Windows PDF)
1. Check native libs: `python -c "import weasyprint; print(weasyprint.__version__)"`.
2. Install libgobject-2.0-0, cairo, pango, harfbuzz.
3. Or fall through to `xhtml2pdf` — accept degraded output.

### If findings from prior scans keep marking as "RESOLVED"
1. **Cause**: `mark_resolved` cross-target contamination (`dedup.py:160`).
2. Immediate: manually reset: `UPDATE findings_history SET status='OPEN' WHERE status='RESOLVED' AND last_scan_id='<current>'`.
3. Long-term fix: scope `mark_resolved` by target.

### If secrets store fails to decrypt
1. Check `ENCRYPTION_KEY` set and matches key used at encrypt time.
2. If lost, the `.antigravity/secrets.enc` may still decrypt with hardcoded `DEFAULT_FALLBACK_KEY_RAW` if it was encrypted while `ENCRYPTION_KEY` was unset — indicates the P0 hardcoded-fallback bug.
3. Rotate all provider API keys upstream once decryption succeeds.

### If suspected prompt injection via findings
1. Grep `agent_reasoning` and `scan_llm_memory` for phrases like `"ignore prior"`, `"false_positive": true`.
2. Investigate the `proof` field of any finding whose LLM verdict flipped.
3. Long-term fix: `SandboxedEnvironment` for Jinja2; structured tool-use schema for validator.

### If cross-scan progress bar wrong
1. **Cause**: `live_progress` id=1 singleton row (`pg_store.py:1015`).
2. Immediate: end one of the scans.
3. Long-term fix: per-`scan_id` row.

### Contact tree
- API/DB failures → platform on-call
- Scope violation / out-of-scope scan → security + legal within 24 h
- Data breach (secrets leaked, findings exfiltrated) → CISO + DPO within regulatory window (72 h GDPR)
- Vulnerability in the platform itself → security triage; consider platform quarantine

---

## 15. Change log

- 2026-09-06 — audit complete on branch `autonous-agent`. 4 deliverables + risk matrix produced.
- Prior work (memory): recon pipeline hardening, dedup fingerprint fix (title+type added), retest confirmation for tool-based findings, Groq/DeepSeek harness switching, RAG bootstrap.

---

## Cross-references
- `AUDIT_REPORT.md` — feature inventory, dependency graph, ranked findings.
- `SIMULATION_TRANSCRIPT.md` — end-to-end execution trace with 22 failure scenarios.
- `RISK_MATRIX.md` — issue table with severity, impact, reproduction, effort.
