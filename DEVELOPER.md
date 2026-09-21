# Developer Guide

Engineering reference for contributors to the Autonomous Pentesting Agent (codename **Neo** / "AntiGravity v2.0"). Read this before changing orchestration, the LLM harness, probes, or the UI.

> **Scope law (non-negotiable):** authorized targets / labs / CTFs only. Never remove authorization checks, never weaken security controls, and never log passwords, API keys, tokens, or secrets. Every network request passes `TargetScopeValidator` before it leaves the process. See [Security invariants](#security-invariants).

---

## 1. What this is

An AI-driven multi-agent pentest engine. A **CentralBrain** drives a 4-phase pipeline; an LLM plans each phase, deterministic specialist agents execute in parallel, findings are verified, chained, scored, and persisted. A FastAPI server launches scans as isolated subprocesses and a React/Vite dashboard streams progress.

```
┌─────────────┐   POST /api/scans    ┌──────────────┐   Popen        ┌──────────────────┐
│ React UI    │ ───────────────────▶ │ FastAPI API  │ ─────────────▶ │ main.py (scan)   │
│ (Vite:5173) │ ◀─── poll/stream ─── │ (uvicorn)    │ ◀── DB rows ── │ CentralBrain     │
└─────────────┘                      └──────┬───────┘                └────────┬─────────┘
                                            │  reads                          │ writes
                                            ▼                                 ▼
                                     ┌───────────────────────────────────────────┐
                                     │ PostgreSQL (pg_store)  — degrades if absent │
                                     └───────────────────────────────────────────┘
```

**Critical mental model:** a scan is a **separate OS process**, not an in-process task of the API. `ui/api/server.py::_run_scan_process` spawns `python main.py --target … --tier … --scan-id <job_id>`. The UI and the scan communicate **only through the database**.

Consequence:
- **Backend changes** (anything in `core/`, `agents/`, `main.py`) apply on the **next scan** — no server restart needed for scan logic, but a running scan won't pick them up.
- **API changes** (`ui/api/server.py`) require restarting the API process.
- **Frontend changes** (`ui/web/src`) apply immediately via Vite HMR.

---

## 2. Repo layout

```
outputs/
├── main.py                     # scan entrypoint (CLI). Spawned per-scan by the API.
├── agents/                     # LLM harness + providers + exploit/kali executors
│   ├── universal_llm_harness.py    # ProviderType enum, factory, pricing
│   ├── llm_harness_adapter.py      # get_llm()/get_provider(); provider selection
│   └── providers/                  # bedrock / claude_cli / deepseek + routing
├── core/
│   ├── orchestration/          # CentralBrain, MetaBrain, planner, schedulers
│   │   ├── central_brain.py        # phase loop, planner, coverage gate, chaining
│   │   ├── family_scheduler.py     # parallel specialist teams (recon/probe/authed)
│   │   ├── phase_dag.py            # RECON→ACTIVE_SCANNING→EXPLOITATION/REPORTING
│   │   └── central_brain_mixins/   # recon_context, etc.
│   ├── common/normalizer.py    # PlannerResponseNormalizer (LLM output → tasks)
│   ├── exploitation/           # probes (ssti, xxe, deserial, mass_assign, …)
│   │   └── payload_synth.py         # LLM context-aware payload generation
│   ├── oob/collaborator.py     # out-of-band interaction server (blind verify)
│   ├── intelligence/           # OSINT, app understanding, hypotheses, identity
│   ├── reporting/              # report builders, chatbot, scoring, fix-gen
│   ├── database/pg_store.py    # ALL SQL. Postgres schema + read/write API.
│   ├── security/               # authorization, egress firewall, consent, audit
│   └── tools/                  # tool gateway, registries, nuclei/nmap runners
├── ui/
│   ├── api/server.py           # FastAPI: scans CRUD, live data, downloads, chat
│   └── web/                    # React 19 + Vite 7 + react-router 7
│       └── src/{pages,components,api.js,index.css,utils.js}
├── requirements.txt            # Python deps (core)
├── ui/api/requirements.txt     # fastapi, uvicorn
├── .env.example                # every env var, documented
└── docker-compose*.yml         # Postgres, web, benchmark stacks
```

---

## 3. Scan lifecycle (end to end)

1. **UI** `POST /api/scans` with `{target, tier, credentials?, phases?}`.
2. **API** creates a `scans` row (status `running`), builds an argv list, and `subprocess.Popen`s `main.py` with `--scan-id <job_id>` (`_run_scan_process`, server.py ~L735). Credentials are written to a temp JSON file passed via `--credentials-file`; `main.py` reads then unlinks it (never argv — that leaks via `/proc`).
3. **main.py** `main()`:
   - `anon_gate.enforce_or_die()` — anonymity/egress gate.
   - eager `get_collaborator()` — binds the OOB listener for the whole scan.
   - parses args, loads `.env` (`load_config()`), sets tier/frameworks, runs optional standalone mobile/SAST steps.
   - `run_single()` → builds `CentralBrain(target, scope, scan_id)` → `brain.run_main_loop()`.
4. **CentralBrain.run_main_loop** walks the phase DAG. For each phase → `_run_phase`:
   - If the active provider `supports_native_tools()` → agentic loop.
   - Else (e.g. `claude_cli`) → **JSON planner** path `_run_phase_approach_a` (see §5).
   - Deterministic parallel specialist teams run via `family_scheduler` (see §6).
   - A **coverage gate** (`_assert_phase_coverage`) forces required lanes to run.
5. **Post-scan** (`main.py`): chain synthesis + rescoring (`_post_scan_chain_analysis`), PoC bundles, attack-surface baseline + regression, SAST↔DAST correlation, final `_persist_vulnerabilities()`.
6. **UI** polls `/api/scans/<id>/…` endpoints and renders live.

Phases: `RECON → ACTIVE_SCANNING → EXPLOITATION`, with `REPORTING` depending on `ACTIVE_SCANNING`. Tiers: `POC` (default, non-destructive) → `SHALLOW` → `DEEP`.

---

## 4. LLM harness & providers

All model calls go through `agents/llm_harness_adapter.py::get_llm()` / `get_provider()`. Never call a provider SDK directly from feature code.

**Providers** (`ProviderType` in `universal_llm_harness.py`, valid set in adapter `_VALID_PROVIDERS`):

| provider | native tools | notes |
|---|---|---|
| `claude_cli` | ❌ no | shells out to the `claude` CLI. **Default.** Large system prompts must go via stdin, not `--append-system-prompt` (Windows argv overflow → empty `{}`). |
| `bedrock` | ✅ yes | AWS Bedrock (boto3). `AWS_REGION`, `AWS_BEDROCK_{SMALL,LARGE}_MODEL`. |
| `deepseek` | ❌ no | OpenAI-compatible. `DEEPSEEK_API_KEY`, `DEEPSEEK_BASE_URL`. |

**Selection order** (adapter): `LLM_PROVIDER` env → `.antigravity/llm_provider` file (written by UI Settings) → `.env` → default `claude_cli`. The UI Settings page writes the file, so changing provider in the UI takes effect on the next scan.

**`supports_native_tools()` is the fork that matters.** Native-tool providers get the agentic loop; everyone else gets the deterministic JSON-planner path. Any new provider must implement this capability honestly.

**Adding a provider:**
1. `agents/providers/<name>_provider.py` implementing the provider interface (`complete`/`chat`, `supports_native_tools`, model config).
2. Add to `ProviderType` enum + pricing table + factory branch in `universal_llm_harness.py`.
3. Add to `_VALID_PROVIDERS` + an init branch in `llm_harness_adapter.py`.
4. Add the option to the Settings list in `ui/api/server.py`.
5. Add env vars to `.env.example`.

---

## 5. Planner & normalizer (non-native path)

For non-native providers, the LLM returns JSON describing what to do; `core/common/normalizer.py::PlannerResponseNormalizer.normalize` turns arbitrary-but-plausible LLM output into a canonical task list. This is the highest-churn correctness surface — LLMs emit many shapes.

It handles:
- **action aliases** → `SPAWN_AGENTS`: `execute_capability`, `execute_tool`, `run_capability`, `run_tool`, `tool_call`, `call_tool`, `use_tool`.
- **single tool-call shape**: a top-level `{tool|capability, parameters|params, objective|reason, target}` with no `tasks`/`agent_spec` is synthesized into one task.
- **capability inference** (`_infer_capability`) reads **both** plural `tools` and singular `tool` (missing the singular caused an all-collapse-to-`technology_fingerprinting` repeating loop).
- **task spec normalization** (`_normalize_task_spec`): `objective` falls back to `reason`; accepts `params` and `parameters`.

When you touch the planner: add a unit test with the exact offending JSON shape (see `tests/`). Do **not** special-case a single provider — normalize the *shape*, which is provider-agnostic.

Planner-completion guard (`central_brain.py::_run_phase_approach_a`): on iteration 0 with zero agents and no history, force `_deterministic_fallback(phase, set())` so a phase never silently does 0 steps.

---

## 6. Parallel specialist agents

`core/orchestration/family_scheduler.py` runs deterministic specialist teams concurrently, independent of the LLM. Entry points called from `CentralBrain`:

- `run_recon_teams(brain)` — OSINT ∥ Web ∥ Infra lanes, then a dependent API-classification lane. Each lane body (`_web`/`_infra`/`_osint`/`_api`) takes an `aid` (agent id) and writes reasoning via `_reason()` (→ `agent_reasoning` table, surfaced as "thoughts" in the UI).
- `run_specialist_probes(brain)` — spawns probe families by `TestFamily` / `AgentTier`.
- `run_authenticated_battery(brain)` — multi-identity authz testing (`_AUTHED_FAMILIES`, `_identity_headers`).

Live state is tracked through `AgentTracker` / `LiveAgentRepo` (→ `live_agents` table). A **coverage ledger** (`brain._coverage_ran: set`) records which lanes ran; `_assert_phase_coverage(phase)` is the gate that enforces required coverage at the end of recon, after specialist probes, and after expert probes.

---

## 7. Probes & dynamic payload synthesis

Probes live in `core/exploitation/*_probe.py`. Each is a self-contained detector for one vuln class. When a defense inspects the *shape* of the payload (WAF, template engine, parser), the probe asks the LLM for context-aware payloads instead of using static lists.

`core/exploitation/payload_synth.py` — `synthesize()` / `synth_payloads()`:
- Flow: **PROPOSE → verify**. The LLM proposes candidates; the probe verifies each against the live oracle before claiming a finding.
- `_KIND_SPEC` covers: `polyglot`, `ssti`, `deserialize`, `mass_assign`, `graphql_query`, `waf_bypass`, `business_logic`, `xxe`.
- OOB kinds (`xxe`, `deserialize`) embed `OOB_PLACEHOLDER`, replaced with a live collaborator token at send time.
- Feedback-aware: prior failed attempts are fed back so round 2 adapts (e.g. `param_fuzzer` 2-round WAF bypass).

Wired probes: `file_upload_probe`, `ssti_probe`, `xxe_probe` (OOB), `deserial_probe` (OOB batch token), `mass_assign_probe`, `graphql_dos_probe`, `param_fuzzer` (2-round), `business_logic_probe` (hypothesis seeding).

**Probes without synthesis are correct as-is** — a class whose detection doesn't depend on payload shape (e.g. missing header, CORS reflection, cookie flags) uses deterministic checks.

**Adding a probe:**
1. `core/exploitation/<name>_probe.py`; reuse the existing probe base/patterns.
2. If detection depends on payload shape, call `payload_synth.synthesize(kind=…)` and verify each candidate.
3. Register it with the family scheduler / probe family it belongs to.
4. Findings persist via the live pipeline only (see §8) — return finding dicts, don't write files-then-parse.

---

## 8. Persistence rules (read this before touching the DB)

- **All SQL is in `core/database/pg_store.py`.** ~45 tables (`scans`, `vulnerabilities`, `exploit_results`, `findings_v2`, `live_progress`, `live_results`, `live_agents`, `agent_reasoning`, `attack_chains`, `tool_outputs`, `agent_activity`, `captured_requests`, `kg_nodes/edges/hypotheses`, `audit_log`, `execution_audit`, …). Timestamps are `TIMESTAMPTZ DEFAULT NOW()`.
- Postgres is **optional at runtime** — the platform degrades gracefully (writes skipped / SQLite fallback) if it's unreachable. Don't assume a connection.
- **Never parse `.log`/`.json` artifact files to insert vuln data into the DB.** Only the live pipeline writes findings. (Hard project rule.)
- `custom_probe` confirmations persist via an **oracle + LLM sweep** so exploit confirmations always land.

---

## 9. Out-of-band (OOB) verification

`core/oob/collaborator.py` gives blind vulns (XXE/SSRF/deserialization) a callback channel at zero cost.

- `LocalHTTPCollaborator` — binds a local listener (default `:8899`), path-token based, exposed publicly via a **cloudflared** tunnel. This is the default free path.
- `InteractshCollaborator` — real interactsh protocol (RSA register + AES-CFB decrypt) if you have a server.
- `NullCollaborator` — no-op when OOB is disabled.

Helpers: `prepare_oob()`, `confirm_oob()`, `token_marker()`, `OOB_PLACEHOLDER`. `get_collaborator()` is initialized eagerly in `main.py` so the listener is up for the whole scan and the tunnel has a live origin.

Setup: set `OOB_DOMAIN` in `.env`, run the cloudflared tunnel to `localhost:8899`. A 502 on the tunnel means nothing is bound (scan not running / lazy init) — the eager init in `main.py` fixes that.

---

## 10. API server

`ui/api/server.py` — FastAPI + uvicorn (`uvicorn.run(app, host=API_HOST, port=API_PORT)`, default port from `.env`).

- **Auth**: `X-API-Key` header required (middleware `_require_api_key`). Downloads accept `?api_key=` on a narrow GET allowlist (browser navigation can't set headers). Dev key auto-written to `.antigravity/dev_api_key`.
- **Scan launch**: `_run_scan_process` (argv list, no shell → no injection). Credentials via unlinked temp file.
- CORS: `CORS_ORIGINS`. Rate limiting via `slowapi` (falls back to built-in limiter if absent).
- Routers dir exists (`ui/api/routers/`) but endpoints currently live in `server.py`.

Restart the API after editing `server.py`.

---

## 11. Frontend

`ui/web` — React 19, Vite 7, react-router 7. No component library; styling via CSS tokens in `index.css`.

- **API client**: `src/api.js` — injects `X-API-Key`; key resolved from `ag_api_key` localStorage, `?api_key=` bootstrap.
- **Theme**: light theme via CSS custom properties — `--bg-card`, `--bg-surface`, `--border`, `--accent`, `--text`, `--text-h`, `--text-dim`, `--accent-dim`, `--accent-on`, plus aliases `--surface-1`→`--bg-card`, `--surface-2`→`--bg-surface` (undefined aliases previously fell back to dark hex → unreadable). Use tokens, never hardcoded colors.
- **Key pages** (`src/pages`): `LiveScan.jsx` (streaming), `ScanDetail.jsx` (tabs: Logs/Exploits/Coverage/Tool Outputs/…), `Scans.jsx`, `Dashboard.jsx`, `Settings.jsx`, `Analyze.jsx`, `Targets.jsx`, `KnowledgeBase.jsx`.
- **Key components** (`src/components`): `LiveAgentsPanel.jsx` (per-second agent timers, status colors), `ScanChatPanel.jsx` (per-scan "Ask LLM" chat, persisted to `ag_scanchat_<scanId>`), `CoveragePanel.jsx`, `AttackChainsPanel.jsx`, `ReconPanel.jsx`.
- **Timestamps**: backend emits naive-UTC ISO (no tz suffix). Always parse with `utils.js::parseTs` (marks bare timestamps as UTC) — using raw `new Date()` reintroduces the `+5:30` elapsed-clock bug.
- **Logs view is intentionally raw**: 2.5s poll + direct append, raw JSON lines, no drip-feed/filter/pretty-render. Don't re-add log post-processing.

**Adding a scan-detail panel:** create `components/<X>Panel.jsx`, fetch via `api.js`, use theme tokens + `parseTs`, mount it as a tab in `ScanDetail.jsx`.

---

## 12. Configuration (env)

Copy `.env.example` → `.env`. Most-used keys:

| Key | Purpose |
|---|---|
| `LLM_PROVIDER` | `claude_cli` \| `bedrock` \| `deepseek` (UI Settings overrides via `.antigravity/llm_provider`) |
| `DEEPSEEK_API_KEY` / `DEEPSEEK_BASE_URL` | DeepSeek provider |
| `AWS_REGION` / `AWS_BEDROCK_{SMALL,LARGE}_MODEL` | Bedrock provider |
| `DATABASE_URL` or `POSTGRES_{HOST,PORT,DB,USER,PASSWORD}` | Postgres (optional) |
| `API_HOST` / `API_PORT` / `API_KEY` / `CORS_ORIGINS` | API server |
| `ENCRYPTION_KEY` (+ `_CURRENT`/`_PREVIOUS`) | secret encryption; dev: `ANTIGRAVITY_ENV=development` + `ENCRYPTION_KEY_DEV_UNSAFE=1` |
| `OOB_DOMAIN` | cloudflared/OOB callback host |
| `LLM_MAX_BUDGET_USD` / `LLM_FALLBACK_CHAIN` / breaker vars | cost + resilience |
| `SHODAN_API_KEY`, `CENSYS_PAT`, `GITHUB_TOKEN`, `NVD_API_KEY`, `ABUSEIPDB_API_KEY` | OSINT/intel enrichment (all optional) |
| `REPORTS_ENABLED` / `REPORTS_DIR` | opt-in report file output |

Generate encryption keys: `python scripts/generate_keys.py`.

---

## 13. Local dev workflow

```bash
# 1. env
python -m venv .venv && .venv\Scripts\activate      # Windows
pip install -r requirements.txt
pip install -r ui/api/requirements.txt python-multipart
cp .env.example .env                                 # then edit

# 2. optional Postgres
docker compose up -d

# 3. API (terminal 1)
python ui/api/server.py

# 4. UI (terminal 2)
cd ui/web && npm install && npm run dev              # http://localhost:5173

# 5. or run a scan headless
python main.py --target https://example.com --tier POC --auto-approve
```

Only run scans against targets you own or are explicitly authorized to test.

---

## 14. Testing & lint

```bash
python -m pytest tests/ -q          # runs without Postgres (SQLite/mocked)
python -m ruff check .              # lint (config: ruff.toml)
cd ui/web && npm run lint           # oxlint
```

- Add a regression test for every planner/normalizer shape and every probe you add.
- Never edit a test to hide a broken change — fix the root cause.
- Live scoring vs disposable targets: `docker compose -f docker-compose.benchmark.yml up --abort-on-container-exit`.

---

## 15. Security invariants (do not break)

1. **Authorization first.** `TargetScopeValidator.is_authorized()` gates every request. Out-of-scope hosts are blocked at request time even if injected via mobile/SAST scope enrichment.
2. **Egress guard.** `core/security/egress_firewall.install_httpx_guard()` installs at import in `main.py`.
3. **Non-destructive default.** `POC` tier only demonstrates; escalation to `SHALLOW`/`DEEP` is explicit.
4. **Consent.** Active exploitation requires consent unless `--auto-approve`.
5. **No secret logging.** Never log passwords/API keys/tokens/secrets. `core/security/llm_redact.py` redacts LLM I/O; server.py strips `password`/`api_key`/`token`/`secret` from captured `key=value` pairs.
6. **Credentials via file, unlinked** — never via argv.
7. **Audit everything** to `pentest.log` + `audit_log`/`execution_audit` tables.

---

## 16. Gotchas

- Backend edits need a **new scan** to take effect (subprocess model).
- `claude_cli` + huge system prompt → empty `{}` on Windows: fold prompt into stdin, not `--append-system-prompt`.
- Non-native providers must go through the normalizer — test the exact JSON shape.
- Frontend timestamps: always `parseTs`.
- Don't re-introduce log filtering/drip-feed in the UI logs view (reverted by design).
- Postgres may be down — code must not assume a live connection.

---

## 17. Project memory (`.agent/`)

For multi-session work, persist state in `.agent/{progress,decisions,known-issues,next-task}.md`. Keep entries concise.
