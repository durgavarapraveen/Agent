# Developer Guide

Engineering reference for contributors to the Autonomous Pentesting Agent (codename **Neo** / "AntiGravity v2.0"). Read this before changing orchestration, the LLM harness, probes, tools, or the UI.

> **Scope law (non-negotiable):** authorized targets / labs / CTFs only. Never remove authorization checks, never weaken security controls, and never log passwords, API keys, tokens, or secrets. Every network request passes `TargetScopeValidator` before it leaves the process. See [§17 Security invariants](#17-security-invariants-do-not-break).

---

## Table of contents

1. [What this is](#1-what-this-is)
2. [Repo layout (top level)](#2-repo-layout-top-level)
3. [The `core/` package — full folder map](#3-the-core-package--full-folder-map)
4. [Scan lifecycle (end to end)](#4-scan-lifecycle-end-to-end)
5. [LLM harness & providers](#5-llm-harness--providers)
6. [Jev — typed classifier](#6-jev--typed-classifier)
7. [Planner & normalizer](#7-planner--normalizer-non-native-path)
8. [Parallel agents, watchdog & concurrency](#8-parallel-agents-watchdog--concurrency)
9. [Probes & dynamic payload synthesis](#9-probes--dynamic-payload-synthesis)
10. [External tool arsenal & Kali execution](#10-external-tool-arsenal--kali-execution)
11. [Metasploit integration](#11-metasploit-integration)
12. [Target-agnostic helpers](#12-target-agnostic-helpers)
13. [Persistence rules](#13-persistence-rules)
14. [Out-of-band (OOB) verification](#14-out-of-band-oob-verification)
15. [API server](#15-api-server) · [16. Frontend](#16-frontend)
17. [Security invariants](#17-security-invariants-do-not-break)
18. [Technologies used](#18-technologies-used)
19. [Config, dev workflow, testing, gotchas](#19-configuration-env)

---

## 1. What this is

An AI-driven multi-agent pentest engine. A **CentralBrain** drives a 4-phase pipeline; an LLM plans each phase, deterministic specialist agents execute in parallel, findings are verified, chained, scored, and persisted. A FastAPI server launches scans as isolated subprocesses; a React/Vite dashboard streams progress. External security tools run inside an isolated **Kali container**.

```
┌─────────────┐   POST /api/scans    ┌──────────────┐   Popen        ┌──────────────────┐
│ React UI    │ ───────────────────▶ │ FastAPI API  │ ─────────────▶ │ main.py (scan)   │
│ (Vite:5173) │ ◀─── poll/stream ─── │ (uvicorn)    │ ◀── DB rows ── │ CentralBrain     │
└─────────────┘                      └──────┬───────┘                └────┬─────────┬───┘
                                            │  reads                 writes│         │ docker exec
                                            ▼                              ▼         ▼
                            ┌───────────────────────────────┐   ┌──────────────────────────┐
                            │ PostgreSQL (pg_store, pgvector)│   │ Kali container            │
                            │  — degrades if absent          │   │ nuclei/nmap/sqlmap/msf/…  │
                            └───────────────────────────────┘   └──────────────────────────┘
```

**Critical mental model:** a scan is a **separate OS process**, not an in-process task of the API. `ui/api/server.py::_run_scan_process` spawns `python main.py --target … --tier … --scan-id <job_id>`. The UI and the scan communicate **only through the database**.

Consequence:
- **Backend changes** (anything in `core/`, `agents/`, `main.py`) apply on the **next scan** — a running scan won't pick them up.
- **API changes** (`ui/api/server.py`) require restarting the API process.
- **Frontend changes** (`ui/web/src`) apply immediately via Vite HMR.

---

## 2. Repo layout (top level)

```
outputs/
├── main.py                     # scan entrypoint (CLI). Spawned per-scan by the API.
├── agents/                     # LLM harness + providers + exploit/kali executors
│   ├── universal_llm_harness.py    # ProviderType enum, factory, pricing
│   ├── llm_harness_adapter.py      # get_llm()/get_provider(); provider selection
│   ├── kali_executor.py            # KaliDockerExecutor — docker exec / native tool runner
│   └── providers/                  # bedrock / deepseek / ollama + jev_classifier + routing
├── core/                       # the engine — see §3 for the full folder map
├── ui/
│   ├── api/server.py           # FastAPI: scans CRUD, live data, downloads, chat
│   └── web/                    # React 19 + Vite + react-router 7
├── tests/                      # pytest suite (runs without Postgres)
├── benchmarks/                 # scoring vs disposable targets (Juice Shop / DVWA)
├── scripts/                    # keygen, payload bundles, corpus/recall tooling
├── skills/ templates/ reports/ logs/ data/
├── Dockerfile                  # Kali tools + Metasploit image
├── Dockerfile.web              # API + built UI image
├── docker-compose.yml          # web + kali + postgres stack
├── docker-compose.benchmark.yml / .anon.yml
├── requirements.txt            # Python deps (core)
├── ui/api/requirements.txt     # fastapi, uvicorn
├── .env.example                # every env var, documented (single template)
├── pytest.ini · ruff.toml · pyrightconfig.json
└── README.md · DEVELOPER.md
```

---

## 3. The `core/` package — full folder map

~65 subpackages. One line each, grouped by responsibility.

### Orchestration & brain
| pkg | responsibility |
|---|---|
| `orchestration` | central brain, agent spawner/scheduler, phase DAG, blackboard, dispatcher, campaigns |
| `workflow` | records, learns, and violation-tests multi-step business workflows |
| `workflows` | concurrency engine + state machine + workflow generator |
| `scheduling` | experiment scheduler + duplicate-work detector |
| `decisions` | decision guard, policy engine, provenance for agent choices |
| `actuation` | top-level agent loop that drives actions (actuators, browser actuator/agent) |
| `execution` | executor pipeline + per-vuln executors (authz, sqli, xss, role-escalation) |
| `adaptation` | generic site adapter + WAF-state adaptation |
| `checkpointing` | secure scan checkpoint save/restore |
| `recovery` | recovery policy for failed/interrupted work |
| `convergence` | completion validator — decides when a scan is done |
| `failure` | failure-taxonomy classification |

### Recon & discovery
| pkg | responsibility |
|---|---|
| `recon` | surface classifier, network/cloud enum, **request-surface miner** |
| `discovery` | coverage-driven multi-channel discovery; JS/mobile/IPA analyzers; workflow crawler |
| `attack_surface` | endpoint/param/object/request inventories, SPA detector, route graph |
| `browser` | Playwright browser worker + JS-aware crawler with observability |
| `extraction` | endpoint + parameter extractors |
| `coverage` | coverage engine/state, blind-spot detector, convergence, hypothesis ledger |
| `network` | network broker (connection brokering) |

### Exploitation & probes
| pkg | responsibility |
|---|---|
| `exploitation` | **largest pkg** — ~90 probes (ssti/xxe/cors/race/smuggling/deserial/graphql/web3), chain builder/reasoner/executor, PoC generator, WAF evasion, `payload_synth.py`, `format_probes/` (parquet/yaml-pickle/hdf5) |
| `injection` | injection models + reporter + eligibility gate |
| `payloads` | payload catalog, mutation, seeds, `probe_engine.py`, git `updater.py` |
| `fuzzing` | grammar engine, multi-parser, fuzzing models, tool adapters |
| `oob` | out-of-band collaborator (blind callback channel) |
| `cloud` | IAM privilege-escalation checks |
| `escalation` | escalation-gate logic |
| `defensive` | blue-team monitors (persistence/network/credential hardening) |

### LLM & reasoning
| pkg | responsibility |
|---|---|
| `llm` | Bedrock config, model routing, circuit breaker, prompt compression/safety, response cache, `json_enforcer.py`, `jev_config.py` |
| `reasoning` | typed planner, hypothesis engine, reasoning engine |
| `hypothesis` | hypothesis generator + ranker |
| `rag` | embedder/local-embedder, reranker, ingestion pipeline, knowledge seeder |
| `prompts` | adaptive prompt construction |
| `learning` | experience learner, reward policy, structured learning |
| `analysis` | finding confidence, taint/correlation, CodeQL/SAST runner, anomaly pipeline |

### Identity & access-control
| pkg | responsibility |
|---|---|
| `identity` | credential store, identity/session managers, differential tester, login detector |
| `authentication` | auth session, OAuth flows, identity bridge |
| `access_control` | horizontal/vertical/IDOR/matrix models |
| `replay` | HTTP proxy, replay engine, cross-role identity store |

### Intelligence & OSINT
| pkg | responsibility |
|---|---|
| `intelligence` | OSINT engine, Censys, subdomain enum, takeover detector, threat/vuln intel, differential/metamorphic engines |
| `intel` | skill library, target memory, tool authoring |
| `knowledge` | knowledge/attack-surface graph, persistent + PG stores, semantic inference |
| `domain` | domain models (finding, evidence, identity, request, session, task state machine) |

### Persistence & evidence
| pkg | responsibility |
|---|---|
| `database` | artifact store + **`pg_store.py` (ALL SQL)** |
| `memory` | experience/failure/strategy stores, pentest memory, dedup, retention |
| `evidence` | evidence model + validator |
| `findings` | finding store, observation, finding state machine |

### Security, verification & governance
| pkg | responsibility |
|---|---|
| `security` | authorization service, capability registry, execution auditor, **egress firewall**, watchdog |
| `verification` | reproduction/confirmation gates, critic agent, oracle engine |
| `validation` | contract/tool-arg validators, reachability, eval harness, readiness gate |
| `scope` | in-scope target manager |
| `compliance` | framework mapper + reporter (PCI/SOC2/HIPAA/CIS/NIST) |
| `economics` | budget governor, cost/LLM/**Jev** logs |

### Reporting & scoring
| pkg | responsibility |
|---|---|
| `reporting` | report builder, canonical/compliance/SARIF/MITRE exporters, remediation & fix generators, risk prioritizer, quality gates, retest engine, repro bundle |
| `scoring` | confidence scorer |

### Infra & utils
| pkg | responsibility |
|---|---|
| `common` | config/settings, schemas, **target_shape/auth_shape/request_schema** (§12), normalizer, retry, token optimizer, url_hygiene |
| `tools` | external tool adapters + registry + invocation engine + router (§10) |
| `observability` | structured logging, OTel tracing, scan metrics, correlation |
| `monitoring` | ASM/surface baseline, regression detector, incremental monitoring |
| `notifications` · `integrations` · `error` | outbound notify · ticket export · error classifier |
| `benchmark` | corpus + runner for scoring the scanner |
| `utils` · `skills` | sanitization helpers · skills scaffold |

---

## 4. Scan lifecycle (end to end)

1. **UI** `POST /api/scans` with `{target, tier, credentials?, phases?}`.
2. **API** creates a `scans` row (status `running`), builds an argv list, and `subprocess.Popen`s `main.py` with `--scan-id <job_id>` (`_run_scan_process`). Credentials → temp JSON file passed via `--credentials-file`; `main.py` reads then **unlinks** it (never argv — leaks via `/proc`).
3. **main.py `main()`**:
   - `anon_gate.enforce_or_die()` — anonymity/egress gate; egress firewall installed at import.
   - eager `get_collaborator()` — binds the OOB listener for the whole scan.
   - `load_config()`, sets tier/frameworks, runs optional standalone mobile/SAST steps.
   - `run_single()` → `CentralBrain(target, scope, scan_id)` → `brain.run_main_loop()`.
4. **CentralBrain.run_main_loop** walks the phase DAG. For each phase → `_run_phase`:
   - provider `supports_native_tools()` → agentic loop (`agentic_executor.py`); else → **JSON planner** path `_run_phase_approach_a` (§7).
   - Deterministic parallel specialist teams run via `family_scheduler` (§8).
   - A **coverage gate** (`_assert_phase_coverage`) forces required lanes.
   - Network verification (`_run_network_verification`) auto-dispatches the Metasploit aux lane on open ports (§11).
5. **Post-scan** (`main.py`): chain synthesis + rescoring (`_post_scan_chain_analysis`), PoC bundles, attack-surface baseline + regression, SAST↔DAST correlation, final `_persist_vulnerabilities()`.
6. **UI** polls `/api/scans/<id>/…` and renders live.

Phases: `RECON → ACTIVE_SCANNING → EXPLOITATION → REPORTING`. Tiers: `POC` (default, non-destructive) → `SHALLOW` → `DEEP`.

---

## 5. LLM harness & providers

All model calls go through `agents/llm_harness_adapter.py::get_llm()` / `get_provider()`. **Never** call a provider SDK directly from feature code.

| provider | native tools | notes |
|---|---|---|
| `deepseek` *(default)* | ❌ | OpenAI-compatible. `DEEPSEEK_API_KEY`, `DEEPSEEK_BASE_URL`, `DEEPSEEK_{SMALL,LARGE}_MODEL`. |
| `bedrock` | ✅ | AWS Bedrock (boto3), incl. the **Mantle OpenAI-compat gateway** (`bedrock-mantle.<region>.api.aws`, deepseek.v3.x); token via `aws-bedrock-token-generator` / `provide_token()`. |
| `ollama` | ❌ | local models. `OLLAMA_BASE_URL`. |

**Selection order** (adapter): `LLM_PROVIDER` env → `.antigravity/llm_provider` file (written by UI Settings) → `.env` → default. `LLM_FALLBACK_CHAIN` (e.g. `deepseek,bedrock,ollama`) gives automatic failover; `core/orchestration/execution_mode.is_bedrock_available()` decides if Bedrock is usable (creds + region resolve).

**`supports_native_tools()` is the fork that matters.** Native-tool providers get the agentic loop; everyone else gets the deterministic JSON-planner path. Any new provider must implement this honestly.

**Adding a provider:** (1) `agents/providers/<name>_provider.py` implementing `complete`/`chat`, `supports_native_tools`, model config; (2) add to `ProviderType` + pricing + factory in `universal_llm_harness.py`; (3) add to `_VALID_PROVIDERS` + init branch in `llm_harness_adapter.py`; (4) add the Settings option in `ui/api/server.py`; (5) add env vars to `.env.example`.

Related knobs: `json_enforcer.py` repairs/salvages malformed or truncated JSON (incl. `_salvage_truncated_array` for max_tokens cutoffs); `llm_router.py` sets `payload_generation` `max_tokens=4096`; the response cache uses single-flight future dedup to collapse concurrent identical calls (see `payload_synth.py`).

---

## 6. Jev — typed classifier

Jev (TypeSafe "System-One") is **not a text LLM** — it returns typed, calibrated decisions (`noul` / `choice` / `score`) with probabilities, complementing the reasoning LLM. `agents/providers/jev_classifier.py` is a thin async `httpx` wrapper over `POST /systemone` at `api.typesafe.ai` (on the egress allowlist). **Every failure returns `{}`/`None`** — a Jev outage never breaks a scan.

Config: `core/llm/jev_config.py`, with **opt-in env-gated wiring sites** (all off by default):
- `NEO_JEV_ROUTING` — recover a probe family from surface signals the keyword matcher missed (`request_surface_miner.py`, `family_scheduler.py`, `probe_engine.py`).
- `NEO_JEV_PHASE_GATE` — score-gate phase progress to kill slow-stall loops (`central_brain.py`, `dispatcher.py`).
- `NEO_JEV_TOOL_GATE` — `noul` risk-gate (fail-open) before a tool action fires (`agentic_executor.py`).
- triage / prioritization — corroborate confirmed findings **without ever suppressing them** (`finding_verifier.py`, `llm_validator.py`), and rank surfaces high-value-first in `dispatcher._prioritize_surfaces` (`NEO_JEV_PRIORITIZE`).

Decisions logged via `core/economics/jev_log.py`; surfaced in `ui/web/src/components/JevDecisionsPanel.jsx`.

---

## 7. Planner & normalizer (non-native path)

For non-native providers, the LLM returns JSON; `core/common/normalizer.py::PlannerResponseNormalizer.normalize` turns arbitrary-but-plausible LLM output into a canonical task list. Highest-churn correctness surface.

Handles: action aliases → `SPAWN_AGENTS` (`execute_capability`, `execute_tool`, `run_tool`, `tool_call`, `use_tool`, …); the single tool-call shape; capability inference reading **both** plural `tools` and singular `tool`; task-spec normalization (`objective`↔`reason`, `params`↔`parameters`).

When you touch the planner: add a unit test with the exact offending JSON shape. **Never special-case a provider — normalize the shape.** Guard: on iteration 0 with zero agents and no history, `_run_phase_approach_a` forces `_deterministic_fallback` so a phase never silently does 0 steps.

---

## 8. Parallel agents, watchdog & concurrency

`core/orchestration/family_scheduler.py` runs deterministic specialist teams concurrently, independent of the LLM:
- `run_recon_teams(brain)` — OSINT ∥ Web ∥ Infra lanes, then a dependent API-classification lane. Each lane writes reasoning via `_reason()` (→ `agent_reasoning`, shown as "thoughts").
- `run_specialist_probes(brain)` — probe families by `TestFamily` / `AgentTier`.
- `run_authenticated_battery(brain)` — multi-identity authz testing.

**AgentTracker / LiveAgentRepo** (`parallel_agents.py` → `live_agents` table) track live state: `start()` → `heartbeat(steps_taken=, findings_count=)` → `finish(findings=)`. A tracker that only `start()`s + `finish()`es shows `steps:0/findings:0` — always heartbeat step counts.

**Concurrency** (`core/orchestration/concurrency.py`): `probe_concurrency()` (env `PROBE_CONCURRENCY`, default 8, health-capped), `kali_concurrency()` for tool fan-out. Fallback chains stay ordered.

**Watchdog** (`core/security/watchdog.py`): `ScanBudget` (`max_runtime_s`, default 7200), `get_watchdog()` singleton, `elapsed_fraction()`. `run_parallel_agents` consults `elapsed_fraction() >= BUDGET_SOFT_EXIT_FRAC` (0.85) as each agent is about to start and **stops launching new ones** once hit — a huge fan-out is one long `gather()` the phase-loop watchdog can't otherwise interrupt (that's how scans overrun `max_runtime`). Coverage gate + no-progress guard force phase advance.

**Coverage ledger** (`brain._coverage_ran`): records which lanes ran; `_assert_phase_coverage(phase)` enforces required coverage at the end of recon, after specialist probes, and after expert probes.

---

## 9. Probes & dynamic payload synthesis

Probes live in `core/exploitation/*_probe.py`; each is a self-contained detector for one vuln class. When a defense inspects the *shape* of the payload (WAF, template engine, parser), the probe asks the LLM for context-aware payloads instead of static lists.

`core/exploitation/payload_synth.py` — `synthesize()` / `synth_payloads()`:
- Flow: **PROPOSE → verify**. The LLM proposes candidates; the probe verifies each against the live oracle before claiming a finding.
- `_KIND_SPEC`: `polyglot`, `ssti`, `deserialize`, `mass_assign`, `graphql_query`, `waf_bypass`, `business_logic`, `xxe`.
- OOB kinds embed `OOB_PLACEHOLDER`, replaced with a live collaborator token at send time.
- Feedback-aware: failed attempts are fed back so round 2 adapts.
- **Single-flight dedup**: concurrent identical `(kind, canary, context)` synth requests share one LLM call via an `asyncio` future (`_inflight`), preventing cache-stampede fan-out.

**Proof**: `core/exploitation/proof_util.attach_proof()` puts request-sent + response-received + curl on every exploit finding and fills empty `method`/`target`/`location`. Findings persist via the **live pipeline only** — return finding dicts, never write-then-parse files.

**Adding a probe:** (1) `core/exploitation/<name>_probe.py` reusing the probe base; (2) if detection is payload-shape-dependent, call `payload_synth.synthesize(kind=…)` and verify each candidate; (3) register with the family scheduler; (4) return finding dicts; (5) add a regression test.

---

## 10. External tool arsenal & Kali execution

### Execution model

Two adapter layers build a shell command string, run by `KaliTool.run()` → `KaliDockerExecutor.run()`:
- `core/tools/tool_adapter.py` — per-tool `*Adapter` classes build `{"command": "<tool flags target>"}` (stack/profile-aware). `FORBIDDEN_TOOLS = {bash, sh, cmd, powershell, zsh}` blocks generic shells.
- `agents/kali_executor.py::KaliDockerExecutor` — the runner.

**Dual path** (`kali_executor.py`):
- **Native**: if `/.dockerenv` exists, or (non-Windows and `nmap` on PATH) → runs on host PATH via `timeout --signal=KILL <n>s <cmd>`.
- **Docker**: otherwise → `docker exec <container> timeout -k 10s -s TERM <n>s <cmd>` (`shell=False`, no injection). rc 124/137 (timeout/OOM) triggers in-container `pkill -9 -f <tool>` reaping; memory-heavy tools wrapped with `prlimit --as=`.

**Container discovery** (`get_container`): `docker ps` → match any container whose image/name contains `kali` (or os-release says kali); else start a stopped one; else auto-create `docker run -dit --init --name kali-pentesting-mcp kalilinux/kali-rolling bash`. Compose names it `kali-pentesting` (env `KALI_CONTAINER`); both are matched. Missing tools are `apt-get install`ed on demand (`ensure_tool`, `TOOL_PACKAGES`).

**Routing**: `tool_router.py` / `tool_invocation_engine.py` map an abstract capability → ordered tool list → `ToolRegistry.execute()` → `tool.run()`. Per-tool normalization (`_normalize_command`) scopes nuclei (`-severity/-rl/-c/-jsonl`), nmap (`--top-ports/--host-timeout`), strips SPA `#` fragments, canonicalizes URLs.

### Arsenal (grouped)

| category | tools |
|---|---|
| **Port/host** | nmap, masscan, rustscan, port_check* |
| **Subdomain/DNS** | subfinder, assetfinder, amass, chaos, dnsx, dnsenum, dnsrecon, fierce, dig/host/nslookup, whois, dns_lookup* |
| **Content/param discovery** | gobuster, feroxbuster, ffuf, dirb, dirsearch, arjun, paramspider, gau, waybackurls, katana |
| **HTTP/fingerprint** | httpx / httpx-toolkit, whatweb, wafw00f, http_request*, http_fetch/parse_html* |
| **Vuln scanners** | nuclei, nikto, wpscan |
| **Injection/exploit** | sqlmap (SQLi), dalfox (XSS), commix (cmd-inj), xsser |
| **TLS** | sslscan, sslyze, testssl.sh, openssl, ssl_inspect* |
| **Auth/network** | hydra, medusa, john, hashcat, responder, crackmapexec/netexec, enum4linux(-ng), smbclient, ldap-utils, impacket |
| **Capture/debug** | tcpdump, tshark, gdb |
| **Browser** | playwright (`HeadlessBrowserTool`) |
| **Metasploit** | `msf_scanner` (read-only aux — §11) |
| **OSINT** | theharvester, ddgs (DuckDuckGo), Censys client |

`*` = Python built-in tool (no Docker; `core/tools/http_ops_tools.py` etc.). Some tools (hydra/john/hashcat/responder/enum4linux…) are installed/mapped but invoked by the orchestrator through the generic Kali path rather than a dedicated adapter.

---

## 11. Metasploit integration

- **File**: `core/tools/adapters/metasploit.py` — `MetasploitAuxTool(KaliTool)`, registered as **`msf_scanner`**.
- **Enable**: env **`NEO_ENABLE_MSF`** (1/true/yes/on), resolved by `core/utils/scan_flags.py::enable_metasploit()`; env wins, else persisted UI file `.antigravity/enable_msf`. **Off by default** → returns a disabled error.
- **Hard safety contract**: only `^auxiliary/scanner/…$` modules (`_ALLOWED`); denied substrings even there (`login, brute, enum_users, fuzzer, /dos/, dos_`); no `exploit/`, `post/`, `payload/`, no LHOST/session/meterpreter. RHOSTS is scope-validated fail-closed via `TargetScopeValidator`.
- **How it runs**: one-shot `msfconsole -q -x "use <mod>; set RHOSTS <host>; set RPORT <p>; run; exit"` through `KaliDockerExecutor`. **No msfrpcd/RPC daemon.** msfconsole is never auto-installed (it's baked into the Kali image; the build fails if `msfconsole -v` doesn't run) — a missing binary is a normal, non-fatal tool skip.
- **Auto-dispatch**: `central_brain._run_network_verification()` (during the active-scanning sweep), gated on `enable_metasploit()`, idempotent (`_netverify_ran`); maps discovered open `ctx.ports` → curated `_PORT_DEFAULT` modules (445→smb_ms17_010, 22→ssh_version, 443→openssl_heartbleed, 80/8080→http_version, …) via `invoke_from_capability("network_vuln_verification", …)`; regex-matches `VULNERABLE` → adds a HIGH `NETWORK_SERVICE` finding.
- **Not auto-run**: `core/exploitation/exploit_factory.build_msf_command()` generates full exploit `msfconsole` strings from a `CVE_TO_MSF_PATH` map — a **dry-run / manual-review generator only** (DISCLAIMER-prefixed), never executed.

> Keep MSF a read-only aux scanner. Do not wire exploit modules into auto-dispatch.

---

## 12. Target-agnostic helpers

Three shared helpers in `core/common/` de-hardcode ~40 target assumptions so tests aren't silently skipped on differently-named targets. All accept operator overrides via `NEO_*` env vars for truly unknowable conventions.

| helper | de-hardcodes | override env |
|---|---|---|
| `target_shape.py` | path/param substring gates (`"/api/" in path`, numeric-id regexes, role literals) → deterministic signal-based classifiers (`is_api_endpoint`, `is_login_endpoint`, `is_privileged_path`, id shapes UUID/ULID) | `NEO_REDIRECT_PARAMS`, `NEO_FILE_PARAMS`, `NEO_ADMIN_ROLES`, `NEO_ANON_ROLES`, … |
| `auth_shape.py` | JWT-only (`eyJ`) success check → accepts opaque tokens, PASETO, cookie sessions; reads role claims across Keycloak/Cognito/Auth0 shapes (`extract_session`, `primary_role`) | `NEO_TOKEN_KEYS` |
| `request_schema.py` | app-specific body field names (`passwordRepeat`, `securityAnswer`) → derived from captured traffic/parsed forms (`credential_fields`, `build_login_body`) | `NEO_USERNAME_FIELDS`, `NEO_PASSWORD_FIELDS`, … |

Also expose async `jev_is_api/jev_is_login/jev_is_privileged` for Jev-assisted classification. Prefer these helpers over any literal target string in probe/recon code.

---

## 13. Persistence rules

- **All SQL is in `core/database/pg_store.py`.** ~45 tables (`scans`, `vulnerabilities`, `exploit_results`, `findings_v2`, `live_progress`, `live_results`, `live_agents`, `agent_reasoning`, `attack_chains`, `tool_outputs`, `captured_requests`, `kg_nodes/edges/hypotheses`, `audit_log`, `execution_audit`, …). Timestamps `TIMESTAMPTZ DEFAULT NOW()`. Postgres image is `pgvector/pgvector:pg16` (RAG embeddings).
- Postgres is **optional at runtime** — degrade gracefully (writes skipped) if unreachable. Never assume a connection.
- **Never parse `.log`/`.json` artifact files to insert vuln data into the DB.** Only the live pipeline writes findings. (Hard project rule.)
- `custom_probe` confirmations persist via an **oracle + LLM sweep** so exploit confirmations always land.
- **Audit trail** is DB-primary (`audit_log`/`execution_audit`, hash-chained); file mirrors gated by `NEO_FILE_AUDIT`. The **RL reward policy** (`RewardPolicyRepo` → `learned_reward_policy`) is DB-backed (was `data/learning/reward_policy.json`). Neither writes a `data/` file by default.
- Every finding is canonicalized at ingestion (`central_brain_mixins/finding_ingestion._stamp_and_add_vuln`) — the universal choke that fixes `get://` double-scheme URL corruption on `location`/`target`/`url`/`affected_endpoint`.

---

## 14. Out-of-band (OOB) verification

`core/oob/collaborator.py` gives blind vulns (XXE/SSRF/deserialization) a callback channel at zero cost.
- `LocalHTTPCollaborator` — local listener (default `:8899`), path-token based, exposed via a **cloudflared** tunnel. Default free path.
- `InteractshCollaborator` — real interactsh (RSA register + AES-CFB) if you run a server.
- `NullCollaborator` — no-op when OOB is disabled.

Helpers: `prepare_oob()`, `confirm_oob()`, `token_marker()`, `OOB_PLACEHOLDER`. `get_collaborator()` is initialized eagerly in `main.py` so the listener is up for the whole scan. Setup: `OOB_DOMAIN` in `.env`, run cloudflared to `localhost:8899`. A 502 on the tunnel = nothing bound (scan not running).

---

## 15. API server

`ui/api/server.py` — FastAPI + uvicorn (default port from `.env`; compose uses **8900**).
- **Auth**: `X-API-Key` header (middleware `_require_api_key`). Downloads accept `?api_key=` on a narrow GET allowlist. Dev key auto-written to `.antigravity/dev_api_key`.
- **Scan launch**: `_run_scan_process` (argv list, no shell). Credentials via unlinked temp file.
- CORS: `CORS_ORIGINS`. Rate limiting via `slowapi` (falls back to built-in).
- Restart the API after editing `server.py`.

---

## 16. Frontend

`ui/web` — React 19, Vite, react-router 7. No component library; styling via CSS tokens in `index.css`.
- **API client**: `src/api.js` — injects `X-API-Key` (from `ag_api_key` localStorage / `?api_key=` bootstrap).
- **Theme**: light theme via CSS custom properties (`--bg-card`, `--bg-surface`, `--border`, `--accent`, `--text`, …). Use tokens, never hardcoded colors.
- **Pages** (`src/pages`): `LiveScan.jsx`, `ScanDetail.jsx` (tabs: Logs/Exploits/Coverage/Tool Outputs/Jev/…), `Scans.jsx`, `Dashboard.jsx`, `Settings.jsx`, `Analyze.jsx`, `Targets.jsx`, `KnowledgeBase.jsx`.
- **Components** (`src/components`): `LiveAgentsPanel.jsx`, `ScanChatPanel.jsx`, `CoveragePanel.jsx`, `AttackChainsPanel.jsx`, `ReconPanel.jsx`, `JevDecisionsPanel.jsx`.
- **Timestamps**: backend emits naive-UTC ISO. Always parse with `utils.js::parseTs` — raw `new Date()` reintroduces the `+5:30` bug.
- **Logs view is intentionally raw** (2.5s poll + append). Don't re-add filtering/drip-feed.

Adding a scan-detail panel: `components/<X>Panel.jsx`, fetch via `api.js`, use theme tokens + `parseTs`, mount as a tab in `ScanDetail.jsx`.

---

## 17. Security invariants (do not break)

1. **Authorization first.** `TargetScopeValidator.is_authorized()` gates every request; out-of-scope hosts blocked even if injected via mobile/SAST enrichment.
2. **Egress guard.** `core/security/egress_firewall.install_httpx_guard()` installs at import in `main.py`. Only allowlisted hosts (target + `api.typesafe.ai` + configured intel APIs) leave the process.
3. **Non-destructive default.** `POC` tier only demonstrates; escalation is explicit.
4. **Consent.** Active exploitation needs consent unless `--auto-approve`.
5. **Metasploit read-only.** Allowlist + scope + `NEO_ENABLE_MSF`; no exploit modules auto-run.
6. **No secret logging.** `llm_redact.py` redacts LLM I/O; server.py strips `password`/`api_key`/`token`/`secret`.
7. **Credentials via file, unlinked** — never argv.
8. **Audit everything** to the DB `audit_log` / `execution_audit` tables — hash-chained (`previous_hash`→`current_hash`), tamper-evident. On-disk mirrors (`data/audit.log`, `data/execution_audit.log`) are **off by default**; set `NEO_FILE_AUDIT=1` to also write them. `pentest.log` remains the operational log.

---

## 18. Technologies used

| layer | stack |
|---|---|
| **LLM / AI** | DeepSeek + AWS Bedrock (boto3, `aws-bedrock-token-generator`) + Ollama; `tiktoken`; **Jev/TypeSafe** typed classifier (httpx) |
| **ML / embeddings** | sentence-transformers, scikit-learn, scipy, numpy, joblib (RAG + reranking) |
| **Backend / API** | FastAPI, uvicorn, fastmcp (MCP), slowapi + aiolimiter, httpx / aiohttp, websockets |
| **Frontend** | React 19, react-router 7, Vite, oxlint |
| **Database** | PostgreSQL 16 + **pgvector**, psycopg2-binary |
| **Security tooling libs** | Playwright, impacket, cryptography, dnspython, semgrep (opt), tree_sitter |
| **External tools** | Kali `kali-rolling` image — see §10 arsenal + Metasploit |
| **Reporting** | reportlab, weasyprint, xhtml2pdf, fpdf2, pypdf, python-docx, jinja2, matplotlib, PyYAML |
| **Observability** | prometheus-client, opentelemetry (opt, no-op fallback) |
| **Infra** | python-dotenv, pydantic, psutil, pytest, ruff, Docker Compose |

---

## 19. Configuration (env)

Copy `.env.example` → `.env`. Most-used keys:

| Key | Purpose |
|---|---|
| `LLM_PROVIDER` | `deepseek` \| `bedrock` \| `ollama` (UI Settings overrides via `.antigravity/llm_provider`) |
| `DEEPSEEK_API_KEY` / `DEEPSEEK_BASE_URL` / `DEEPSEEK_{SMALL,LARGE}_MODEL` | DeepSeek provider |
| `AWS_REGION` / `AWS_BEDROCK_{SMALL,LARGE}_MODEL` | Bedrock provider |
| `LLM_FALLBACK_CHAIN` / `LLM_MAX_BUDGET_USD` | failover + cost cap |
| `DATABASE_URL` or `POSTGRES_{HOST,PORT,DB,USER,PASSWORD}` | Postgres (optional) |
| `API_HOST` / `API_PORT` / `API_KEY` / `CORS_ORIGINS` | API server |
| `KALI_CONTAINER` | Kali container name (compose: `kali-pentesting`) |
| `NEO_ENABLE_MSF` | Metasploit aux lane on/off |
| `NEO_FILE_AUDIT` | also mirror the hash-chained audit to `data/{audit,execution_audit}.log` (default off — DB is the audit store) |
| `NEO_ASM_MONITORING` | post-scan ASM baseline + regression (default off; writes `data/{baselines,regression,asm}`) |
| `NEO_JEV_*` / `NEO_JEV_PRIORITIZE` | Jev wiring sites (§6) |
| `PROBE_CONCURRENCY` / `DISPATCH_BUDGET` / `BUDGET_SOFT_EXIT_FRAC` | concurrency + watchdog |
| `NEO_PAYLOAD_SYNC` | opt-in payload-catalog git sync (default off) |
| `ENCRYPTION_KEY` (+ `_CURRENT`/`_PREVIOUS`) | secret encryption; dev: `ANTIGRAVITY_ENV=development` + `ENCRYPTION_KEY_DEV_UNSAFE=1` |
| `OOB_DOMAIN` | cloudflared/OOB callback host |
| `SHODAN_API_KEY`, `CENSYS_PAT`, `GITHUB_TOKEN`, `NVD_API_KEY`, `ABUSEIPDB_API_KEY` | OSINT/intel (optional) |
| `REPORTS_ENABLED` / `REPORTS_DIR` | opt-in report file output |

Generate encryption keys: `python scripts/generate_keys.py`.

### Local dev workflow

```bash
python -m venv .venv && .venv\Scripts\activate      # Windows
pip install -r requirements.txt
pip install -r ui/api/requirements.txt python-multipart
cp .env.example .env                                 # then edit
docker compose up -d postgres kali                   # DB + tools
python ui/api/server.py                              # terminal 1 — API
cd ui/web && npm install && npm run dev              # terminal 2 — UI (:5173)
python main.py --target https://example.com --tier POC --auto-approve   # or headless
```

Full Docker stack + Metasploit run instructions: **[README.md](README.md)** §A/§B. Only scan targets you own or are authorized to test.

### Testing & lint

```bash
python -m pytest tests/ -q          # runs without Postgres (SQLite/mocked)
python -m ruff check .              # lint (ruff.toml)
cd ui/web && npm run lint           # oxlint
docker compose -f docker-compose.benchmark.yml up --abort-on-container-exit   # live scoring
```

Add a regression test for every planner/normalizer shape and every probe. Never edit a test to hide a broken change.

### Gotchas

- Backend edits need a **new scan** (subprocess model); a running scan uses the code it started with.
- Non-native providers must go through the normalizer — test the exact JSON shape.
- Frontend timestamps: always `parseTs`.
- Postgres may be down — code must not assume a live connection.
- Tools "not found" locally → run inside the Kali container (`docker compose exec kali …`).
- `get://` URL corruption: canonicalize at the ingestion choke, never per-probe.

---

## 20. Project memory (`.agent/`)

For multi-session work, persist state in `.agent/{progress,decisions,known-issues,next-task}.md`. Keep entries concise.
