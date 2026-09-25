# Autonomous Pentester — Analysis + Fix Plan

Source-derived (README/DEVELOPER treated as stale). All refs `file:line`.
Generated 2026-09-25 from 4 parallel source audits (run-flow, agent-arch, central_brain, probe/chaining).

---

## STATUS (2026-09-25) — implemented + reviewed

DONE (each implemented, code-reviewed PASS, syntax + targeted tests green):
- **P0-1** shared confirmation gate `core/evidence/confirmation_gate.py` (`apply_ingestion_gates` + `oracle_reverify`); wired into `SharedContext.add_vulnerability` + `_stamp_and_add_vuln`. Oracle re-verify made conservative: downgrades ONLY response-derivable classes {SQLI,NOSQLI,SSTI,RCE,LFI,XXE,SSRF}, never field-keyed classes, never trusted-tool findings, requires a real response body. (Two review BLOCKs found + fixed: proof-as-response over-downgrade; details clobber.)
- **P0-2** SPA routes → injection surfaces (`surface_classifier._surface_from_spa_route` + same-domain guard).
- **P0-3** post-rescore pg re-flush in `_persist_vulnerabilities` (upsert confirmed to update severity).
- **P0-4** stop-signal slug aligned to server (`central_brain.py`).
- **P1-1** no-progress giveup folded into DAG transition path.
- **P1-2** shared `record_probe_observation` sink fed by custom_probe + probe_engine (missed-response capture).
- **P1-3** tool-arg sanitizer: unlisted tools no longer pass raw (danger blocklist, token-boundary); sqlmap/nuclei depth flags un-stripped.
- **P1-4** field-keyed oracle starvation: gate no longer over-downgrades them; mass_assign/business_logic set honest evidence keys.
- **P1-5** REPORTING (hosts CriticAgent) force-run once before any early loop exit.
- **D-1** remediation stage `core/remediation/fix_planner.py` — attaches actionable `remediation_plan` (root cause/fix/patch/verification/refs/effort) to every confirmed/high finding before report+persist; LLM-driven (bounded, attempt-capped) with deterministic per-class fallback + aliases; non-destructive. Wired in `_generate_report`.
- **P2-6** migrations reordered ascending; **P2-7** API port aligned to 8900 across server + settings.

DONE — deliberate follow-up (verify-first, each code-reviewed PASS, tests green):
- **P2-1** recon hand-off: `family_scheduler._RECON_COVERED_FAMILIES` = {SSL_TLS, CLOUD}; `classify_family_jev` now acknowledges these as recon/infra-covered (debug log) instead of emitting a false "novel surface" gap.
- **P2-3** the 3 clashing `HypothesisEngine` classes (reasoning=catalog-gap, coverage=surface/V2, hypothesis=ledger singleton) now carry distinguishing class docstrings so they can't be mis-imported. (Aggressive class-rename/merge deliberately avoided — high churn, low correctness value.)
- **P2-4** dead `llm_client`: removed the constructed-but-unused `ReasoningEngine(llm_client=None)` (+ its import); documented the reasoning `HypothesisEngine.llm_client` as a RESERVED hook (deterministic engine, LLM comes from DynamicHypothesisEngine).
- **P2-5** AUDIT CORRECTION: `SpecialistTeam`/`EvidenceBus` are NOT dead — they are imported by central_brain + family_scheduler and used in 2 tests. Only `ReasoningEngine` was dead (removed). `BaseAgent` is unused scaffolding but left in place (deleting a base class is risky, no correctness benefit).
- **D-2** VERIFIED the LLM Pα path is already live — `_run_dynamic_hypothesis_cycle` runs both first_order (cb:3916, ACTIVE_SCANNING) and second_order (cb:4676, EXPLOITATION); `DynamicHypothesisEngine._get_llm()` self-fetches the harness. Improvement: now pass the routed `self.llm` so Pα uses the same role-routed, cost-logged client (plus `enhancer.novel_payloads` per injection point already supplies LLM novelty). A full rewire of the rule-based engines was unnecessary.

STILL DEFERRED:
- **P2-2** active CSRF PoC — sends a real cross-site *state-changing* request (side effects); belongs behind human-assist / explicit consent, not an auto-loop. (Not requested in the follow-up.)

Changed files: core/evidence/confirmation_gate.py (new), core/remediation/{__init__,fix_planner}.py (new), core/memory/shared_context.py, core/orchestration/{central_brain.py,agentic_executor.py}, core/orchestration/central_brain_mixins/{finding_ingestion,persistence}.py, core/payloads/probe_engine.py, core/exploitation/{custom_probe,mass_assign_probe,business_logic_probe}.py, core/recon/surface_classifier.py, core/common/settings.py, core/database/pg_store.py, ui/api/server.py.

---

## PART A — HOW IT RUNS

**CLI** (`main.py:305` `main()` → `run_single`/`run_multi`/`CampaignManager`):
```
python main.py --target example.com --tier POC
python main.py --target example.com --mode coverage --profile standard \
  --phases RECON,ACTIVE_SCANNING,EXPLOITATION,REPORTING
python main.py --targets a.com,b.com --campaign --max-parallel 3
python main.py --targets-file targets.txt --resume
```
Flags `main.py:326-407`: `--tier{POC,SHALLOW,DEEP}`, `--mode{fast,coverage,benchmark}`→`NEO_SCAN_MODE`, `--profile{standard,lab}`, `--scan-id`, `--human-assist`, `--incremental`, `--schedule N`, `--mobile-app/--source-*` (standalone → `_run_standalone_analysis` `main.py:416`).

**API**: `POST /api/scans/run` (`ui/api/server.py:2841`) → detached thread `_run_scan_process` (`:793`) → `subprocess.Popen([python, main.py, --scan-id job_id, ...])` (`:804`). Server: `uvicorn ui.api.server:app`.

**Docker** (`docker-compose.yml`): `web` (8900), `kali-pentesting` (tools, reached over docker net), `postgres` (pgvector pg16, db `pentesting_db`).

**Env**: `POSTGRES_*`/`DATABASE_URL`; budgets `BUDGET_MAX_RUNTIME_S`(7200,≤0 disables), `BUDGET_MAX_REQUESTS`, `BUDGET_MAX_LLM_COST`, `BUDGET_SOFT_EXIT_FRAC`(0.85); `CONVERGENCE_THRESHOLD`(0.85), `PHASE_MAX_ENTRIES`(3), `PHASE_NO_PROGRESS_LIMIT`(15); `NEO_SCAN_MODE/PROFILE`, `AUTH_*`, `INFRA_AGENTS_ENABLED`, `NEO_HUMAN_ASSIST`, `KILL_SWITCH_FILE`.

---

## PART B — HOW IT WORKS

**Lifecycle**: `run()` → `run_main_loop` → `_run_main_loop_impl` (`central_brain.py:2696`) → `while self.current_phase:` (`:2869`) → `run_phase(phase)` (`:2924`, dispatch `:3497`) → `_flush_partial` (`:2930`) → `_transition_to_next_phase` (`:2966`) → checkpoint. Back in `run_single`: `_post_scan_chain_analysis` (`main.py:137`) then `finally _persist_vulnerabilities()` (`:141`).

**Phases**: `BUSINESS_UNDERSTANDING → RECON → ACTIVE_SCANNING → EXPLOITATION → REPORTING`. Transition = DAG `PhaseScheduler`+`default_dag` (primary); legacy `_evaluate_phase_transition` only in DAG `except`. Completion for scanning/exploitation is convergence-based (≥0.85). Watchdog `security/watchdog.py` + `FINALIZE_LATCH` (`central_brain.py:743`) force one REPORTING then halt.

**Agents & where invoked**:
| agent | file | invoked |
|---|---|---|
| DynamicAgent (ReAct recon) | `core/orchestration/dynamic_agent.py` | `_spawn_and_run_agent` `central_brain.py:9191`; parallel `:9230` |
| AgenticExecutor (native tool-use) | `core/orchestration/agentic_executor.py` | `_run_phase_agentic` `:5620` |
| planner (LLM) | — | `_run_phase_approach_a` `llm.generate_response` `:5972` |
| AdaptivePlanner | — | `should_transition_phase` `:349` |
| Pα / hypothesis | `core/reasoning/hypothesis_engine.py`, `core/hypothesis/*`, `core/intelligence/dynamic_hypothesis.py` | `_run_dynamic_hypothesis_cycle` `:3887`; `hypothesis_engine_v2.generate_from_surface` `:3748` |
| family_scheduler (probe fan-out) | `core/orchestration/family_scheduler.py` | `run_recon_teams` `:3512`, `run_specialist_probes` `:3909/4149`, `run_authenticated_battery` `:2950/3924/4183` |
| UniversalExploitAgent | `agents/exploit_agent.py` | `_run_agent_exploitation` `:4519` (consent gate) |
| BrowserAgent (Playwright) | `core/actuation/browser_agent.py` | probe `run_browser_agent` (`family_scheduler.py:118`), `_browser_xss_validation` `:4484` |
| CriticAgent (FP validator) | `core/verification/critic_agent.py` | `verify_findings` `central_brain.py:4755` |
| infra (k8s/cloud/SCA) | `core/{kubernetes,cloud,sca}/agent.py` | `_analyze_infra_agents` `:4509` → `collect_infra_findings` `:8339` (opt-in) |
| blackboard bus | `core/orchestration/blackboard.py` | reactive `authed_retest` on cred/pivot |
| correlation/attack-graph | — | `_run_attack_chaining` `:4661`, `correlate` `:4682/4717`, `_run_attack_path_engine` `:4737` |

**LLM**: harness `agents/universal_llm_harness.py` (`generate_response/generate_json/generate_with_tools`), proxy `agents/llm_client.py` `LLMClient.get()`, provider `agents/providers/bedrock_provider.py` (Bedrock Mantle OpenAI-compat, `provide_token` auth). Role routing `core/llm/model_roles.py` + deterministic-class refusal `model_routing.py`. ZDR on by default. Cost/token log per call.
Context to agents via `shared_context=self.ctx` + `context_hint` + `_build_agent_context` (`central_brain.py:9143`). Findings flow ctx→`_flush_partial`→`VulnRepo.bulk_insert` (pg). **Agents never write DB directly** — only the pipeline does.

**Note**: `llm.generate()` regression from memory is RESOLVED — every LLM call uses a real method; bare `.generate(` calls are on engine/report objects, not the harness.

---

## PART C — BUGS (prioritized, with fix)

### P0 — correctness / data loss

**P0-1 Probe findings bypass the confirmation+persist gate.**
Specialist probes and Dispatcher/UPE call `ctx.add_vulnerability` directly (`family_scheduler.py:260`), skipping `_stamp_and_add_vuln` where the oracle re-verify gate, ReproductionGate, FindingConfirmationGate + inline persist live (`central_brain_mixins/finding_ingestion.py:95-197`). A probe that self-sets `status=CONFIRMED` reaches the pg `vulnerabilities` table unverified. The "every finding funnels through here" comment (`finding_ingestion.py:95`) is aspirational.
**Fix**: route probe output through `_stamp_and_add_vuln` (pass a brain hook into `family_scheduler._run_one`), OR move the oracle/confirmation gate *into* `shared_context.add_vulnerability` so all paths share it. Prefer the latter (single choke).

**P0-2 SPA routes never become injection surfaces (chaining break).**
`crawler._harvest_spa_routes` writes `ctx.spa_routes` (`core/browser/crawler.py:437`) but `SurfaceClassifier.classify` reads only `captured_requests`+`endpoints` (`core/recon/surface_classifier.py:98,111`). JS-bundle-mined routes get ONLY DOM-XSS + route-disclosure — no SQLi/SSTI/SSRF/IDOR battery.
**Fix**: in `surface_classifier.classify`, fold `ctx.spa_routes` (with mined params) into the endpoint set before family routing; or merge `spa_routes`→`ctx.endpoints` at end of crawl.

**P0-3 Post-scan chain rescore not persisted to pg.**
Last pg write is `_flush_partial("after REPORTING")`. Then `_post_scan_chain_analysis` rescores severities in place (`main.py:137`), and `finally _persist_vulnerabilities()` (`persistence.py:327`) writes the **knowledge store**, NOT `VulnRepo`/pg. Chain-upgraded severities never reach the table the UI reads.
**Fix**: after `_post_scan_chain_analysis`, add a final `VulnRepo.bulk_insert`/update of the rescored vulns (or make `_persist_vulnerabilities` also upsert pg). Clarify the two divergent sinks (`_flush_partial`→pg vs `_persist_vulnerabilities`→knowledge store).

**P0-4 Stop-signal filename mismatch — UI "stop" is ineffective for targets with a colon.**
Brain `_stop_file` slug does NOT strip `:` (`central_brain.py:887`); server stop route + pre-run cleanup DO (`server.py:2888,2951`). For `host:8080`-style targets the two compute different paths → brain never sees the stop file; scan runs until watchdog.
**Fix**: extract one shared `slug_for_target()` helper; use it in both brain and server.

### P1 — resilience / coverage

**P1-1 Legacy anti-loop transition is dead on the happy path.**
DAG scheduler `return`s at `central_brain.py:848/853` before `_evaluate_phase_transition` (`:858`); its soft-deadline hop + `_no_progress_phases` force-advance `_NEXT` map fire only in the DAG `except`. Normal-path loop safety = DAG caps + FINALIZE_LATCH only.
**Fix**: fold no-progress force-advance into the DAG path (or invoke `_evaluate_phase_transition` as an always-on guard before the DAG `return`). Prevents phase re-entry stalls the memory notes cost ~2h.

**P1-2 LLM confirmation sweep sees only custom_probe.**
`_llm_probe_finding_sweep` reads `ctx.probe_observations` (`persistence.py:230`), written ONLY by `custom_probe.py:233`. The other ~40 probes are excluded from LLM confirm/persist.
**Fix**: have probes populate `probe_observations` (via the same `_run_one` hook as P0-1), or point the sweep at unconfirmed `ctx.vulnerabilities`.

**P1-3 Two arg sanitizers drift; unlisted tools skip sanitization; listed tools strip legit flags.**
`tool_router.ToolRouter` vs `agentic_executor._sanitize_tool_args` (`:965`). Unlisted tools (subfinder/httpx/whatweb/sslscan/arjun/feroxbuster/dirsearch) return raw args (`:976`); listed tools strip legit unlisted flags — e.g. sqlmap `-D/-T/--dump-all`, nuclei `-eid` (`:990`), weakening exploit depth.
**Fix**: unify on `tool_router` (delete/redirect the executor's copy); expand allowlists for the depth flags; add the missing tools.

**P1-4 Field-keyed oracles starve → heuristic findings stand unverified.**
`_oracle_mass_assignment`(needs `privilege_changed`), `_oracle_csrf`(`state_changed_without_token`), `_oracle_business_logic`(`workflow_step_skipped`) (`oracle.py:356,370,411`) return inconclusive unless the probe sets that evidence key — then the probe's own heuristic finding stands.
**Fix**: set the required evidence keys in those probes (mass_assign/csrf/business_logic) so the oracle can actually adjudicate.

**P1-5 Critic can be skipped by early giveup.**
`CriticAgent.verify_findings` runs at `central_brain.py:4755` (post-exploitation/REPORTING). Early-giveup (`:329-338`) / forced REPORTING can bypass it → ACTIVE_SCANNING probe FPs never adjudicated.
**Fix**: run critic inside the REPORTING finalize path unconditionally (incl. FINALIZE_LATCH), before report generation.

### P2 — hygiene / debt

- **P2-1 Missing families**: `CLOUD`, `SSL_TLS` have no battery probe (`TestFamily` `test_plan.py:24`); covered by recon ingest only. `classify_family_jev` routes to them → novel-gap log, never attacked (`family_scheduler.py:771`). Add probes or explicitly hand off to recon modules.
- **P2-2 csrf probe detect-only** (`confirmed:False` `csrf_probe.py:126,151`) — add a state-change oracle confirm (pairs with P1-4).
- **P2-3 Hypothesis-engine fragmentation** — 5 modules, clashing `HypothesisEngine` names (`core/reasoning/`, `core/hypothesis/` ×2, `core/coverage/`, `core/intelligence/`). Consolidate or alias to kill import-mistake risk.
- **P2-4 "Pα" engines accept `llm_client` but never call it** (`reasoning_engine.py:18`, reasoning/coverage `HypothesisEngine`s) — generation is pure catalog/keyword. Either wire the LLM (see Part D zero-day) or drop the param to stop implying LLM behavior.
- **P2-5 Dead frameworks** — `agents/base.py BaseAgent` abstract contract unused (live agents are standalone); `core/orchestration/specialist_agents.py` SpecialistTeam/EvidenceBus have no `core/` importers; `dynamic_agent.py:279-328` ReAct path bypassed by `CapabilityWorker`. Decide keep-and-wire or delete.
- **P2-6 Migrations applied in list order, not id order** — `_MIGRATIONS` = 0001,0002,0003,0006,0005,0004 (`pg_store.py:1087`). Harmless now (all `IF NOT EXISTS`); reorder by id to avoid a future dependency trap.
- **P2-7 API_PORT inconsistency** — `server.py __main__`=8903, Dockerfile/compose=8900, `settings.py`=8000. Single-source it (settings).

---

## PART D — CAPABILITY GAPS vs THE BRIEF

Brief goal: *find every vuln (incl zero-days) then FIX them.*

**D-1 No remediation/auto-fix stage.** Pipeline ends at REPORTING; the brief's "then fix them" is unimplemented. Add a guarded RemediationAgent: per-CONFIRMED finding → generate patch/config diff + regression test, output as reviewable artifact or PR (never auto-apply to prod; consent-gated like exploit). Chain: `CriticAgent` (confirmed) → RemediationAgent → PoC/patch bundle in REPORTING.

**D-2 Zero-day / novel discovery is weak.** "Pα/hypothesis" engines are rule/catalog-based, not LLM-driven (P2-4). For genuine novel-vuln hunting, wire the LLM hypothesis loop (`dynamic_hypothesis`) as the primary generator over surface+evidence, feeding the agentic executor for exploration, with the oracle/critic gate (P0-1) preventing FP flooding.

---

## PART E — SUGGESTED ORDER

1. P0-1 (single confirmation choke) — unblocks P1-2, P1-4, P2-2 which all depend on it.
2. P0-2 (SPA surface) — biggest coverage win.
3. P0-3, P0-4 — data-loss + operability.
4. P1-1 (loop safety), P1-3 (tool depth), P1-5 (critic).
5. D-1 (remediation) — closes the brief.
6. P2 cleanup.

## PART F — VERIFY EACH FIX
- P0-1: probe emits a self-CONFIRMED FP → assert it is downgraded/quarantined and absent from pg unless oracle agrees.
- P0-2: seed a target whose only injectable params live in a JS bundle route → assert SQLi/SSTI probe fires on it.
- P0-3: force a chain severity upgrade → assert pg row reflects upgraded severity.
- P0-4: start scan on `host:8080`, hit UI stop → assert brain halts before watchdog.
- Run smallest relevant test in `tests/` per area; do not weaken tests to pass.
