# AntiGravity — Feature & Architecture Overview

**Audience:** new team members, stakeholders, partners evaluating capabilities.
**Read time:** ~25 minutes.
**Presentation length:** ~50 minutes with demo.
**Revision:** 2026-09-06 — includes zero-day hunting stack (post-OpenAI/HF incident retrofit).

---

## Slide 1 — What is AntiGravity?

**AntiGravity is an autonomous, LLM-driven security testing platform that behaves like a group of senior human pentesters.**

Given a target (`example.com` or `10.0.0.0/16`) and an authorization scope, it:

1. Discovers the attack surface (subdomains tiered LIVE/DEAD/EXTERNAL, endpoints, technologies, APIs, JS bundles, exposed `.git` sources)
2. Reasons about what to test next using a large-language-model planner with an **adversarial critic loop**
3. Runs real security tools (nmap, nuclei, sqlmap, dalfox, ffuf, semgrep, CodeQL, custom probes) inside a hardened Kali container
4. **Coordinates parallel sub-agents through a Postgres-backed scratchpad** (message board pattern — same architecture OpenAI's agent used against Hugging Face in July 2026)
5. Confirms every finding with a second-pass validator + DNS/service verification to cut false positives
6. **Hunts for zero-days via format-parser probes** (HDF5 external raw storage, fsspec+Jinja SSTI, YAML/pickle deserialization, Parquet metadata injection)
7. Produces an executive report (HTML + PDF + SARIF + JSON) with reproducible PoCs

It replaces roughly **8 tool consoles** and **3 spreadsheets** that a senior pentester used to juggle by hand — and now attempts the exploit *chains* those pentesters would have improvised.

**One-liner:** *A group of senior pentesters that runs the engagement for you, reasons like they would, hunts zero-days in file formats, and writes the report.*

---

## Slide 2 — Why this exists

Traditional automated scanners have two failure modes:

- **DAST scanners** (Burp, ZAP, Nessus) fire every check regardless of context → noisy, wasteful, miss chain-based bugs.
- **Manual pentesting** is thorough but doesn't scale — one engineer can't test the ~4,300 endpoints a mid-size SaaS ships in a quarter.

**And a third gap the OpenAI/HF incident exposed:** neither DAST nor manual testing systematically hunts vulnerabilities in *file-format parsers* — the HDF5, fsspec, and Jinja bugs that took Hugging Face down in July 2026.

AntiGravity closes all three gaps by:

- Reasoning about the target before firing payloads (LLM planner)
- Running an **adversarial critic**: attacker LLM proposes → critic LLM revises → both scored
- **Sharing findings across parallel agents** through a scratchpad, so agent-A's SQLi discovery lets agent-B start credential cracking immediately
- Composing findings into **attack chains** (SQLi → data exfil → credential crack → login → IDOR → deeper access)
- **Publishing format-parser probes** to every uploaded file, converter, or artifact endpoint
- Retesting every finding + DNS-verifying takeover claims to catch false positives
- Rendering the report in the format the customer's SIEM / GitHub Advanced Security / ticketing system already speaks (SARIF, GitLab DAST JSON, PDF)

---

## Slide 3 — High-level architecture (updated)

```
                          Operator (browser)
                                 │
                       React 19 SPA (Vite)
                                 │  X-API-Key
                       ┌─────────▼─────────┐
                       │  FastAPI backend  │  Postgres 15 + pgvector
                       │  /api/*           ├──── scans, findings,
                       │  /ws/scan/{id}    │     agent_scratchpad,
                       │  /api/metrics     │     agent_reasoning (+args
                       └─────────┬─────────┘     +result +status +ms),
                                 │               RAG documents, audit chain
                                 ▼
                       ┌──────────────────────────────┐
                       │  Scan process                │
                       │  CentralBrain                │
                       │  + LLM harness               │
                       │  + AdversarialCritic         │
                       │  + AgenticExecutor           │
                       │  + Parallel sub-agents ⇄ Scratchpad
                       │  + Egress firewall (httpx)  ─┼──✗── blocked host
                       └──────┬───────┬───────────────┘
                              │       │  docker exec
                    ┌─────────┘       ▼
                    ▼          ┌──────────────────┐
              DeepSeek /       │ kali-pentesting  │
              Groq /           │ container        │
              Ollama           │ nmap, nuclei,    │
              (LLM providers)  │ sqlmap, dalfox,  │
                               │ ffuf, playwright,│
                               │ semgrep, codeql  │
                               └──────────────────┘
```

**New properties this cycle:**

- **Fail-closed authorization sealing** — `TargetScopeValidator.validate()` refuses to proceed with an empty scope list.
- **Egress firewall** — `install_httpx_guard()` monkey-patches every httpx client at import time; any request outside the authorized scope raises before the socket opens.
- **Docker network policy** — `render_docker_network_policy()` emits iptables snippets that lock the scan container to allowlisted destinations.
- **Postgres-backed scratchpad** — every sub-agent posts observations to `agent_scratchpad`; other agents tail their inbox each turn.
- **Enriched reasoning rows** — every tool call is stored with `tool_args`, `tool_result_preview` (masked), `tool_status`, `duration_ms`. Operator can click any `#N · toolname` row in the UI and see the exact payload + response.

---

## Slide 4 — Core features (updated map)

Organised by scan phase. Bold rows are new this cycle.

| Phase | Feature | What it does |
|---|---|---|
| **Recon** | Subdomain enumeration + **tiering** | `subfinder` + `assetfinder` + `amass` + crt.sh + Wayback + `dnsx`, then classified LIVE / DEAD / EXTERNAL. Cap `MAX_SUBDOMAIN_SCANS=6` per scan; DEAD tier gets 3-round quick probe; EXTERNAL (GitHub Pages, Leanpub, third-party ecom) skipped. |
| Recon | Port + service discovery | `nmap -sV` XML output, Masscan for large ranges |
| Recon | Technology fingerprinting | `httpx`, `whatweb`, HTTP-header + banner heuristics |
| Recon | **JS bundle analyzer** | Downloads bundled JS, extracts endpoints + hardcoded secrets + source-map references, feeds attack-surface graph |
| Recon | **Exposed source extractor** | Detects `.git/`, `.svn/`, `.env`, source-map exposure; rehydrates JS source via sourcemaps |
| Recon | API-schema import | OpenAPI/Swagger/GraphQL introspection → seeds endpoint inventory |
| Recon | OSINT correlation | Shodan + Censys + VirusTotal + AbuseIPDB + NVD + GitHub secret scan |
| **Discovery** | Attack-surface graph | Endpoints, params, identities, sessions unified into one graph the planner reads |
| Discovery | Parameter mining | `arjun`, plus route normalizer for SPA hash-fragment routing |
| Discovery | Auth-flow detection | Form / JWT / bearer / cookie auth session capture |
| Discovery | **DOM sink monitor** | Playwright-driven crawl instruments `innerHTML`, `document.write`, `eval`, `Function()` sinks and marks tainted-source flows |
| **Exploitation** | LLM planner | Reasons about what to try next given current attack-surface state |
| Exploitation | **Adversarial critic loop** | Two-LLM pattern: attacker proposes probe → critic scores + revises → both logged |
| Exploitation | **Framework quirks corpus** | Retrieval-augmented planner primed with stack-specific tricks: express, fastify, angular, nextjs, django, rails, graphql, kubernetes, artifactory, huggingface |
| Exploitation | 85+ vulnerability-class executors | SQLi, XSS, SSRF, XXE, CSRF, IDOR, SSTI, JWT abuse, GraphQL/WS, cloud-cred enumerators, HTTP smuggling, cache poisoning, prototype pollution, deserialization, CSP bypass, DOM XSS, clickjacking, HTTP request smuggling, WebSocket hijack |
| Exploitation | **Cross-role replay** | Every admin request captured is re-fired under low-privilege identities; success = privilege escalation |
| Exploitation | **Semantic API fuzzer + coverage tracker** | Coverage-guided fuzzer (AFL-analogous for HTTP): scores 0..1 by new status codes, response lengths, headers, body fingerprints seen |
| Exploitation | **Custom Python probe sandbox** | LLM writes probe code; source stored in `tool_args` and displayed inline in operator UI |
| Exploitation | **Format-parser zero-day probes** | HDF5 external raw storage disclosure, HDF5 heap-overread, fsspec ReferenceFileSystem + Jinja SSTI/RCE, YAML unsafe_load RCE, pickle RCE, Parquet metadata injection |
| Exploitation | Attack chain composition | LLM stitches individual findings into full exploitation paths |
| Exploitation | Escalation gate | Fail-closed approval queue for high-risk actions (webhook / queue / TTY) |
| **Post-exploit** | Credential extraction | Pulls tokens, sessions, keys from confirmed exploits |
| Post-exploit | Hash cracking | `hashcat` + Python fallback; small wordlist bundled, full wordlist opt-in |
| Post-exploit | Lateral movement planner | Composes pivot paths from harvested credentials + discovered internal endpoints |
| Post-exploit | **Dump extractor** | Given confirmed SQLi/IDOR, extracts sample data to prove business impact |
| **Validation** | Retest engine | Re-fires every finding at scan end to confirm it still reproduces |
| Validation | LLM validator | Second-pass verdict on each finding (false-positive filter) |
| Validation | **Takeover verifier** | Provider-fingerprint match + **DNS CNAME lookup** required (fixes Heroku "Application Error" false positive) |
| Validation | ML FP filter | RandomForest gate; only trains when ≥200 labelled rows exist |
| Validation | Fingerprint dedup | Cross-scan dedup with `RECURRING`/`RESOLVED` state machine, scoped by target |
| **SAST** | **Semgrep + CodeQL pipeline** | Extract source from exposed `.git`/sourcemaps → semgrep security-audit → CodeQL security-and-quality → LLM review each finding for exploit design |
| **Reporting** | HTML report | Self-contained, interactive (DataTables + Chart.js) with noscript fallback |
| Reporting | PDF report | WeasyPrint → xhtml2pdf → pdfkit → fpdf2 fallback chain |
| Reporting | SARIF 2.1.0 export | GitHub Advanced Security compatible |
| Reporting | GitLab DAST JSON | Native GitLab pipeline integration |
| Reporting | Executive summary | LLM-generated business-impact narrative |
| Reporting | Reproducible PoCs | Per-finding zip with `shlex`-quoted curl commands + Playwright scripts + README |
| Reporting | Attack chain narrative | Prose description of each composed chain with business impact |
| **Ops** | Live WebSocket feed | Real-time scan progress, log tail, per-agent thoughts |
| Ops | **Enriched agent thoughts UI** | Every `#N · toolname` row expandable → shows args JSON + first 4 KB result preview + colored status (2xx/3xx/4xx/5xx/ERR/OK) + duration |
| Ops | Scan chat | Per-scan LLM Q&A over the scan's own reasoning + fact index |
| Ops | Scan diff | Two-scan comparison for regression testing |
| Ops | Scheduled scans | Recurring per-target cadence |
| Ops | Campaign mode | Parallel multi-target scans with shared reporting |
| Ops | Kill-all | Emergency stop for every in-flight scan |
| Ops | Idempotent resume | Crash recovery via per-phase encrypted checkpoint |
| **Benchmarking** | **CyberGym runner** | Clones `sunblaze-ucb/CyberGym`, spins tasks via docker compose, grades agent findings → capability floor tracked over time |

---

## Slide 5 — How the scan pipeline works (updated)

```
1. Operator hits POST /api/scans/run { target, tier, phases, credentials }
   │
   ├─ Auth gate: X-API-Key middleware validates (with query-param allowlist
   │  for download-style GETs: /logs-download, /report, /sarif, /gitlab-dast,
   │  /api/evidence/*)
   ├─ Input validation: Pydantic (URL scheme, tier enum, phase enum)
   ├─ Rate limit: slowapi + built-in per-route
   ├─ Credentials → temp file (mode 0600), NEVER argv
   │
2. subprocess.Popen spawns the scan process with TRACEPARENT env
   │
   ├─ install_httpx_guard() runs at import → egress firewall live
   ├─ TargetScopeValidator.validate() refuses empty scope (fail-closed seal)
   │
3. CentralBrain.run_main_loop starts
   │
   ├─ Scratchpad(scan_id) initialised — Postgres message board
   ├─ ScopeManager + TargetScopeValidator + LegalValidator wired
   ├─ Unified ScopeAuthority is the single consult point
   │
4. RECON phase:
   │
   ├─ _probe_live_subdomains → tiers into LIVE / DEAD / EXTERNAL
   ├─ _scan_subdomain_endpoints capped at MAX_SUBDOMAIN_SCANS (6)
   ├─ JS bundle analyzer → surface graph
   ├─ Exposed source extractor → semgrep + CodeQL if source recovered
   ├─ Framework corpus lookup → primes next phase's planner
   │
5. DISCOVERY phase:
   │
   ├─ DOM sink monitor via Playwright
   ├─ Attack-surface graph consolidation
   │
6. EXPLOIT phase (each planner turn):
   │
   ├─ AgenticExecutor asks LLM: "given ctx, what should we try?"
   │  │
   │  ├─ AdversarialCritic pairs attacker + critic LLMs
   │  ├─ LLM circuit breaker per (provider, model, phase)
   │  ├─ Prompt-safety fences on every untrusted section
   │  ├─ 429/503 retry with Retry-After
   │  │
   │  └─ Returns tool calls: [nmap on subdomain X, nuclei on URL Y, ...]
   │
   ├─ Parallel sub-agents dispatched — cross-role replay, semantic fuzz,
   │  format-parser probes — coordinate through Scratchpad
   │
   ├─ For each tool call:
   │  │
   │  ├─ ScopeAuthority.is_authorized(target) → fail closed if not
   │  ├─ egress firewall asserts host is in-scope
   │  ├─ ToolRouter builds argv (shlex.quote on every user-derived value)
   │  ├─ Rate-limited per provider
   │  ├─ subprocess.run with per-tool timeout
   │  ├─ Timed via monotonic clock → duration_ms
   │  ├─ Result parsed → findings ingested into SharedContext
   │  ├─ ONE enriched agent_reasoning row written:
   │  │    thought, tool_planned, tool_args (redacted),
   │  │    tool_result_preview (masked, 4KB), tool_status, duration_ms
   │  │
   │  └─ prompt-safety fenced when tool stdout flows into the next LLM call
   │
   ├─ Coverage tracker scores every response 0..1 (novelty)
   ├─ save_checkpoint(scan_id, ctx, phase, phase_index)
   │
7. VALIDATE phase:
   │
   ├─ RetestEngine → LLMValidator → FP filter → DedupStore
   ├─ TakeoverVerifier: fingerprint + DNS CNAME provider-suffix match
   │
8. REPORT phase:
   │
   ├─ HTML + PDF + SARIF + GitLab DAST + JSON + MD
   ├─ Repro bundles per finding
   ├─ Executive summary (Jinja2 SandboxedEnvironment)
   ├─ Attack chain narrative
   │
9. Notifier fan-out (Slack + PagerDuty + SIEM + webhook)
   │
10. Scratchpad.clear_scan(scan_id)
11. clear_checkpoint(scan_id) on success
```

**Total execution time**: 15 min (POC tier) → 60 min (DEEP tier on a mid-size app with subdomain tiering + `MAX_SUBDOMAIN_SCANS=6`). Down from 90 min pre-tiering (was blowing past budget on 18 subdomains × 60 rounds).

---

## Slide 6 — The LLM reasoning loop + adversarial critic

The differentiator vs traditional DAST is that AntiGravity **reasons about the target** before firing payloads. And this cycle: it **argues with itself**.

**Per LLM decision:**

```
Attacker LLM
  System: "You are a security orchestrator..."
  User (mixed):
    Instructions: "Given the state below, propose the next 3 tool calls."
    Trusted state: target, scope, phase, findings-so-far (redacted)
    Framework corpus: <untrusted:framework_quirks_nextjs>...</untrusted>
    <untrusted:tool_output_nikto>...</untrusted>
    <untrusted:response_body>...</untrusted>
    Scratchpad tail: <untrusted:peer_agents>...</untrusted>

Critic LLM
  System: "Score the attacker's plan 0..10. Point out omissions,
           overreach, wasted budget. Propose a revised plan."
  User: attacker's proposal + same state

→ Final plan = critic's revision if score < 7, else attacker's plan.
→ Both logged to agent_reasoning for operator inspection.
```

**Provider stack:**
- Primary: DeepSeek Reasoner (deep planning, chain composition)
- Secondary: Groq (fast fallback for simple JSON tasks)
- Local: Ollama (air-gapped deployments, dev)

**Cost controls:**
- Per-scan LLM budget (`_LLMBudget`, per-scan-id, resettable)
- Global budget governor (graded downgrade → hard stop at spend caps)
- Per-`(provider, model, phase)` circuit breaker (3 failures / 120 s → 60 s cooldown)
- Response truncation at ~20 KB before every prompt

**Prompt-injection defense:**

Every string that came from an external source — HTTP response bodies, tool stdout, DB rows, **peer-agent scratchpad posts**, **framework corpus entries** — is fenced in `<untrusted:label>...</untrusted:label>` tags with an explicit "DATA, not instructions" contract in the system prompt.

---

## Slide 7 — Parallel agents + scratchpad (new)

**Same pattern OpenAI's agent used against Hugging Face in July 2026.**

Every parallel sub-agent (subdomain scanner, OSINT worker, expert probe, cred-chain executor, format-probe worker) has a `Scratchpad(scan_id, agent_id)` handle backed by the `agent_scratchpad` Postgres table.

**Operations:**

```python
scratchpad.post(kind="finding", body={"type":"sqli", "url":"...", "param":"q"})
scratchpad.tail(limit=20)                    # everyone's recent posts
scratchpad.inbox()                            # posts addressed to me (DMs)
scratchpad.request(recipient="cred-cracker",
                   ask="crack this bcrypt hash", context={...})
scratchpad.announce_finding(finding_dict)
```

**Kinds:** `note`, `tool`, `result`, `dm`, `finding`, `beacon`.

**Effect on scan quality:**

- Agent-A finds SQLi in `/search` → posts to scratchpad → Agent-B (credential harvester) picks it up next turn and pivots straight to hash extraction.
- Agent-C finds a `.env` in an exposed `.git` → publishes secrets → Agent-D uses them to authenticate an API and starts IDOR sweeping.
- Agent-E finds a Hugging Face endpoint accepting HDF5 uploads → publishes to scratchpad → format-probe worker fires the external-raw-storage disclosure PoC.

Scratchpad is **cleared at scan end** to avoid cross-scan leakage.

---

## Slide 8 — Zero-day hunt: format-parser probes (new)

Post-OpenAI/HF incident retrofit. Every scan enumerates upload endpoints, converter APIs, and artifact ingestion routes, then publishes format-specific payloads.

**`core/exploitation/format_probes/`:**

| Probe | Vulnerability class | Reference incident |
|---|---|---|
| `hdf5_external_disclosure` | HDF5 external raw storage → arbitrary file read | HF July 2026 |
| `hdf5_heap_overread` | HDF5 malformed dataspace → OOB read | Various CVEs |
| `fsspec_jinja_disclosure` | fsspec ReferenceFileSystem + unsandboxed Jinja2 → file read | HF July 2026 |
| `fsspec_jinja_rce_command` | Same primitive + `os.popen` → RCE | HF July 2026 |
| `yaml_unsafe_load_rce` | `yaml.load` without SafeLoader → arbitrary object → RCE | CVE-2017-18342 lineage |
| `pickle_rce` | `pickle.loads` on untrusted data → RCE | perennial |
| `parquet_metadata_injection` | Malformed Parquet metadata → parser DoS/OOB | Emerging class |

Each probe registers via a `@register` decorator; the planner enumerates the registry and picks probes matching the discovered endpoint's content-type.

**Every probe is scope-authorized before firing** and every result flows through the same `agent_reasoning` enrichment (args + preview + status + duration).

---

## Slide 9 — Attack chain intelligence (unchanged mechanism, better inputs)

The chain intelligence module (`core/reporting/chain_intelligence.py`) asks the LLM:

> *"Given these findings, compose the DISTINCT attack chains — sequences where one finding ENABLED the next. Only include chains where later steps DEPEND on earlier ones."*

**Example output (real from OWASP Juice Shop dry run):**

```
Chain: "Exposed .git → source review → SSTI in profile → RCE"
Severity: CRITICAL
Business impact: Full container compromise, pivot to internal network

Steps:
1. Exposed .git/ directory at /assets/.git
   Recovered app source (Node/Express + EJS).
2. Semgrep flagged unescaped user input in profile.ejs
3. LLM planner constructed SSTI probe:
   POST /profile { username: "<%- global.process.mainModule.require('child_process').execSync('id') %>" }
4. Response contained `uid=0(root)` — RCE confirmed
5. Egress firewall LOG line shows RCE payload attempted callback to
   authorized listener — proof of full command execution.

Narrative: Attacker with unauthenticated access recovered application source
from a misconfigured deployment, identified an EJS injection sink through
static analysis, and achieved command execution in under 4 minutes.
```

---

## Slide 10 — Safety architecture (updated)

**Every dangerous action is behind a gate.**

| Gate | What it protects | Enforcement |
|---|---|---|
| API auth (`X-API-Key`) | Every HTTP + WS endpoint | Refused at boot in prod without a key |
| **Query-param auth allowlist** | Browser downloads (logs, PDF, SARIF, GitLab DAST, evidence) | `_accepts_query_auth()` limits to specific GET paths |
| CORS allowlist | Cross-origin scan launches | `*` refused in prod |
| Scope authority | Out-of-scope scans | Every executor consults it before firing |
| **Fail-closed scope seal** | Empty-scope run | `TargetScopeValidator.validate()` raises on empty |
| **Egress firewall (httpx)** | Data exfil, C2, unauthorized fetches | `install_httpx_guard()` monkey-patches every client at import |
| **Docker network policy** | Container-level egress | `render_docker_network_policy()` iptables snippet |
| Escalation gate | DEEP-tier exploits | Fail-closed webhook + queue + optional TTY |
| Consent manager | Auto-approve exploits | `AUTO_APPROVE_EXPLOITS=1` ignored in prod (WARN logged) |
| Legal validator | SOW / ROE expiry | Blocks scans when contract expired |
| Rate limits | Abuse endpoints | slowapi + built-in per-route rolling window |
| TLS verification | OSINT feed MITM | On by default |
| Container isolation | Tool subprocess blast radius | Every offensive tool runs in Kali container, not on the API host |
| Path safety | Arbitrary-file read | `Path.resolve().relative_to(root)` on every user-derived path |
| PII redaction | Log-line leaks | Filter runs `mask_sensitive_data` on every record before stdout |
| **Redacted tool_args** | Reasoning-row secret leak | `_redact_args()` masks `password`, `token`, `api_key`, `authorization`, `cookie`, `hf_token`, `openai_api_key`, etc. before persist |
| **Masked result_preview** | Reasoning-row secret leak | `_preview_result()` runs `mask_sensitive_data` before persist |
| Credential encryption | DB dump exposure | `auth_bypasses.password/token` column-encrypted with Fernet |
| Prompt-safety fence | LLM jailbreaks via captured responses **or peer agents** | Every LLM boundary uses `guarded_prompt()` |

---

## Slide 11 — Observability (updated)

`GET /api/health` — deep readiness probe:

```json
{
  "status": "ok",
  "checks": {
    "postgres": "ok",
    "kali_container": "state:running",
    "llm_harness": "initialised",
    "egress_firewall": "installed",
    "scratchpad": "ok",
    "metrics": "prometheus",
    "tracing": "otel"
  }
}
```

`GET /api/metrics` — Prometheus scrape now includes:

- All previous metrics, plus:
- `antigravity_scratchpad_posts_total{kind}`
- `antigravity_critic_revisions_total{outcome}`
- `antigravity_egress_blocked_total{host}`
- `antigravity_format_probe_hits_total{probe}`
- `antigravity_subdomain_tier_total{tier}` — LIVE/DEAD/EXTERNAL distribution
- `antigravity_coverage_novelty_bucket` — histogram of novelty scores

**Enriched agent_reasoning stream** — every row now carries args + preview + status + duration → operator can audit every LLM decision and every tool invocation without leaving the UI.

---

## Slide 12 — Operator UX (updated)

React 19 SPA (Vite) with 11 pages — the **Live Agents panel** is the star this cycle.

**LiveAgentsPanel enhancements:**

- Every parallel sub-agent renders as a card with status badge (RUN/WAIT/DONE/FAIL), current tool, current step, findings count, cost.
- "thoughts" toggle opens a scrolling feed of every LLM step.
- Each thought row now renders as `<ThoughtRow>`:
  - Header: `#N · tool_name`  colored status  duration
  - Status color: green (2xx or OK), yellow (3xx), red (4xx/5xx/ERR), grey (unknown)
  - Duration: `1.2s` or `340ms`
  - Click → expandable panel showing:
    - `ARGS` — JSON-pretty-printed tool arguments (secrets redacted server-side)
    - `RESULT PREVIEW` — first 4 KB of tool response with `(truncated)` marker when capped
- For `run_custom_python` rows, `ARGS` shows the actual Python source the LLM wrote — closes the biggest audit gap.

**Other UX properties unchanged:**

- Every polling loop uses `createPoller()` (AbortController + generation counter).
- Every fetch dispatches `ag:unauthorized` on 401.
- Download URLs carry `?api_key=` (browsers can't set headers on top-level navigations).
- WS handshake uses `Sec-WebSocket-Protocol: api-key,<key>` subprotocol.

---

## Slide 13 — Data model (updated)

40+ tables. New/changed:

| Table | Purpose |
|---|---|
| `scans` | Scan lifecycle |
| `vulnerabilities` | Every confirmed finding (CASCADE from `scans`) |
| `findings_v2` | Canonical dataclass persistence |
| `findings_history` | Cross-scan dedup with `RECURRING`/`RESOLVED` |
| `auth_bypasses` | Credentials / tokens captured (column-encrypted) |
| `attack_chains` | LLM-composed exploitation paths |
| `scan_artifacts` | PoC scripts, screenshots, PDF/HTML/SARIF blobs |
| **`agent_reasoning` (extended)** | Live chain-of-thought + `tool_args JSONB`, `tool_result_preview TEXT`, `tool_status INT`, `duration_ms INT`. Additive `ALTER TABLE … IF NOT EXISTS` migration for existing installs. |
| **`agent_scratchpad` (new)** | Per-scan message board. Rows: `id, scan_id, agent_id, kind, body JSONB, recipient, created_at`. `kind ∈ {note, tool, result, dm, finding, beacon}`. Truncated at scan end. |
| `live_agents` | Per-agent state for the parallel-agent panel |
| `scan_llm_memory` | LLM phase summaries (feeds scan chatbot) |
| `rag_documents` | pgvector 1536-dim HNSW index |
| `audit_log` | Hash-chained event log |
| `experiences` | Per-tool per-target success/failure history |
| `strategies` | Learned exploitation strategies |
| `learned_skills` | Reusable exploitation patterns |
| `scan_schedules` | Recurring scan cadences |
| `campaigns` | Parallel multi-target runs |

---

## Slide 14 — RAG + framework corpus (updated)

**RAG knowledge base** — unchanged mechanism:
- Local files, uploaded files, URLs (scheme allowlist, blocks 169.254.169.254 + private ranges), raw text, web-search
- pgvector HNSW cosine similarity, top-k configurable
- Semantic-quality guard refuses fallback hash-bag vectors

**Framework quirks corpus (new)** — `core/intelligence/framework_corpus/`:

10 stacks pre-loaded with battle-tested tricks:

- `express` — trust-proxy quirks, prototype pollution via `qs`, method-override
- `fastify` — JSON schema bypass, hooks execution order
- `angular` — sanitizer bypass, template SSTI via ExpressionChangedAfterItHasBeenCheckedError
- `nextjs` — RSC injection, middleware CVE-2025-29927, `unstable_cache` poisoning
- `django` — SSTI in `{% include %}`, `TEMPLATE_DEBUG` leaks, pickle in cache backend
- `rails` — cookie serialization pickle, `Marshal.load`, mass assignment
- `graphql` — introspection abuse, batching DoS, alias-based rate-limit bypass
- `kubernetes` — TokenRequest privilege escalation, kubelet 10250 exposure, ServiceAccount JWT reuse
- `artifactory` — CVE-2026-66384 RubyGems JRuby deserialization, generic repo path traversal
- `huggingface` — HDF5 external storage, fsspec+Jinja RCE, Trainer API pickle load

`lookup(stack)` and `lookup_all()` return priority-sorted entries. Retrieved entries fence into the planner as `<untrusted:framework_quirks_...>` so the LLM knows they came from external corpus and applies them contextually.

---

## Slide 15 — SAST pipeline (new)

`core/analysis/source_extractor.py` + `core/analysis/codeql_runner.py`:

**Trigger conditions:**
1. Exposed `.git/` detected → `extract_exposed_git()` recovers repo
2. Source-map exposure detected → `rehydrate_sourcemap()` recovers original TS/JS
3. Operator provides source directly via UI upload

**Pipeline:**

```
source tree
   │
   ├─► semgrep run_semgrep(root)
   │      ├─ security-audit ruleset
   │      ├─ owasp-top-ten ruleset
   │      └─ language-specific rulesets
   │
   ├─► run_codeql(root)
   │      ├─ build DB (autobuild)
   │      ├─ security-and-quality suite
   │      └─ SARIF → findings
   │
   └─► For each SAST finding:
          llm_review_finding(finding, tree)
          → planner reads source snippet + rule
          → proposes concrete exploit for the running app
          → probe published to scratchpad
          → executor fires it
          → confirmed? materialize as vulnerability finding
```

**All egress in this pipeline is gated** — `install_httpx_guard()` catches any CodeQL / semgrep telemetry callback and blocks it.

---

## Slide 16 — CyberGym benchmark (new)

`tests/benchmarks/cybergym_runner.py`:

Clones `github.com/sunblaze-ucb/CyberGym`, spins up each task via `docker compose`, runs the AntiGravity agent against it, grades findings.

**Usage:**

```bash
python -m tests.benchmarks.cybergym_runner --tasks all --tier DEEP
python -m tests.benchmarks.cybergym_runner --task heap_overflow_01 --tier POC
```

**Report:**

- Pass / fail per task
- Time to first finding
- LLM cost per task
- False-positive rate on control tasks

**Purpose:** capability floor. Every merge to `main` runs a smoke subset. Full benchmark runs weekly and is tracked over time so regressions get caught before customer engagements.

---

## Slide 17 — What ships out of the box

Everything below runs on `pip install -r requirements.txt` + `docker-compose up`:

**Backend:**
- Python 3.13 (patch-pinned in Docker)
- PostgreSQL 15 + pgvector
- FastAPI + Uvicorn
- Kali rolling in a separate container (unprivileged uid 10001)
- **httpx egress firewall installed at import**

**Frontend:**
- React 19 + Vite 8
- Tesla-black minimalist theme (Inter font)
- **Enriched thought rows with expandable args + result preview**

**Tools (in Kali container, versions pinned via ARG):**
- Recon: subfinder, assetfinder, dnsx, httpx, katana
- Discovery: nuclei, ffuf, gobuster, feroxbuster, playwright (DOM sink monitor)
- Exploitation: sqlmap, dalfox, nikto, wpscan
- Post-ex: hashcat, hydra, john, medusa
- Cloud: awscli, gcloud, azure-cli
- **SAST: semgrep, CodeQL**
- Browser: Playwright + Chromium

**LLM providers:**
- DeepSeek (default; reasoning-tuned)
- Groq (fast fallback)
- Ollama (local, air-gapped)

**Observability (all opt-in):**
- Prometheus scrape at `/api/metrics` (with new metrics)
- OpenTelemetry OTLP
- JSON structured logging

**Notifications (all opt-in):** Slack, PagerDuty, SIEM, generic webhook.

---

## Slide 18 — What's NOT included (deliberate)

- **We are not a WAF or IDS.** We test — we don't defend.
- **We do not run persistence.** Payloads are all read-only proof-of-concepts; no backdoors, no C2 beacons, no shell-drop scripts.
- **We are not a bug bounty platform.**
- **We do not scan without a scope declaration.** `TargetScopeValidator.validate()` refuses empty scope at boot.

Anything that runs against a live target is explicitly authorized by:
1. Scope manager (target in allowlist)
2. Legal validator (SOW/ROE contract active)
3. Escalation gate (DEEP tier: operator approval per action)
4. Consent manager (per-exploit briefing)
5. **Egress firewall** (host-level filter regardless of scope drift)

---

## Slide 19 — Security posture

Passed a full internal audit of 155 findings — all closed. This cycle added:

| Category | Fix |
|---|---|
| Scope drift | ✓ Fail-closed scope validator seal |
| Data exfil via httpx | ✓ Import-time egress firewall |
| Container-level egress | ✓ iptables policy generator |
| Takeover false positives | ✓ DNS CNAME verification + FP marker suppression |
| Log-download 401 in browser | ✓ Query-param auth allowlist for GET download paths |
| Reasoning-row secret leak | ✓ `_redact_args()` + `_preview_result()` masking |
| Peer-agent prompt injection | ✓ Scratchpad tail fenced as `<untrusted:peer_agents>` |
| Format-parser gap | ✓ HDF5 / fsspec+Jinja / YAML / pickle / Parquet probe pack |
| Subdomain budget blowout | ✓ LIVE/DEAD/EXTERNAL tiering + `MAX_SUBDOMAIN_SCANS=6` |
| No SAST | ✓ Semgrep + CodeQL + LLM-reviewed findings |
| No capability floor | ✓ CyberGym benchmark runner |

---

## Slide 20 — Where we are on the maturity curve

```
              ┌─────────────────────────┐
              │  External red-team run  │
              │  Threat-model sign-off  │  ← 6-week gate to first customer
              │  SOC 2 mapping (opt)    │
              └───────────┬─────────────┘
                          │
    ┌─────────────────────┴─────────────────────┐
    │  Zero-day hunting stack COMPLETE:         │
    │  ✓ Adversarial critic loop                │
    │  ✓ Parallel agents + scratchpad           │
    │  ✓ Framework quirks corpus (10 stacks)    │  ← WHERE WE ARE
    │  ✓ Format-parser probes (HDF5/fsspec/…)   │
    │  ✓ SAST pipeline (semgrep + CodeQL)       │
    │  ✓ Coverage-guided semantic fuzzer        │
    │  ✓ Cross-role replay                      │
    │  ✓ CyberGym benchmark runner              │
    └─────────────────────┬─────────────────────┘
                          │
    ┌─────────────────────┴─────────────────────┐
    │  Deployment checklist COMPLETE:           │
    │  ✓ Auth, CORS, TLS, rate limits           │
    │  ✓ Encryption at rest + in transit        │
    │  ✓ Scope authorization end-to-end (seal)  │
    │  ✓ Egress firewall (httpx + iptables)     │
    │  ✓ Observability + notifications          │
    │  ✓ Backup + idempotent resume             │
    │  ✓ CI/CD (lint, tests, SBOM, Trivy)       │
    └─────────────────────┬─────────────────────┘
                          │
    ┌─────────────────────┴─────────────────────┐
    │  Working autonomous pipeline              │
    │  ✓ Reconnaissance → Reporting             │
    │  ✓ LLM planner + 85+ executors            │
    │  ✓ Retest + dedup + FP filter             │
    │  ✓ Multi-format reports                   │
    └───────────────────────────────────────────┘
```

**Bottom line:** every code-level gate is closed. Zero-day hunting stack shipped. Remaining pre-production items are process-level (red-team review, threat model sign-off, optional compliance mapping).

---

## Slide 21 — Roadmap (planned, not built)

**Q1:**
- Split the four remaining monolith files (`server.py`, `generic.py`, `central_brain.py`, `pg_store.py`)
- Move to Alembic migrations
- Multi-tenant isolation at the Postgres row level (RLS)

**Q2:**
- Native Burp + ZAP passive proxy import
- Better mobile-app scanning (APK static + dynamic via Frida)
- Kubernetes-native operator (CRDs for `Scan`, `Target`, `Schedule`)
- **Federated scratchpad** — cross-scan memory of successful chains, differential-privacy gated

**Q3:**
- Learned-strategy transfer across customers
- Bug-bounty submission flow (HackerOne / Bugcrowd export)
- **Continuous zero-day drift monitor** — re-runs format-probe pack when upstream parsers publish CVEs

**Q4:**
- Continuous scanning mode (diff since last scan, per-commit gating)
- SBOM-based scan targeting (import CycloneDX → prioritize by CVE match)
- **Autonomous exploit development for new CVEs** — LLM reads advisory + patch diff → constructs PoC

---

## Slide 22 — Demo script (7 minutes)

**Ideal live-demo path:**

1. Open the frontend, show the Dashboard with an active scan finishing
2. Click into that scan → **Live Agents tab** → show ~8 parallel sub-agents
3. Click "thoughts" on the `expert_probe/format_hdf5` agent → show the enriched feed
4. Click a `#12 · run_custom_python` row → expand → **show the actual Python source** the LLM wrote to trigger the HDF5 disclosure
5. Show `#13` result preview containing `/etc/passwd` bytes — file disclosure confirmed
6. Switch to **Scan Detail → Recon tab** — show subdomain tiering (LIVE / DEAD / EXTERNAL badges)
7. **Vulnerabilities tab** — filter by CRITICAL, click into the HDF5 finding
8. **PoC tab** — show reproduction curl + Playwright script
9. **Attack Chains tab** — show `.git → semgrep SSTI → EJS RCE` composed chain
10. **Chat tab** — ask: "why did you skip *.leanpub.com?" → LLM answers "classified EXTERNAL tier, not owned by target scope"
11. **Activity tab** — show live log tail via WebSocket
12. Kill All Scans → show the emergency stop
13. Open a rendered PDF report
14. Show `/api/metrics` — new `format_probe_hits_total{probe="hdf5_external_disclosure"}` counter

Total: ~7 minutes.

---

## Slide 23 — Q&A quick-reference

**Q: What if the LLM provider goes down?**
A: Provider fallback chain (DeepSeek → Groq → Ollama). Circuit breaker per `(provider, model, phase)`. Deterministic fallback catalog when all providers fail.

**Q: What's the false-positive rate?**
A: Retest engine + LLM validator + ML FP filter (when trained on ≥200 rows) + fingerprint dedup + **DNS-verified takeover** + **DOM-sink taint tracing** layered together. The Heroku takeover FP that shipped in last cycle's scan is now fixed by mandatory CNAME provider-suffix match.

**Q: How does it compare to Burp / Nessus / ProjectDiscovery cloud?**
A: Different problem. Burp is a manual pentester's IDE. Nessus is a signature-based network scanner. PD cloud is a template runner. AntiGravity is an autonomous decision-maker with adversarial critic loop, cross-agent coordination via scratchpad, and a zero-day hunting stack for file-format parsers.

**Q: Can it find zero-days like the OpenAI/HF incident?**
A: The format-probe pack (`hdf5_external_disclosure`, `fsspec_jinja_disclosure`, `fsspec_jinja_rce_command`, and the rest) is the exact primitive class OpenAI's agent exploited against Hugging Face in July 2026. Parallel agents + Postgres scratchpad is the same coordination pattern. Framework corpus is primed with those specific stacks. Whether it lands on a novel zero-day depends on the target — we ship the machinery.

**Q: Can it scan production without breaking it?**
A: Depends on tier. POC = safe read-only probes. SAFE_ACTIVE = safe probes with light writes. DEEP = full exploitation, escalation-gate approval per action. Scope manager + fail-closed seal + egress firewall block anything out of scope regardless of tier.

**Q: How do we integrate with our SIEM?**
A: `SIEM_HTTP_URL` + `SIEM_HTTP_TOKEN` env vars — every scan-finished / critical-finding / exploit-authorized / **egress-blocked** event posts a JSON envelope.

**Q: What about compliance?**
A: SOC 2 CC-6 / ISO 27001 A.12.6 / PCI-DSS 11.3 controls rendered into the report's compliance-mapping section.

**Q: Cost per scan?**
A: LLM tokens ~$1-3 per POC scan, ~$5-15 per DEEP scan against a mid-size app (DeepSeek pricing). Adversarial critic loop adds ~30% token overhead but is the difference between fuzzing and finding.

**Q: How do I audit what an agent actually did?**
A: Live Agents panel → thoughts → any row expands to show the exact `args` (Python source, curl payload, etc.) and `result preview` (masked). Every row also carries `duration_ms` and a color-coded HTTP status. Nothing the LLM does is hidden from the operator.

---

## Appendix — Where the docs live

- `docs/PRESENTATION.md` — this document (2026-09-06 revision)
- `docs/ARCHITECTURE.md` — system architecture reference
- `docs/COMMANDS.md` — every CLI + API command
- `docs/COVERAGE_ROADMAP.md` — vulnerability class coverage
- `docs/RAG_PIPELINE_DOCUMENTATION.md` — RAG deep dive
- `docs/ZERO_DAY_STACK.md` — format-probe reference + framework corpus contents
- `docs/production_readiness/` — audit + remediation trail
- `README.md` — quick start

---

## Appendix — Key command cheat sheet

```bash
# Local dev
docker-compose up -d postgres
python -m uvicorn ui.api.server:app --reload
cd ui/web && npm run dev

# Launch a scan (CLI)
python main.py --target example.com --tier POC
python main.py --target example.com --tier DEEP --auto-approve --scan-id my-scan-1

# Resume a crashed scan
python main.py --resume --scan-id my-scan-1

# Run CyberGym benchmark
python -m tests.benchmarks.cybergym_runner --tasks smoke --tier POC
python -m tests.benchmarks.cybergym_runner --tasks all --tier DEEP

# Backup
./scripts/pg_backup.sh
./scripts/pg_backup.sh --verify
./scripts/pg_backup.sh --restore backup.dump

# Pin Docker base digest
./scripts/pin_kali_digest.sh
./scripts/pin_kali_digest.sh --check

# Health check (now surfaces egress_firewall + scratchpad)
curl -H "X-API-Key: <key>" http://localhost:8903/api/health

# Metrics scrape
curl -H "X-API-Key: <key>" http://localhost:8903/api/metrics

# Kill all scans
curl -X POST -H "X-API-Key: <key>" http://localhost:8903/api/scans/kill-all

# Render Docker egress iptables snippet for a target
python -c "from core.security.egress_firewall import render_docker_network_policy; \
           print(render_docker_network_policy(['example.com', 'api.example.com']))"
```

---

*End of presentation.*
