# Neo — Autonomous Penetration Testing Platform (v2.0)

AI-driven, multi-agent autonomous penetration testing and external attack-surface management. An LLM plans each phase; deterministic specialist agents execute in parallel; findings are verified (including blind/out-of-band), chained, scored, and persisted. A FastAPI backend launches scans and a React dashboard streams them live.

> ⚠️ **Authorized use only.** Scan targets you own or are explicitly authorized to test (labs / CTFs / signed engagements). Every request is gated by `TargetScopeValidator`; authorization checks must never be removed.

---

## Highlights

- **Autonomous 4-phase pipeline** — `RECON → ACTIVE_SCANNING → EXPLOITATION → REPORTING`, driven by `CentralBrain` with a coverage gate that enforces required lanes.
- **Parallel specialist agents** — OSINT / web / infra / API recon lanes and probe families run concurrently, with a live per-agent activity + reasoning ("thoughts") stream.
- **Real tool arsenal** — 30+ Kali tools (nuclei, nmap, sqlmap, ffuf, katana, dalfox, subfinder, nikto, …) plus a read-only **Metasploit** auxiliary lane, all run inside an isolated Kali container.
- **Dynamic payload synthesis** — LLM proposes context-aware payloads (SSTI, XXE, deserialization, mass-assignment, GraphQL, WAF bypass, polyglots) that are verified against a live oracle before any finding is claimed.
- **Out-of-band verification** — blind XXE/SSRF/deserialization confirmed via a built-in local collaborator + free cloudflared tunnel (zero cost), or interactsh.
- **Attack-chain reasoning** — findings are chained, re-scored by chain membership, and bundled into reproducible PoCs.
- **Target-agnostic classification** — auth/API/param/role detection by shape + discovery (never app-specific literals), with an optional **Jev** typed classifier at decision gates.
- **Multi-provider LLM** — **DeepSeek** (default) / AWS **Bedrock** / Ollama; switchable from the UI Settings page.
- **Multi-identity authz testing** — IDOR/BOLA/BFLA across roles.
- **Grey-box add-ons** — Android APK / iOS IPA endpoint extraction and Semgrep SAST correlated with runtime (DAST) findings.
- **Web dashboard + API** — real-time logs, agents, coverage, exploits, chains, and a per-scan "Ask LLM" chatbot.
- **Graceful degradation** — PostgreSQL is optional; the platform runs without it.

---

## Architecture (one screen)

```
 React UI ──POST /api/scans──▶ FastAPI ──Popen──▶ main.py (one process per scan)
 (Vite:5173) ◀──poll/stream──   (uvicorn)          └─ CentralBrain → phases → agents
                                    │                         │        │
                                    │                         │        └─▶ Kali container
                                    │                         │            (nuclei/nmap/msf…)
                                    └────── PostgreSQL ◀───────┘   (UI & scan talk only via DB)
```

A scan is a **separate subprocess** (`python main.py --scan-id …`). Backend changes apply on the next scan; API changes need an API restart; UI changes hot-reload. See **[DEVELOPER.md](DEVELOPER.md)** for the full architecture, folder map, tool arsenal, and technologies.

---

## Two ways to run

| | Docker (recommended) | Local dev |
|---|---|---|
| Gets you | Postgres + **all Kali tools + Metasploit** + API/UI, isolated | fast Python/UI iteration; tools only if on host `PATH` |
| Best for | real scans, benchmarking, reproducibility | editing `core/`, probes, planner, frontend |

---

## A. Run with Docker (full stack: DB + Kali tools + Metasploit)

**Prerequisites:** Docker + Docker Compose v2. First Kali build pulls ~GBs of tools (nuclei templates, Metasploit) — allow time.

```bash
# 1. config — copy an env template and edit LLM keys
cp .env.example .env            # then set LLM keys (DeepSeek default; Bedrock/Ollama also supported)

# 2. build + start the whole stack (postgres + kali + web)
docker compose up -d --build

# 3. watch it come up
docker compose ps
docker compose logs -f web
```

Services (`docker-compose.yml`):

| service | container | purpose | port |
|---|---|---|---|
| `web` | `antigravity-web` | FastAPI API + React UI | **8900** |
| `kali` | `kali-pentesting` | all external security tools + Metasploit | (internal net) |
| `postgres` | `pentesting-postgres` | PostgreSQL 16 + pgvector | 5432 |

The API reaches the Kali tools over the Docker **network** (env `KALI_CONTAINER=kali-pentesting`) — the docker socket is **not** mounted (container-escape safe). Open **http://localhost:8900** and set your API key + LLM provider in **Settings**.

### Run a scan inside Docker

```bash
# headless scan in the kali container (tools local to it)
docker compose exec kali python main.py --target https://example.com --tier POC --auto-approve

# or launch from the UI at http://localhost:8900
```

### Stop / reset

```bash
docker compose down            # stop, keep volumes (DB, reports, loot)
docker compose down -v         # stop + wipe all data volumes
```

---

## B. Metasploit / msfconsole

Metasploit ships **inside the Kali container** (the build fails if `msfconsole -v` doesn't run). The scanner uses it only as a **read-only auxiliary/scanner lane** — allow-listed modules, no exploit modules — via `core/tools/adapters/metasploit.py` (the `msf_scanner` tool). It is **off by default**.

```bash
# enable the msf auxiliary lane for a scan (env flag)
docker compose exec -e NEO_ENABLE_MSF=1 kali \
    python main.py --target https://example.com --tier POC --auto-approve
```

Or set it persistently in `.env`:

```bash
NEO_ENABLE_MSF=1
```

Internally each run is invoked as `msfconsole -q -x <resource-script>` (auto-dispatched on open ports found in recon; scoped to the authorized target). To open an interactive console for manual work in the same container:

```bash
docker compose exec kali msfconsole
```

> Metasploit stays a **read-only aux scanner** by design (allowlist + scope + `NEO_ENABLE_MSF`). Do not wire exploit modules into the auto-dispatch path.

**Running the scanner on the host (not Docker)?** Metasploit is not auto-installed. Install `metasploit-framework` so `msfconsole` is on `PATH`, then set `NEO_ENABLE_MSF=1`. A missing binary is non-fatal — the lane is simply skipped.

---

## C. Local dev (no Docker for the app)

**Prerequisites:** Python 3.11+, Node.js + npm. Optional: Docker (for Postgres + Kali tools), `semgrep`, `apktool`/`jadx`, cloudflared.

```bash
# 1. environment
python -m venv .venv
.venv\Scripts\activate            # Windows   (source .venv/bin/activate on *nix)
pip install -r requirements.txt
pip install -r ui/api/requirements.txt python-multipart

# 2. config
cp .env.example .env              # then edit: LLM_PROVIDER, keys, DB, OOB_DOMAIN
python scripts/generate_keys.py   # generate ENCRYPTION_KEY (prod)

# 3. optional Postgres + Kali tools (tools still need the container)
docker compose up -d postgres kali
```

### Run the dashboard

```bash
# terminal 1 — API
python ui/api/server.py

# terminal 2 — UI
cd ui/web && npm install && npm run dev
```

Open **http://localhost:5173**. Set your API key and LLM provider in **Settings**.

### Run a scan (headless)

```bash
python main.py --target https://example.com --tier POC --auto-approve
```

> Without the Kali container, host-`PATH` tools are used; anything missing is skipped gracefully. For full coverage use the Docker stack (A).

---

## CLI usage

```bash
# tiers: POC (default, non-destructive) | SHALLOW | DEEP
python main.py --target https://example.com --tier POC

# specific phases
python main.py --target https://example.com --phases RECON,ACTIVE_SCANNING

# authenticated (creds file is read then unlinked — never passed via argv)
python main.py --target https://example.com --credentials-file creds.json

# multi-target
python main.py --targets a.com,b.io,api.c.com
python main.py --targets-file targets.txt --campaign --max-parallel 3

# grey-box: merge mobile endpoints + correlate SAST with runtime findings
python main.py --target https://example.com --mobile-app app.apk --source-repo https://github.com/org/repo

# incremental (diff vs saved attack-surface baseline)
python main.py --target https://example.com --incremental

# resume from last checkpoint
python main.py --target https://example.com --resume

# standalone analysis — no target needed
python main.py --mobile-app app.apk
python main.py --ipa-app app.ipa
python main.py --source-path ./checkout
```

Add `--auto-approve` / `-y` to skip interactive exploit-consent prompts (CI). `--frameworks pci,soc2,hipaa,cis,nist` to scope compliance mapping. `--sarif` to export SARIF.

---

## LLM providers

| provider | how | env |
|---|---|---|
| `deepseek` *(default)* | OpenAI-compatible API | `DEEPSEEK_API_KEY`, `DEEPSEEK_BASE_URL`, `DEEPSEEK_{SMALL,LARGE}_MODEL` |
| `bedrock` | AWS Bedrock (boto3) — incl. the Mantle OpenAI-compat gateway | `AWS_REGION`, `AWS_BEDROCK_{SMALL,LARGE}_MODEL` |
| `ollama` | local models | `OLLAMA_BASE_URL`, model names |

`LLM_FALLBACK_CHAIN` (e.g. `deepseek,bedrock,ollama`) provides automatic failover. Select the primary via the **Settings** page (writes `.antigravity/llm_provider`) or `LLM_PROVIDER` in `.env`. Changes take effect on the next scan.

---

## Configuration

All variables are documented in [`.env.example`](.env.example). Common ones:

- **LLM**: `LLM_PROVIDER`, provider keys/models above, `LLM_MAX_BUDGET_USD`, `LLM_FALLBACK_CHAIN`.
- **Database**: `DATABASE_URL` or `POSTGRES_{HOST,PORT,DB,USER,PASSWORD}` (optional — degrades to no-DB).
- **API**: `API_HOST`, `API_PORT`, `API_KEY`, `CORS_ORIGINS`.
- **Tools**: `KALI_CONTAINER` (Kali container name), `NEO_ENABLE_MSF` (Metasploit aux lane), `PROBE_CONCURRENCY`, `DISPATCH_BUDGET`.
- **Secrets**: `ENCRYPTION_KEY` (dev: `ANTIGRAVITY_ENV=development` + `ENCRYPTION_KEY_DEV_UNSAFE=1`).
- **OOB**: `OOB_DOMAIN` (+ run cloudflared to `localhost:8899`).
- **OSINT/intel** (all optional): `SHODAN_API_KEY`, `CENSYS_PAT`, `GITHUB_TOKEN`, `NVD_API_KEY`, `ABUSEIPDB_API_KEY`.

---

## Testing

```bash
python -m pytest tests/ -q     # runs without Postgres
python -m ruff check .         # Python lint
cd ui/web && npm run lint      # frontend lint

# live scoring vs disposable targets (Juice Shop / DVWA)
docker compose -f docker-compose.benchmark.yml up --abort-on-container-exit
```

---

## Safety & governance

- **Authorization enforced** on every request (`TargetScopeValidator`); egress firewall installed at startup.
- **Non-destructive by default** (`POC` tier); escalation is explicit; active exploitation needs consent unless `--auto-approve`.
- **Metasploit is read-only aux** (allowlist + scope + `NEO_ENABLE_MSF`); no exploit modules in auto-dispatch.
- **No secret logging** — passwords/keys/tokens/secrets are redacted; credentials passed via unlinked temp files, never argv.
- **Full audit trail** — hash-chained, tamper-evident, in the DB `audit_log` / `execution_audit` tables (on-disk `data/*.log` mirrors are opt-in via `NEO_FILE_AUDIT`); plus the operational `pentest.log`.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ENCRYPTION_KEY is not set` | `python scripts/generate_keys.py` (or dev-unsafe env vars) |
| DB "connection refused" | Postgres down — `docker compose up -d postgres`, or run without it (writes skipped) |
| UI blank tables / 401 | set the API key in **Settings** |
| Tools "not found" / 0 results | not in the Kali container — use `docker compose exec kali …` or install on host `PATH` |
| `metasploit disabled` in logs | set `NEO_ENABLE_MSF=1` (and ensure `msfconsole` exists — it's in the Kali image) |
| OOB tunnel 502 | nothing bound on `:8899` — start a scan (collaborator inits eagerly in `main.py`) |
| APK/SAST returns nothing | install `apktool` / `jadx` / `semgrep` on `PATH` |

---

## Contributing

Read **[DEVELOPER.md](DEVELOPER.md)** — architecture, scan lifecycle, full `core/` folder map, the external tool arsenal & Metasploit integration, technologies used, LLM harness/providers, planner/normalizer, parallel agents, probes & payload synthesis, target-agnostic helpers, Jev, OOB, DB rules, API, frontend, and the security invariants you must not break.
