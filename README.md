# Neo — Autonomous Penetration Testing Platform (v2.0)

AI-driven, multi-agent autonomous penetration testing and external attack-surface management. An LLM plans each phase; deterministic specialist agents execute in parallel; findings are verified (including blind/out-of-band), chained, scored, and persisted. A FastAPI backend launches scans and a React dashboard streams them live.

> ⚠️ **Authorized use only.** Scan targets you own or are explicitly authorized to test (labs / CTFs / signed engagements). Every request is gated by `TargetScopeValidator`; authorization checks must never be removed.

---

## Highlights

- **Autonomous 4-phase pipeline** — `RECON → ACTIVE_SCANNING → EXPLOITATION → REPORTING`, driven by `CentralBrain` with a coverage gate that enforces required lanes.
- **Parallel specialist agents** — OSINT / web / infra / API recon lanes and probe families run concurrently, with a live per-agent activity + reasoning ("thoughts") stream.
- **Dynamic payload synthesis** — LLM proposes context-aware payloads (SSTI, XXE, deserialization, mass-assignment, GraphQL, WAF bypass, polyglots) that are verified against a live oracle before any finding is claimed.
- **Out-of-band verification** — blind XXE/SSRF/deserialization confirmed via a built-in local collaborator + free cloudflared tunnel (zero cost), or interactsh.
- **Attack-chain reasoning** — findings are chained, re-scored by chain membership, and bundled into reproducible PoCs.
- **Multi-provider LLM** — `claude_cli` (default), AWS **Bedrock**, or **DeepSeek**; switchable from the UI Settings page.
- **Multi-identity authz testing** — IDOR/BOLA/BFLA across roles.
- **Grey-box add-ons** — Android APK / iOS IPA endpoint extraction and Semgrep SAST correlated with runtime (DAST) findings.
- **Web dashboard + API** — real-time logs, agents, coverage, exploits, chains, and a per-scan "Ask LLM" chatbot.
- **Graceful degradation** — PostgreSQL is optional; the platform runs without it.

---

## Architecture (one screen)

```
 React UI ──POST /api/scans──▶ FastAPI ──Popen──▶ main.py (one process per scan)
 (Vite:5173) ◀──poll/stream──   (uvicorn)          └─ CentralBrain → phases → agents
                                    │                         │
                                    └────── PostgreSQL ◀──────┘   (UI & scan talk only via DB)
```

A scan is a **separate subprocess** (`python main.py --scan-id …`). Backend changes apply on the next scan; API changes need an API restart; UI changes hot-reload. See [DEVELOPER.md](DEVELOPER.md) for the full model.

---

## Quick start

**Prerequisites:** Python 3.11+, Node.js + npm. Optional: Docker (Postgres + Kali tools), `semgrep`, `apktool`/`jadx`, cloudflared.

```bash
# 1. environment
python -m venv .venv
.venv\Scripts\activate            # Windows   (source .venv/bin/activate on *nix)
pip install -r requirements.txt
pip install -r ui/api/requirements.txt python-multipart

# 2. config
cp .env.example .env              # then edit: LLM_PROVIDER, keys, DB, OOB_DOMAIN
python scripts/generate_keys.py   # generate ENCRYPTION_KEY (prod)

# 3. optional Postgres
docker compose up -d
```

### Run a scan (headless)

```bash
python main.py --target https://example.com --tier POC --auto-approve
```

### Run the dashboard

```bash
# terminal 1 — API
python ui/api/server.py

# terminal 2 — UI
cd ui/web && npm install && npm run dev
```

Open **http://localhost:5173**. Set your API key and LLM provider in **Settings**.

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
| `claude_cli` *(default)* | shells out to the `claude` CLI | `CLAUDE_CLI_{SMALL,LARGE}_MODEL`, `CLAUDE_CLI_BIN` |
| `bedrock` | AWS Bedrock (boto3) | `AWS_REGION`, `AWS_BEDROCK_{SMALL,LARGE}_MODEL` |
| `deepseek` | OpenAI-compatible API | `DEEPSEEK_API_KEY`, `DEEPSEEK_BASE_URL` |

Select via the **Settings** page (writes `.antigravity/llm_provider`) or `LLM_PROVIDER` in `.env`. Takes effect on the next scan.

---

## Configuration

All variables are documented in [`.env.example`](.env.example). Common ones:

- **LLM**: `LLM_PROVIDER`, provider keys/models above, `LLM_MAX_BUDGET_USD`, `LLM_FALLBACK_CHAIN`.
- **Database**: `DATABASE_URL` or `POSTGRES_{HOST,PORT,DB,USER,PASSWORD}` (optional — degrades to no-DB).
- **API**: `API_HOST`, `API_PORT`, `API_KEY`, `CORS_ORIGINS`.
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
- **No secret logging** — passwords/keys/tokens/secrets are redacted; credentials passed via unlinked temp files, never argv.
- **Full audit trail** in `pentest.log` and the `audit_log` / `execution_audit` tables.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ENCRYPTION_KEY is not set` | `python scripts/generate_keys.py` (or dev-unsafe env vars) |
| DB "connection refused" | Postgres down — `docker compose up -d`, or run without it (writes skipped) |
| UI blank tables / 401 | set the API key in **Settings** |
| OOB tunnel 502 | nothing bound on `:8899` — start a scan (collaborator inits eagerly in `main.py`) |
| `claude_cli` returns empty `{}` | large system prompt via argv overflowed on Windows — folded into stdin (already handled) |
| APK/SAST returns nothing | install `apktool` / `jadx` / `semgrep` on `PATH` |

---

## Contributing

Read **[DEVELOPER.md](DEVELOPER.md)** — architecture, scan lifecycle, LLM harness/providers, planner/normalizer, parallel agents, probes & payload synthesis, OOB, DB rules, API, frontend, and the security invariants you must not break.
