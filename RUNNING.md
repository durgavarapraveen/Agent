# Running AntiGravity

Practical guide to running the scanner, the **standalone APK / source analysis**,
the web UI, the tests, and the benchmarks.

- Python **3.11**
- OS: Linux / macOS / Windows (commands below work in bash and PowerShell)

---

## 1. Setup

```bash
# Core Python dependencies
pip install -r requirements.txt

# Web API dependencies (FastAPI + Uvicorn) + multipart for file uploads
pip install -r ui/api/requirements.txt python-multipart
```

**Encryption key** (required for signing/evidence; production refuses to start
without a real key):

```bash
# Generate a real key and write it into .env
python scripts/generate_keys.py

# …or, for local dev only, auto-generate a throwaway per-machine key:
export ANTIGRAVITY_ENV=development
export ENCRYPTION_KEY_DEV_UNSAFE=1
```

Copy `.env.example` → `.env` and fill in an LLM provider (DeepSeek / Bedrock /
Ollama / …). See the comments in `.env.example`.

### Optional components (features degrade gracefully without them)

| Component | Needed for | Install |
|---|---|---|
| **PostgreSQL** | Persisting scans/findings/cost | `docker compose up -d` (or a local Postgres). Without it the scan still runs; DB writes are skipped. |
| **apktool** or **jadx** | APK decompilation | Package manager / official installer, on `PATH` |
| **semgrep** (+ **git**) | Grey-box source SAST | `pip install semgrep` |
| **Ollama** | Local LLM (free tier) | https://ollama.com — then `python scripts/setup_local_models.py --pull` |
| **Node.js + npm** | Building the web UI | https://nodejs.org |

---

## 2. Individual analysis — APK / IPA / source (no target, no scan)

Analyze a mobile app binary or a source checkout **on its own**.

### CLI

```bash
# Android APK — extract backend endpoints, secrets, deeplinks, cert-pinning
python main.py --mobile-app /path/to/app.apk

# iOS IPA
python main.py --ipa-app /path/to/app.ipa

# Source code — run Semgrep and group findings by vuln class
python main.py --source-path /path/to/checkout
python main.py --source-repo https://github.com/org/repo

# Both at once
python main.py --mobile-app app.apk --source-path /path/to/checkout
```

A JSON report is printed and written to `reports/standalone_analysis_<ts>.json`.
No `--target` is required in this mode.

> APK decompile needs `apktool`/`jadx`; SAST needs `semgrep` (and `git` for a
> repo URL). If a tool is missing the run completes with empty results instead
> of failing.

### Web UI

Open **Analyze (APK / Source)** in the sidebar → upload an `.apk`/`.ipa` and
click **Analyze**, or enter a repo URL / server path and click **Run SAST**.

---

## 3. Full scan (against a live target)

```bash
# Basic scan
python main.py --target https://example.com --tier POC

# Limit phases
python main.py --target https://example.com --phases RECON,ACTIVE_SCANNING

# Authenticated scan
python main.py --target https://example.com --credentials-file creds.json

# Feed a mobile app / source into a scan (endpoints merged into scope;
# SAST correlated with runtime findings)
python main.py --target https://example.com --mobile-app app.apk --source-repo https://github.com/org/repo

# Incremental (only re-test what changed vs the saved baseline)
python main.py --target https://example.com --incremental
```

`--tier` is `POC` | `SHALLOW` | `DEEP`. Add `--auto-approve` (`-y`) to skip the
interactive exploit-consent prompts (needed for unattended/CI runs).

---

## 4. Web UI (dashboard)

Two processes: the FastAPI backend and the Vite frontend.

```bash
# Terminal 1 — API server (defaults to 0.0.0.0:8903; override with API_PORT/API_HOST)
python ui/api/server.py

# Terminal 2 — frontend dev server (proxies /api → http://127.0.0.1:8903)
cd ui/web
npm install
npm run dev            # dev server with hot reload
# or: npm run build    # production build into ui/web/dist
```

Then open the URL Vite prints (typically http://localhost:5173).
Start scans from **Targets → Scan** (the "Grey-box & Mobile" section there lets
you attach an APK/IPA or source repo to a scan). View results per scan under
**Scan History → <scan>**, including the **Cost & Risk**, **Chain Analysis**,
**Fix Code**, **Recordings**, **Regressions**, **Surface Diff**, and
**Grey-box (SAST)** tabs.

> If the API needs an API key, set it on the **Settings** page (or `?api_key=…`
> once in the URL).

---

## 5. Tests

```bash
# Full suite (DB-integration tests auto-skip without Postgres)
python -m pytest tests/ -q

# A single phase
python -m pytest tests/test_p1_1_workflow_interceptor.py -q

# Lint (repo config)
python -m ruff check .
```

Expected without a database: **all tests pass, a handful skipped** (the
`@integration` DB tests). Start Postgres to run those too.

---

## 6. Benchmarks

```bash
# Catalog + scoring unit tests (always runnable)
python -m pytest tests/test_p11_benchmarks.py -q

# Live scoring against disposable Juice Shop / DVWA containers (needs Docker)
docker compose -f docker-compose.benchmark.yml up --abort-on-container-exit
```

---

## 7. CI

- `.github/actions/antigravity-scan/` — reusable action: runs a scan, uploads
  SARIF to the Security tab, comments findings on the PR, fails on a severity
  threshold. Wrapper: `scripts/ci_scan.py`.
- `.github/workflows/antigravity-scan.yml` — runs the action against Juice Shop.
- `.github/workflows/benchmark.yml` — weekly benchmark regression check.

---

## Troubleshooting

- **"ENCRYPTION_KEY is not set"** → run `scripts/generate_keys.py`, or set
  `ENCRYPTION_KEY_DEV_UNSAFE=1` (dev only).
- **DB "connection refused"** → Postgres isn't running; scans still work, DB
  persistence is skipped. Start Postgres (or `docker compose up -d`) to enable it.
- **APK analysis returns nothing** → install `apktool` or `jadx` on `PATH`.
- **SAST returns nothing** → `pip install semgrep` (and have `git` for repo URLs).
- **UI shows blank tables / 401** → set the API key on the Settings page.
