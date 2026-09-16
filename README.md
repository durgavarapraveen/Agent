# AntiGravity Autonomous Penetration Testing Platform (v2.0)

**AntiGravity** is an AI-driven, multi-agent autonomous penetration testing and external attack surface management (EASM) platform. It provides end-to-end automated security assessments—from passive OSINT and active reconnaissance to vulnerability scanning, attack graph generation, proof-of-concept (PoC) exploitation, retesting, and executive/compliance report generation.

---

## 🚀 Key Features & Capabilities

- **Autonomous Agentic Orchestration**: Powered by LLM-driven decision loops (`CentralBrain` & `MetaBrain`) with circuit-breakers and fallback execution trees.
- **8-Phase Automated Pipeline**:
  - **Phase 0 (Authorization & Scope Verification)**: Enforces strict target validation with boundary checks via `TargetScopeValidator`.
  - **Phase 1 (Reconnaissance & OSINT)**: Passive OSINT, subdomains, CT logs, DNS records, cloud storage buckets, live HTTP request capture.
  - **Phase 2 (Vulnerability Analysis)**: Tech-matched Nuclei scanning, Nmap/Naabu port scanning, SQLMap, ZAP, and CVE correlation.
  - **Phase 3 (Attack Graph & Chains)**: Multi-step attack vector graph construction, privilege escalation paths, and lateral movement.
  - **Phase 4 (Exploitation Verification)**: Tiered exploitation (`POC`, `SHALLOW`, `DEEP`) to safely demonstrate risk without destructive actions.
  - **Phase 5 (Retest & Reporting)**: Automatic false-positive filtering, vulnerability retesting, and multi-framework compliance mapping (PCI-DSS, SOC2, HIPAA, CIS, NIST).
  - **Phase 6 (Post-Exploitation & Hardening)**: Credential harvesting simulation, persistence auditing, and MITRE ATT&CK mapping.
  - **Phase 7 (OSINT & EASM)**: Certificate Transparency, employee enumeration, cloud bucket discovery, and dark web/leak database correlation.
- **Standalone Mobile & Source Analysis**: Zero-setup analysis of Android APKs, iOS IPAs, and Source Code checkouts (via Semgrep SAST).
- **Local & Cloud LLM Support**: Seamlessly use DeepSeek, Groq, Bedrock, or run locally at zero-cost using **Ollama**.
- **Zero-Dependency Core**: Run scans out-of-the-box using the SQLite fallback without requiring a running PostgreSQL instance. 
- **Docker & Kali Linux Integration**: Containerized security tools via `KaliDockerExecutor` utilizing a heavily optimized 10-layer BuildKit cache strategy for ultra-fast incremental builds and isolated tool failure debugging.
- **Interactive Web UI & API**: A modern React-based frontend and FastAPI backend for real-time monitoring of scan execution, vulnerability timelines, and reports.
- **Coverage Engine (V2)**: Utilizes a `CoverageMatrix` and deterministic executors to automatically map endpoints to security tests for rigorous completeness.
- **Thread-Safe Shared Memory (`SharedContext`)**: Synchronized real-time state sharing across all worker agents and orchestrators.
- **PostgreSQL & pgvector Engine**: Highly scalable persistent storage for OSINT, threat intelligence, and vector-based semantic search across findings and context.

---

## 🛠️ Integrated Tools & Technologies

| Domain | Integrated Tools & Technologies |
|---|---|
| **Core Framework** | Python 3.11+, Asyncio, Pydantic v2, Pytest, `threading.Lock`, PostgreSQL, SQLite |
| **LLM & AI Engine** | Groq, DeepSeek, Bedrock, Ollama, Prompt A/B Testing, Fallback Decision Trees |
| **Recon & OSINT** | Sublist3r, `crt.sh` (CT Logs), `dnspython`, Shodan, Censys, AbuseIPDB, VirusTotal, GitHub Scanner |
| **Scanners & Encoders** | Nmap, Naabu, Katana, Nuclei (v3+), SQLMap, OWASP ZAP, FFuf, HTTPx |
| **Mobile & Source** | apktool, jadx, semgrep, git |
| **Container Environment** | Docker, 10-Layer Kali Container (`Dockerfile`), Web App (`Dockerfile.web`), `docker-compose` |
| **Web UI & API Server**   | React, Vite, Node.js, FastAPI, Uvicorn |
| **Reporting & Export** | ReportLab, WeasyPrint, Matplotlib, Jinja2, HTML5/CSS3 Executive Dashboards |

---

## 📦 Installation & Setup

### Prerequisites
- Python 3.11+
- Node.js + npm (for the web UI)
- Docker Desktop / Docker Engine (optional, for containerized tool execution and Postgres)
- `apktool`, `jadx` (optional, for mobile app decompilation)
- `semgrep` (optional, for SAST)

### 1. Clone & Setup Environment
```bash
git clone <repository-url>
cd <repository-folder>

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Core dependencies
pip install -r requirements.txt

# Web API dependencies
pip install -r ui/api/requirements.txt python-multipart
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`. 

**Generate an encryption key** (Required for production):
```bash
python scripts/generate_keys.py
```
*(Or for local dev, `export ANTIGRAVITY_ENV=development` and `export ENCRYPTION_KEY_DEV_UNSAFE=1`)*

Fill in your API credentials (e.g., Shodan, GitHub, API keys for Groq/DeepSeek) in `.env`.

### 3. Optional Components
- **PostgreSQL**: `docker compose up -d` (If not running, AntiGravity degrades gracefully to SQLite).
- **Ollama**: For free local LLM execution, install Ollama and run `python scripts/setup_local_models.py --pull`.
- **SAST**: `pip install semgrep`

---

## 💻 Usage Guide

### Full Scan (Live Target)
```bash
# Basic scan
python main.py --target https://example.com --tier POC

# Run with specific phases
python main.py --target https://example.com --phases RECON,ACTIVE_SCANNING

# Authenticated scan
python main.py --target https://example.com --credentials-file creds.json

# Feed a mobile app & source into a scan (endpoints merged into scope; SAST correlated with runtime findings)
python main.py --target https://example.com --mobile-app app.apk --source-repo https://github.com/org/repo

# Incremental scan (only re-test what changed vs the saved baseline)
python main.py --target https://example.com --incremental
```

*(Note: Add `--auto-approve` or `-y` to skip interactive exploit-consent prompts for CI runs)*

### Individual Analysis — APK / IPA / Source (No Target Required)
```bash
# Android APK — extract backend endpoints, secrets, deeplinks, cert-pinning
python main.py --mobile-app /path/to/app.apk

# iOS IPA
python main.py --ipa-app /path/to/app.ipa

# Source code — run Semgrep and group findings by vuln class
python main.py --source-path /path/to/checkout
python main.py --source-repo https://github.com/org/repo
```

### Multi-Target Assessment & Compliance
```bash
# Comma-separated list of targets
python main.py --targets example.com,app2.io,api.service.com

# Custom Compliance Frameworks
python main.py --target example.com --frameworks pci,soc2,hipaa
```

---

## 🖥️ Web UI (Dashboard)

AntiGravity provides a powerful interactive UI to monitor scans, review chain analysis, view AI-generated fix code, and analyze target source/mobile apps.

```bash
# Terminal 1 — API server
python ui/api/server.py

# Terminal 2 — Frontend dev server
cd ui/web
npm install
npm run dev
```

Open `http://localhost:5173` to access the dashboard. Configure your API keys in the **Settings** page if required.

---

## 📁 Comprehensive Architecture Map (530+ Files)

The project consists of over 530 Python files across 65+ packages. The `core/` directory contains the primary engines for the platform, divided into logical subsystems:

### Orchestration & State Management
- `core/orchestration/` - Durable orchestration, CentralBrain, MetaBrain, parallel execution, and agent spawners.
- `core/memory/` - Thread-safe in-memory state tracking across the agent swarm.
- `core/database/` - Postgres and SQLite backend abstractions.
- `core/checkpointing/`, `core/recovery/` - State persistence, error handling, and recovery mechanisms.

### Reconnaissance & Intelligence
- `core/discovery/` - API-first deep testing, OSINT, scraping, crawling, and attack surface mappers.
- `core/intelligence/`, `core/intel/` - Threat intelligence, LLM semantic application understanding, and IP reputation.
- `core/attack_surface/` - Surface state mapping, normalization, and endpoint tracking.
- `core/knowledge/`, `core/learning/` - Deduplication, knowledge graphs, and semantic inference.

### Security Testing & Execution
- `core/execution/` - Execution strategies, deterministic detectors, and tool wrappers.
- `core/exploitation/` - Systematic authorization testing (IDOR/BOLA/BFLA), payload injection, and chained exploits.
- `core/fuzzing/` - Grammar and context-aware input mutations.
- `core/tools/`, `core/integrations/` - Tool registries, Nuclei, Nmap, and third-party ticket integrations (Jira/Linear).
- `core/browser/` - Playwright automation and hardened browser workers for live interaction testing.

### AI & LLM Engine
- `core/llm/` - Multi-provider routing, batch endpoint classification, prompt caching, and cost governance.
- `core/prompts/` - Managed prompt templates for all specialized agents.
- `core/reasoning/`, `core/decisions/` - Policy engines, decision trees, and circuit breakers.

### Validation & Reporting
- `core/reporting/` - Executive PDF/HTML builders, attack narrative with browser recordings.
- `core/compliance/` - PCI-DSS, SOC2, HIPAA, CIS, and NIST CSF mapping algorithms.
- `core/evidence/`, `core/findings/` - Evidence collection, Oracle validation, and finding normalization.
- `core/monitoring/`, `core/observability/` - Incremental scan diffs, regression detection, and observability.

### Autonomous Agents (`agents/`)
- `exploit_agent.py` - Dedicated executor for multi-step exploits.
- `kali_executor.py` - Manages execution within isolated Docker environments.
- `universal_llm_harness.py` - Manages rate limits and multi-provider balancing (Groq, DeepSeek, Bedrock, Ollama).

### Additional Components
- `ui/` - Interactive React/Vite dashboard frontend and FastAPI backend.
- `tests/` - 1200+ Pytest suite (integration, unit, and mocked tests).
- `scripts/` - CI/CD deployment scripts, key generators, and benchmark launchers.

---

## 🛡️ Safety & Governance

- **Authorization Enforcement**: Every target must pass `TargetScopeValidator.is_authorized()` check before any network request or tool execution.
- **Strict Read-Only OSINT**: OSINT modules passively query public records without invasive probing.
- **Non-Destructive Exploitation**: Exploitation operates under strict `POC` (Proof-of-Concept) constraints by default, preventing data loss or service disruption.
- **Audit Logging**: All actions, tool commands, and LLM prompts are logged locally in `pentest.log` and the database for full auditability.

---

## 🧪 Testing & Benchmarks

Run the full automated test suite (runs locally without Postgres via SQLite):
```bash
python -m pytest tests/ -q
python -m ruff check .
```

Run live scoring against disposable targets (Juice Shop/DVWA):
```bash
docker compose -f docker-compose.benchmark.yml up --abort-on-container-exit
```

---

## 🛠 Troubleshooting

- **"ENCRYPTION_KEY is not set"** → Run `python scripts/generate_keys.py`.
- **DB "connection refused"** → Postgres isn't running; scans will fallback to SQLite if implemented, or writes skipped. Start Postgres via `docker compose up -d`.
- **APK/SAST returns nothing** → Ensure `apktool` / `jadx` / `semgrep` are installed and on your `PATH`.
- **UI shows blank tables / 401** → Ensure API key is set in UI Settings.
