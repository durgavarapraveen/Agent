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
- **Docker & Kali Linux Integration**: Containerized security tools via `KaliDockerExecutor` with auto-provisioning capabilities.
- **Thread-Safe Shared Memory (`SharedContext`)**: Synchronized real-time state sharing across all worker agents and orchestrators.
- **PostgreSQL & pgvector Engine**: Highly scalable persistent storage for OSINT, threat intelligence, and vector-based semantic search across findings and context.

---

## 🛠️ Integrated Tools & Technologies

| Domain | Integrated Tools & Technologies |
|---|---|
| **Core Framework** | Python 3.13+, Asyncio, Pydantic v2, Pytest, `threading.Lock`, PostgreSQL, `pgvector` |
| **LLM & AI Engine** | Groq / LLM API (`LLMClient`), Prompt A/B Testing, Fallback Decision Trees |
| **Recon & OSINT** | Sublist3r, `crt.sh` (CT Logs), `dnspython`, Shodan, Censys, AbuseIPDB, VirusTotal, GitHub Scanner |
| **Scanners & Encoders** | Nmap, Naabu, Katana, Nuclei (v3+), SQLMap, OWASP ZAP, FFuf, HTTPx |
| **Container Environment** | Docker, Kali Linux Container (`Dockerfile.kali`), `docker-compose` |
| **Reporting & Export** | ReportLab, WeasyPrint, Matplotlib, Jinja2, HTML5/CSS3 Executive Dashboards |

---

## 📦 Installation & Setup

### Prerequisites
- Python 3.10+ (Python 3.13 recommended)
- Docker Desktop / Docker Engine (optional, for containerized tool execution)

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

# Install dependencies
pip install -r requirements.txt

# Start PostgreSQL and Kali services
docker compose up -d
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env` and fill in your API credentials:
```env
ENABLE_OSINT=true
SHODAN_API_KEY=your_shodan_key
GITHUB_TOKEN=your_github_token
CENSYS_PAT=your_censys_personal_access_token
ABUSEIPDB_API_KEY=your_abuseipdb_key
VIRUSTOTAL_API_KEY=your_vt_key
```

---

## 💻 Usage Guide

### Single Target Assessment
```bash
# Run a standard assessment against a single target
python main.py --target example.com

# Run with an authorization document and specific exploitation tier
python main.py --target example.com --auth auth.txt --tier SHALLOW
```

### Skipping OSINT Phase
If you want a faster run or do not need OSINT gathering:
```bash
python main.py --target example.com --skip-osint
```
*(Or set `ENABLE_OSINT=false` in your `.env` file)*

### Multi-Target Assessment
```bash
# Comma-separated list of targets
python main.py --targets example.com,app2.io,api.service.com

# Target list file
python main.py --targets-file targets.txt --tier POC
```

### Custom Compliance Frameworks
```bash
python main.py --target example.com --frameworks pci,soc2,hipaa
```

### CLI Command Options
- `--target` : Single target domain or URL.
- `--targets` : Comma-separated list of target domains/URLs.
- `--targets-file` : Path to a file containing one target per line.
- `--auth` : Path to the authorization text/JSON file.
- `--tier` : Exploitation depth (`POC`, `SHALLOW`, `DEEP`). Default is `POC`.
- `--skip-osint` : Disables OSINT and EASM discovery phases.
- `--reset-dedup` : Clears the deduplication database before starting.
- `--frameworks` : Comma-separated list of compliance frameworks (`pci`, `soc2`, `hipaa`, `cis`, `nist`).

---

## 📁 Project Structure

```
├── main.py                     # Primary CLI Entrypoint
├── .env.example                # Template for environment variables
├── requirements.txt            # Python dependency manifest
├── Dockerfile.kali             # Kali Linux container definition
│
├── core/                       # Core Orchestration & Engines
│   ├── central_brain.py        # Main LLM-driven orchestrator state machine
│   ├── meta_brain.py           # Multi-target parallel manager
│   ├── shared_context.py       # Thread-safe in-memory state & event store
│   ├── osint_engine.py         # OSINT employee & credential discovery engine
│   ├── osint_integration.py    # OSINT orchestrator & task manager
│   ├── subdomain_enum.py       # Subdomain & VHost discovery module
│   ├── threat_intel.py         # Threat intelligence & IP reputation engine
│   ├── nuclei_runner.py        # Nuclei vulnerability scanner wrapper
│   ├── retest_engine.py        # Automated finding retesting engine
│   ├── reporting.py            # Enterprise HTML/PDF report builder
│   ├── config.py               # Environment & configuration loader
│   └── authorization.py        # Strict target scope validator
│
├── agents/                     # Specialized Agents & Executors
│   ├── agent_spawner.py        # Worker agent instantiator
│   ├── kali_executor.py       # Kali Docker container command executor
│   └── llm_client.py           # LLM API client wrapper & prompt manager
│
├── compliance/                 # Regulatory Compliance Mappers
│   ├── pci_dss.py              # PCI-DSS v4.0 mapping
│   ├── soc2.py                 # SOC2 Trust Services Criteria
│   ├── hipaa.py                # HIPAA Security Rule
│   ├── cis_controls.py         # CIS Critical Security Controls v8
│   └── nist_csf.py             # NIST Cybersecurity Framework
│
├── tools/                      # Security Tool Wrappers
│   ├── real_scanner.py         # Docker-based Nmap, SQLMap, ZAP, Naabu wrappers
│   ├── kali_scanner.py         # Native Kali Linux tool integration
│   └── manager.py              # Tool registry and execution router
│
└── tests/                      # Automated Test Suite (364+ Tests)
    ├── test_complete_e2e_flow.py # End-to-end integration tests
    ├── test_osint_storage.py   # OSINT database and schema tests
    └── ...                     # Comprehensive unit & module tests
```

---

## 🛡️ Safety & Governance

- **Authorization Enforcement**: Every target must pass `TargetScopeValidator.is_authorized()` check before any network request or tool execution.
- **Strict Read-Only OSINT**: OSINT modules passively query public records (CT logs, DNS, public breach databases) without, invasive probing.
- **Non-Destructive Exploitation**: Exploitation modules operate under strict `POC` (Proof-of-Concept) constraints by default, preventing data loss or service disruption.
- **Audit Logging**: All actions, tool commands, and LLM prompts are logged locally in `pentest.log` and PostgreSQL databases for full auditability.

---

## 🧪 Testing

Run the full automated test suite (360+ tests):
```bash
python -m pytest -k "not trio"
```
Or run specific test modules:
```bash
python -m pytest tests/test_complete_e2e_flow.py
python -m pytest tests/test_osint_storage.py
```
