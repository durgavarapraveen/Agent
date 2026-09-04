# AntiGravity Platform — Operations & Command Reference Manual

This guide contains all the commands needed to set up, launch, operate, debug, and inspect the AntiGravity Autonomous Penetration Testing Platform and its Docker infrastructure.

---

## 1. Quick Start & Project Execution

### A. Environment Setup
```powershell
# 1. Activate the Python Virtual Environment
.venv\Scripts\activate

# 2. Copy and configure your environment variables (if not already done)
cp .env.example .env
# Edit .env and supply your API keys (DEEPSEEK_API_KEY, OPENAI_API_KEY, etc.)

# 3. Start Docker services (Kali Container & PostgreSQL with pgvector)
docker compose up -d
```

### B. Starting the Web UI & API Server (V2 Architecture)
```powershell
# 1. Start the FastAPI Backend Server
python -m uvicorn ui.api.server:app --port 8900

# 2. Start the React/Vite Frontend
cd ui/web
npm install
npm run dev
```

### C. Running Penetration Tests (`main.py`)
```powershell
# Standard Single-Target Scan (POC Tier)
python main.py --target https://www.decibyl.ai/

# Scan with Explicit Mode Selection
# Modes: DETERMINISTIC (A), DYNAMIC (B), HYBRID
python main.py --target https://www.decibyl.ai/ --mode DETERMINISTIC

# Run with OSINT and Threat Intelligence Enabled
python main.py --target https://www.decibyl.ai/ --osint

# Run with Custom Compliance Framework Mapping
# Supported frameworks: pci, soc2, hipaa, cis, nist
python main.py --target https://www.decibyl.ai/ --compliance pci,soc2,hipaa

# Run with Aggressive Exploitation Tier (Options: POC, SHALLOW, DEEP)
python main.py --target https://www.decibyl.ai/ --tier SHALLOW

# Run with Custom Scope File
python main.py --target https://www.decibyl.ai/ --scope .pentest_scope.json

# Run in Offline / Air-Gapped Mode (Uses local fallback tools only)
python main.py --target https://www.decibyl.ai/ --offline
```

### C. Running Verification Tests
```powershell
# Run the entire test suite
.venv\Scripts\python -m pytest tests/

# Run hybrid engine and tool router integration tests
.venv\Scripts\python -m pytest tests/test_hybrid_integration.py tests/test_architecture.py

# Run quick unit tests with verbose output
.venv\Scripts\python -m pytest tests/ -k "router or tool or normalizer" -v
```

---

## 2. Docker Container Management Commands

### A. Service Lifecycle
```powershell
# Start all containers in background
docker compose up -d

# Check status and health of all running containers
docker compose ps

# View real-time logs of all services
docker compose logs -f

# View logs for a specific service
docker compose logs -f kali-pentesting
docker compose logs -f postgres

# Stop all containers
docker compose stop

# Stop and remove containers and networks
docker compose down

# Build containers (utilizes the 10-Layer Docker caching strategy for Kali)
# Tip: Use without --no-cache to resume from transient network failures during apt-get
docker compose build

# Rebuild containers from scratch (forces downloading everything)
docker compose build --no-cache

docker compose up -d
```

---

## 3. Kali Linux Container (`kali-pentesting-mcp`) Commands

### A. Accessing the Kali Container Shell
```powershell
# Open an interactive Bash terminal inside the Kali container
docker exec -it kali-pentesting-mcp bash

# Execute a one-off command inside Kali without entering interactive shell
docker exec kali-pentesting-mcp whoami
```

### B. Inspecting Installed Tools & Environment
```bash
# Check paths of all core security tools
which nmap masscan subfinder httpx dnsx nuclei ffuf assetfinder whatweb wafw00f sqlmap nikto hydra

# Check tool versions
nuclei -version
httpx -version
subfinder -version
nmap --version
```

### C. Testing Security Tools Directly inside Kali
```bash
# 1. Test Subdomain Enumeration with assetfinder & subfinder
assetfinder --subs-only decibyl.ai
subfinder -d decibyl.ai -silent

# 2. Test HTTP Probing with httpx
echo "decibyl.ai" | httpx -silent -title -tech-detect -status-code

# 3. Test Web Technology Fingerprinting with whatweb & wafw00f
whatweb https://www.decibyl.ai
wafw00f https://www.decibyl.ai

# 4. Test Port Scanning with nmap
nmap -sV -F decibyl.ai

# 5. Test Vulnerability Scanning with Nuclei
nuclei -u https://www.decibyl.ai -tags cve,tech,misconfig -silent

# 6. Update Nuclei Templates
nuclei -update-templates
```

### D. Inspecting Persistent Workspace Volumes in Kali
```bash
# Code and data are mounted at /pentesting
cd /pentesting
ls -la

# View generated reports, payloads, and captured loot
ls -la /pentesting/reports/
ls -la /pentesting/loot/
ls -la /pentesting/payloads/
```

---

## 4. PostgreSQL & pgvector Container (`hexstrike_pgvector`) Commands

### A. Accessing the PostgreSQL Interactive CLI (`psql`)
```powershell
# Connect directly to the PostgreSQL database inside the container
docker exec -it hexstrike_pgvector psql -U hexstrike_user -d hexstrike_db
```

### B. Essential PostgreSQL / SQL Commands

Once inside `psql` (or run via `docker exec hexstrike_pgvector psql -U hexstrike_user -d hexstrike_db -c "<SQL>"`):

```sql
-- 1. List all databases
\l

-- 2. List all tables in the current database
\dt

-- 3. Show schema description of a specific table
\d subdomains
\d osint_findings
\d threat_intel
\d vuln_intel
\d target_profiles

-- 4. Check if pgvector extension is installed and active
SELECT * FROM pg_extension WHERE extname = 'vector';

-- 5. Query discovered subdomains
SELECT id, target, subdomain, source, discovered_at FROM subdomains ORDER BY discovered_at DESC LIMIT 20;

-- 6. Query OSINT findings (leaks, employees, cloud buckets)
SELECT id, target, finding_type, title, severity, discovered_at FROM osint_findings ORDER BY discovered_at DESC LIMIT 20;

-- 7. Query Threat Intelligence records & IP reputations
SELECT id, indicator, indicator_type, threat_score, sources FROM threat_intel ORDER BY threat_score DESC LIMIT 20;

-- 8. Query Vulnerability Intelligence & CVE mappings
SELECT id, cve_id, title, cvss_score, affected_service FROM vuln_intel ORDER BY cvss_score DESC LIMIT 20;

-- 9. Inspect vector embeddings (semantic vulnerability search)
SELECT id, cve_id, title, embedding FROM vuln_intel WHERE embedding IS NOT NULL LIMIT 5;

-- 10. Exit psql prompt
\q
```

### C. One-Line Quick Database Queries from Windows PowerShell
```powershell
# Check total record counts across all persistent tables
docker exec hexstrike_pgvector psql -U hexstrike_user -d hexstrike_db -c "
SELECT 'subdomains' AS table_name, count(*) FROM subdomains
UNION ALL
SELECT 'osint_findings', count(*) FROM osint_findings
UNION ALL
SELECT 'threat_intel', count(*) FROM threat_intel
UNION ALL
SELECT 'vuln_intel', count(*) FROM vuln_intel;
"

# View recent target scan summaries
docker exec hexstrike_pgvector psql -U hexstrike_user -d hexstrike_db -c "
SELECT target, count(subdomain) AS total_subdomains FROM subdomains GROUP BY target;
"

# Backup PostgreSQL database to a local SQL dump file
docker exec hexstrike_pgvector pg_dump -U hexstrike_user hexstrike_db > hexstrike_backup.sql

# Restore PostgreSQL database from a SQL dump file
cat hexstrike_backup.sql | docker exec -i hexstrike_pgvector psql -U hexstrike_user -d hexstrike_db
```

---

## 5. Log Files & Output Inspection

```powershell
# View live pentest execution log
Get-Content -Wait -Tail 50 pentest.log

# List generated HTML and JSON reports
Get-ChildItem reports/

# Open the latest generated HTML report in your default browser
Start-Process (Get-ChildItem reports/pentest_*.html | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
```
