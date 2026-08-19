# COMPLETE PROJECT SETUP GUIDE

## 📁 PROJECT STRUCTURE

All files are now available in this folder. Here's the complete directory structure:

```
outputs/
├── main.py                          # Entry point - RUN THIS
├── requirements.txt                 # Python dependencies
├── .env.example                     # Configuration template
├── .gitignore                       # Git ignore
├── README.md                        # User guide
├── ARCHITECTURE.md                  # System design
├── DEVELOPMENT.md                   # Extension guide
├── PROJECT_SUMMARY.md              # Quick overview
├── FINAL_RESULTS.md                # Results report
├── SETUP_GUIDE.md                  # This file
│
├── core/                           # Core system
│   ├── __init__.py
│   ├── exceptions.py               # Exception types
│   ├── models.py                   # Data models (Task, Finding, etc)
│   ├── events.py                   # Event bus system
│   └── context.py                  # Execution context
│
├── orchestrator/                   # Orchestration engine
│   ├── __init__.py
│   ├── central.py                  # Central orchestrator (BRAIN)
│   ├── planner.py                  # Task planning
│   └── scheduler.py                # Task execution scheduler
│
├── agents/                         # Agent system
│   ├── __init__.py
│   ├── base.py                     # Base agent class
│   ├── factory.py                  # Agent factory & registry
│   └── specialists.py              # 8 specialist agent types
│
├── knowledge/                      # Knowledge store
│   ├── __init__.py
│   └── store.py                    # SQLite database
│
├── tools/                          # Tool system
│   ├── __init__.py
│   ├── base.py                     # Tool abstraction
│   ├── manager.py                  # Tool registry & manager
│   └── mock.py                     # Mock tools for demo
│
├── llm/                            # LLM providers
│   ├── __init__.py
│   ├── base.py                     # Provider interface
│   └── ollama.py                   # Ollama implementation
│
├── mcp/                            # MCP integration
│   ├── __init__.py
│   └── manager.py                  # MCP server manager
│
├── scope/                          # Scope management
│   ├── __init__.py
│   └── manager.py                  # Scope enforcement
│
├── reporting/                      # Report generation
│   ├── __init__.py
│   └── generator.py                # JSON + Markdown reports
│
└── tests/                          # Test suite
    ├── __init__.py
    ├── conftest.py                 # Pytest configuration
    ├── test_core.py                # Core tests
    ├── test_scheduler.py           # Scheduler tests
    ├── test_store.py               # Knowledge store tests
    └── test_scope.py               # Scope manager tests
```

## 🚀 QUICK START

### Step 1: Install Python Dependencies

```bash
pip install -r requirements.txt
```

**What gets installed:**
- `aiohttp==3.9.1` - Async HTTP client
- `python-dotenv==1.0.0` - Environment variables
- `requests==2.31.0` - HTTP library

### Step 2: Create Configuration File

```bash
cp .env.example .env
```

Edit `.env` and set:
```bash
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=neural-chat
MAX_CONCURRENT_AGENTS=4
GLOBAL_EXECUTION_TIMEOUT=1800
```

### Step 3: Run Demo Mode (NO REAL TARGET NEEDED)

```bash
python main.py --demo
```

This will:
- ✅ Show dynamic agent creation
- ✅ Demonstrate replanning
- ✅ Generate reports
- ✅ Run in ~20ms

## 🎯 USAGE EXAMPLES

### Demo Mode (Safest - No Real Target)
```bash
python main.py --demo
```
**Output:** Demo assessment with generated reports in `reports/` folder

### Web Target Assessment (REQUIRES AUTHORIZATION)
```bash
python main.py --target https://authorized-target.example --mode PASSIVE
```

**Modes:**
- `PASSIVE` - Information gathering only (default)
- `SAFE_ACTIVE` - Non-destructive testing
- `FULL_AUTHORIZED` - Full testing (requires authorization)

### Source Code Analysis
```bash
python main.py --repository ./my-project
```
**Output:** Analyzes code for security issues

## 📊 WHAT EACH FILE DOES

### Entry Point
- **main.py** - Command-line interface, entry point

### Core System
- **core/models.py** - Task, Finding, Evidence, Agent data classes
- **core/exceptions.py** - Exception hierarchy
- **core/events.py** - Event bus and logging system
- **core/context.py** - Execution context holder

### Brain (Orchestrator)
- **orchestrator/central.py** - Central orchestrator (THE BRAIN)
  - Understands objectives
  - Creates plans
  - Makes decisions
  - Manages agents
  - Continuous replanning

- **orchestrator/planner.py** - Creates task plans
- **orchestrator/scheduler.py** - Manages task execution

### Agents (The Workers)
- **agents/base.py** - Base agent class
- **agents/factory.py** - Creates agents dynamically
- **agents/specialists.py** - 8 specialist agent implementations:
  1. ReconAgent
  2. APIAgent
  3. AuthenticationAgent
  4. SourceAnalysisAgent
  5. DependencyAgent
  6. ValidationAgent
  7. CorrelationAgent
  8. ReportingAgent

### Knowledge Base
- **knowledge/store.py** - SQLite database
  - Stores all discoveries
  - Maintains relationships
  - Persists evidence

### Tools (Capabilities)
- **tools/base.py** - Tool abstraction
- **tools/manager.py** - Tool registry & manager
- **tools/mock.py** - Mock tools for demo/testing

### LLM (AI Reasoning)
- **llm/base.py** - Provider interface
- **llm/ollama.py** - Ollama local model support

### Integration
- **mcp/manager.py** - Model Context Protocol integration
- **scope/manager.py** - Scope/authorization enforcement
- **reporting/generator.py** - Report generation (JSON + Markdown)

### Tests
- **tests/** - Comprehensive unit tests
  - test_core.py - Core module tests
  - test_scheduler.py - Scheduler tests
  - test_store.py - Knowledge store tests
  - test_scope.py - Scope manager tests

## 🧪 RUN TESTS

```bash
# All tests
pytest tests/ -v

# Specific test
pytest tests/test_core.py -v

# With coverage
pytest tests/ --cov=. --cov-report=html
```

## 📂 OUTPUT DIRECTORIES

After running, these directories are created:

### `workspace/`
SQLite databases for each assessment:
- `demo.db` - Demo mode database
- `source.db` - Source analysis database

### `reports/`
Generated assessment reports:
- `report_YYYYMMDD_HHMMSS.json` - Structured data
- `report_YYYYMMDD_HHMMSS.md` - Human-readable

## 🔧 CONFIGURATION OPTIONS

Edit `.env` file:

```bash
# Ollama LLM
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=neural-chat

# Execution limits
MAX_CONCURRENT_AGENTS=4
MAX_TOTAL_TASKS=100
MAX_TASK_RUNTIME=300
MAX_AGENT_ITERATIONS=10
GLOBAL_EXECUTION_TIMEOUT=1800

# Logging
LOG_LEVEL=INFO

# Directories
WORKSPACE_DIR=workspace
REPORTS_DIR=reports
```

## ⚙️ SYSTEM REQUIREMENTS

- Python 3.9+
- pip package manager
- 100MB disk space (for databases and reports)
- Optional: Ollama for local LLM (for real usage)

## 🎓 EXAMPLE EXECUTION FLOW

```
$ python main.py --demo

[INFO] AUTONOMOUS SECURITY AGENT - DEMO MODE
[INFO] Central Orchestrator initialized

>>> ITERATION 1
[INFO] Creating Recon Task
[INFO] Agent RECONNAISSANCE-001 executing
[INFO] Discovery: Web application with APIs
[INFO] Proposal: Analyze APIs

>>> ITERATION 2
[INFO] Creating API Analysis Task
[INFO] Agent API-001 executing
[INFO] Discovery: REST API with JWT auth
[INFO] Proposal: Analyze Authentication

>>> FINALIZING ASSESSMENT
[INFO] Running validation and reporting
[INFO] Report generation complete

ASSESSMENT COMPLETE
Duration: 0.02s
Agents: 2
Tasks: 6
Findings: 0
Reports: 2 (JSON + Markdown)
```

## 🆘 TROUBLESHOOTING

### "ModuleNotFoundError: No module named 'aiohttp'"
```bash
pip install aiohttp python-dotenv requests
```

### "Connection refused" (Ollama)
This is OK for demo mode. Ollama is only needed for real assessments:
```bash
# Install Ollama from https://ollama.ai
# Run: ollama serve
# Download model: ollama pull neural-chat
```

### Tests fail
```bash
# Install pytest
pip install pytest

# Run tests
pytest tests/ -v
```

## 📖 DOCUMENTATION FILES

1. **README.md** - User guide and troubleshooting
2. **ARCHITECTURE.md** - System design and components
3. **DEVELOPMENT.md** - How to extend and customize
4. **PROJECT_SUMMARY.md** - Quick overview
5. **FINAL_RESULTS.md** - Project completion report

## 🚀 NEXT STEPS

### To Start Using:
1. ✅ Install dependencies: `pip install -r requirements.txt`
2. ✅ Run demo: `python main.py --demo`
3. ✅ Check `reports/` folder for generated reports
4. ✅ Read README.md for detailed usage

### To Customize:
1. Add new agents in `agents/specialists.py`
2. Register in `agents/factory.py`
3. Add new tools in `tools/`
4. Extend knowledge store in `knowledge/store.py`

### To Deploy:
1. Configure `.env` with your settings
2. Set up Ollama (if not using demo mode)
3. Define scope and target
4. Run appropriate command

## 📋 CHECKLIST

- [ ] Downloaded all files from this folder
- [ ] Extracted to your project directory
- [ ] Installed dependencies: `pip install -r requirements.txt`
- [ ] Created `.env` from `.env.example`
- [ ] Ran demo: `python main.py --demo`
- [ ] Checked `reports/` for generated reports
- [ ] Read README.md for more info

## ✨ YOU'RE ALL SET!

All files are ready to use. Start with:

```bash
python main.py --demo
```

This will:
1. Run a complete demonstration
2. Create autonomous agents
3. Execute dynamic replanning
4. Generate security reports
5. Save to `reports/` folder

**Total time:** ~20ms
**No external tools needed for demo**
**Full reports generated**

---

**For questions, see:**
- README.md - Usage guide
- ARCHITECTURE.md - How it works
- DEVELOPMENT.md - How to extend

🎉 **Enjoy your autonomous security assessment platform!**
