# Autonomous Multi-Agent Cybersecurity Assessment Platform

A production-quality Python framework for autonomous cybersecurity reasoning and assessment. The system dynamically creates specialist agents based on discovered requirements, maintains persistent knowledge, correlates findings, and generates detailed security reports.

## Features

### Core Architecture
- **Dynamic Agent System**: Unlimited logical agents with configurable concurrency limits
- **Central Orchestrator**: Intelligent reasoning and planning without hardcoded workflows
- **Persistent Knowledge Store**: SQLite-based system for maintaining all assessment data
- **Event-Driven Architecture**: Full visibility into all system operations
- **Structured LLM Output**: Validated JSON decisions instead of free-form responses

### Capabilities
- **Reconnaissance**: Automated target surface mapping
- **Web Application Analysis**: HTTP/API security assessment
- **Source Code Analysis**: Static analysis of codebases
- **API Security**: REST/GraphQL endpoint analysis
- **Vulnerability Research**: CVE/CWE/MITRE ATT&CK integration
- **Finding Correlation**: Identify attack paths and relationships
- **Validation**: Independent verification of candidate findings
- **Report Generation**: Professional JSON and Markdown reports

### Execution Modes
- **PASSIVE**: Information gathering only (default)
- **SAFE_ACTIVE**: Non-destructive testing
- **FULL_AUTHORIZED**: Full authorization for authorized targets

### Target Types
- **Web Applications**: Full HTTP/API assessment
- **Source Code**: Repository analysis
- **Demo Mode**: Simulated assessment without real targets

## Installation

### Prerequisites
- Python 3.9+
- Ollama (for local LLM)
- Git

### Setup

```bash
# Clone repository
git clone <repo-url>
cd security-assessment-platform

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
```

## Configuration

### Ollama Setup

```bash
# Install Ollama from https://ollama.ai

# Download a model
ollama pull neural-chat

# Run Ollama (default port 11434)
ollama serve
```

### Environment Variables

Edit `.env`:

```bash
# Ollama configuration
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=neural-chat

# Execution limits
MAX_CONCURRENT_AGENTS=4
MAX_TOTAL_TASKS=100
GLOBAL_EXECUTION_TIMEOUT=1800
```

## Usage

### Demo Mode (No Real Target Required)

```bash
python main.py --demo
```

Shows:
- Dynamic agent spawning
- Task execution and dependencies
- Finding generation
- Validation and correlation
- Report generation

### Web Target Assessment

```bash
python main.py --target https://authorized-target.example --mode PASSIVE
```

Modes:
- `PASSIVE`: Reconnaissance only
- `SAFE_ACTIVE`: Includes non-destructive testing
- `FULL_AUTHORIZED`: Full attack surface testing

### Source Code Analysis

```bash
python main.py --repository ./my-project
```

Analyzes:
- Architecture and dependencies
- Secrets and credentials
- Dangerous functions
- Security-sensitive code

## Architecture

### System Overview

```
USER REQUEST
     |
     v
SCOPE MANAGER (Authorization)
     |
     v
CENTRAL ORCHESTRATOR
     |
     +-- Planner
     +-- Scheduler
     +-- Agent Factory
     |
     v
AGENTS (Dynamic)
     |
     +--> Recon Agent
     +--> API Agent
     +--> Source Agent
     +--> Auth Agent
     +--> Validation Agent
     +--> Correlation Agent
     +--> Reporting Agent
     |
     v
KNOWLEDGE STORE (SQLite)
     |
     v
FINDINGS & EVIDENCE
     |
     v
REPORTING
```

### Component Details

#### Central Orchestrator (`orchestrator/central.py`)
- Understands user objectives
- Creates and manages task plans
- Makes structured decisions via LLM
- Manages agent lifecycle
- Determines assessment completion

#### Agent System (`agents/`)
- **BaseAgent**: Abstract agent class
- **Specialists**: Recon, API, Auth, Source, Dependency, Validation, etc.
- **AgentFactory**: Dynamically creates agents based on capabilities
- **AgentRegistry**: Maintains available agent types

#### Knowledge Store (`knowledge/store.py`)
- Persistent SQLite database
- Stores: targets, assets, endpoints, APIs, technologies, findings, evidence
- Relationships between entities
- Efficient querying for agent context

#### Task System (`orchestrator/scheduler.py`)
- Task dependency resolution
- Concurrent execution with limits
- Task lifecycle management
- Status tracking and history

#### Tool System (`tools/`)
- **Base Tool**: Standard tool interface
- **ToolRegistry**: Manages available tools
- **Tool Manager**: Executes tools with scope validation
- **Mock Tools**: Demo/test implementations

#### LLM Integration (`llm/`)
- **LLMProvider**: Abstract interface
- **OllamaProvider**: Local model execution
- **MockProvider**: Testing support
- Structured JSON output parsing

#### Scope Manager (`scope/manager.py`)
- Validates targets and domains
- Enforces authorization boundaries
- Prevents scope expansion
- Restricts dangerous operations by mode

#### Report Generator (`reporting/generator.py`)
- JSON report with all structured data
- Markdown report with findings and recommendations
- Evidence attachment
- Severity-based organization

## Adding New Agents

### Step 1: Create Agent Class

```python
# agents/specialists.py
class CustomAgent(BaseAgent):
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Role Name", "capability_name", context)
    
    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Work completed")
        
        # Perform analysis
        # result.findings.append(...)
        # result.discoveries.append(...)
        # result.task_proposals.append(...)
        
        return result
```

### Step 2: Register Agent

```python
# agents/factory.py (in _register_default_agents)
self.register("custom_capability", CustomAgent)
```

### Step 3: Propose Tasks

Agents propose work:

```python
result.task_proposals.append(TaskProposal(
    capability="new_capability",
    objective="Analyze X",
    reason="Discovery triggered analysis",
    priority=7,
    proposed_by=self.agent_id
))
```

## Adding New Tools

### Step 1: Implement Tool

```python
# tools/custom.py
from tools.base import Tool, ToolInputSchema, ToolOutputSchema, ToolPermission

class CustomTool(Tool):
    def __init__(self):
        input_schema = ToolInputSchema(
            required_params={"target": "str"},
            optional_params={"option": "str"}
        )
        output_schema = ToolOutputSchema(
            return_type="dict",
            description="Result description"
        )
        super().__init__(
            name="custom_tool",
            description="Tool description",
            input_schema=input_schema,
            output_schema=output_schema,
            permissions=[ToolPermission.PASSIVE]
        )
    
    async def execute(self, **params) -> Dict[str, Any]:
        # Implementation
        return {"status": "success", "data": {...}}
```

### Step 2: Register Tool

```python
# tools/manager.py (in _load_default_tools)
from tools.custom import CustomTool
self.registry.register(CustomTool(), "category")
```

## Adding MCP Servers

### Configuration

```python
# In your orchestrator or main script
await context.mcp_manager.register_mcp_server(
    name="vulnerability_research",
    url="https://mcp-server.example.com"
)
```

### Using MCP Tools

```python
result = await context.mcp_manager.call_tool(
    "query_cve",
    {"cve_id": "CVE-2024-1234"}
)
```

## Extending the LLM Provider

### Create New Provider

```python
# llm/custom_provider.py
from llm.base import LLMProvider

class CustomProvider(LLMProvider):
    async def generate(self, prompt: str, system_prompt: str = "", 
                      max_tokens: int = 2000, temperature: float = 0.7) -> str:
        # Implementation
        pass
    
    async def generate_json(self, prompt: str, system_prompt: str = "",
                           schema: Dict[str, Any] = None) -> Dict[str, Any]:
        # Implementation
        pass
```

### Use Provider

```python
# main.py
from llm.custom_provider import CustomProvider

llm_provider = CustomProvider()
context = ExecutionContext(
    target=target,
    objective=objective,
    llm_provider=llm_provider,
    ...
)
```

## Test Suite

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test
python -m pytest tests/test_agents.py -v

# With coverage
python -m pytest tests/ --cov=. --cov-report=html
```

## Demo Walkthrough

```bash
$ python main.py --demo

[INFO] AUTONOMOUS SECURITY AGENT - DEMO MODE
[INFO] ==================================================
[INFO] Central Agent: Analyzing objective...
[INFO] Creating initial plan...
[INFO] Created 1 initial tasks

>>> ITERATION 1
[INFO] Executing tasks (queued: 1)...
[INFO] Agent RECON-001: Reconnaissance phase started
[INFO] Agent RECON-001: Discovery - Web application with APIs
[INFO] Task TASK-001: Completed
[INFO] Processing task results...
[INFO] Total discoveries: 1
[INFO] Total findings: 0
[INFO] Total proposals: 2

>>> REPLANNING
[INFO] Created 2 tasks from proposals

>>> ITERATION 2
[INFO] Agent API-001: API analysis started
[INFO] Agent API-001: Found REST API with JWT auth
[INFO] Task TASK-002: Completed
[INFO] Processing task results...
[INFO] Total discoveries: 2
[INFO] Total proposals: 1

>>> ITERATION 3
[INFO] Agent AUTHENTICATION-001: Authentication analysis
[INFO] Processing complete

>>> FINALIZING ASSESSMENT
[INFO] Executing validation/correlation/reporting tasks...

==================================================
ASSESSMENT COMPLETE
==================================================
Duration: 23.4s
Iterations: 3
Agents created: 5
Tasks executed: 8
Discoveries: 2
Findings: 3
  - Critical: 0
  - High: 1
  - Medium: 2
==================================================

[INFO] JSON report saved to reports/report_20240119_143052.json
[INFO] Markdown report saved to reports/report_20240119_143052.md
```

## Output Files

### Reports Directory
```
reports/
├── report_20240119_143052.json
├── report_20240119_143052.md
└── ...
```

### Workspace Directory
```
workspace/
├── demo.db
├── source.db
└── target_hash.db
```

## Security Considerations

### Scope Enforcement
- All targets must be explicitly authorized
- Scope violations raise `ScopeViolationException`
- Tool execution validates against scope

### Execution Modes
- **PASSIVE**: No active testing, information gathering only
- **SAFE_ACTIVE**: Non-destructive testing allowed
- **FULL_AUTHORIZED**: Full testing with explicit user approval

### Evidence Preservation
- All findings must have supporting evidence
- LLM cannot invent CVEs or findings
- Validation agents independently verify claims

### Resource Limits
- `max_concurrent_agents`: Limits parallel execution
- `max_total_tasks`: Maximum tasks per assessment
- `max_agent_iterations`: Replan iterations
- `global_execution_timeout`: Total execution time

## Performance Tuning

### Concurrency
```bash
# Increase concurrent agents
MAX_CONCURRENT_AGENTS=8

# Reduce for resource-constrained environments
MAX_CONCURRENT_AGENTS=2
```

### Timeouts
```bash
# Increase for complex targets
GLOBAL_EXECUTION_TIMEOUT=3600

# Reduce for faster feedback
GLOBAL_EXECUTION_TIMEOUT=600
```

### Iteration Limits
```python
# orchestrator/central.py
orchestrator.max_iterations = 10  # Increase exploration
```

## Troubleshooting

### Ollama Connection Error
```
Error: Connection refused
Solution: Ensure ollama is running: ollama serve
```

### Out of Memory
```
Error: MemoryError
Solution: Reduce MAX_CONCURRENT_AGENTS
```

### Tasks Not Executing
```
Error: Tasks stuck in QUEUED state
Solution: Check task dependencies, increase timeouts
```

## File Structure

```
project/
├── main.py                  # Entry point
├── requirements.txt         # Dependencies
├── .env.example            # Configuration template
│
├── core/
│   ├── exceptions.py       # Exception types
│   ├── models.py           # Data models
│   ├── events.py           # Event system
│   └── context.py          # Execution context
│
├── orchestrator/
│   ├── central.py          # Central orchestrator
│   ├── planner.py          # Task planning
│   └── scheduler.py        # Task scheduling
│
├── agents/
│   ├── base.py             # Base agent class
│   ├── factory.py          # Agent factory
│   └── specialists.py      # Specialist agents
│
├── knowledge/
│   └── store.py            # SQLite knowledge store
│
├── tools/
│   ├── base.py             # Tool abstraction
│   ├── manager.py          # Tool management
│   └── mock.py             # Mock tools
│
├── llm/
│   ├── base.py             # LLM abstraction
│   └── ollama.py           # Ollama provider
│
├── mcp/
│   └── manager.py          # MCP integration
│
├── scope/
│   └── manager.py          # Scope enforcement
│
├── reporting/
│   └── generator.py        # Report generation
│
├── tests/
│   ├── test_agents.py
│   ├── test_scheduler.py
│   ├── test_store.py
│   └── ...
│
└── workspace/              # Execution artifacts
```

## Contributing

### Adding New Capabilities

1. Create agent in `agents/specialists.py`
2. Register in `agents/factory.py`
3. Add tests in `tests/`
4. Update this README

### Bug Reports

Include:
- Python version
- Ollama version
- Command executed
- Full error trace
- .env configuration (sanitized)

## License

This project is provided as-is for authorized security assessment only.

## Disclaimer

This tool is designed for authorized security testing only. Users are responsible for:
- Obtaining proper authorization before testing
- Following all applicable laws and regulations
- Respecting target system availability and integrity
- Handling sensitive data responsibly

Unauthorized access to computer systems is illegal.

---

**Version:** 1.0.0  
**Last Updated:** 2024
