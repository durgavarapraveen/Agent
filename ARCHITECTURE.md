# System Architecture

## Overview

The Autonomous Multi-Agent Cybersecurity Assessment Platform is built on a **dynamic agent orchestration** architecture that operates without hardcoded workflows. The system reasons about what work needs to be done, dynamically creates specialist agents, and correlates findings into actionable intelligence.

## Core Design Principles

### 1. No Hardcoded Workflows
Instead of: `Recon -> API -> Auth -> Report`

The system uses:
```
Objective → Central Agent → Reason → Plan → Execute → Observe → Replan
```

### 2. Dynamic Agent Creation
- Agents are created based on discovered requirements
- Unlimited logical agents with bounded concurrency
- Agents propose new work via structured task proposals
- Central Agent approves/rejects proposals

### 3. Persistent Knowledge
- All discoveries stored in SQLite knowledge base
- Agents query for relevant context
- Evidence preserved for all findings
- Audit trail of all operations

### 4. Evidence-Based Reasoning
- All findings must have supporting evidence
- LLM cannot invent vulnerabilities
- Validation agents independently verify claims
- Confidence scoring for all findings

## System Components

### Central Orchestrator (`orchestrator/central.py`)

**Responsibilities:**
- Understand user objectives
- Create initial assessment plan
- Create tasks from proposals
- Make structured decisions
- Manage agent lifecycle
- Determine assessment completion
- Execute re-planning loops

**Decision Flow:**
```
Objective
    ↓
LLM Reasoning
    ↓
Structured Decision
    ├─ CREATE_TASK
    ├─ APPROVE_TASK
    ├─ REJECT_TASK
    ├─ REPLAN
    ├─ CONTINUE
    ├─ COMPLETE
    └─ ... others
    ↓
Execute Decision
```

**Re-planning Loop:**
1. Collect task proposals from agents
2. Evaluate new discoveries
3. Create tasks from proposals
4. Queue tasks for execution
5. Check if assessment complete
6. If more work needed, repeat

### Agent System (`agents/`)

**Architecture:**
```
BaseAgent (Abstract)
    ├─ ReconAgent
    ├─ APIAgent
    ├─ AuthenticationAgent
    ├─ SourceAnalysisAgent
    ├─ DependencyAgent
    ├─ ValidationAgent
    ├─ CorrelationAgent
    └─ ReportingAgent
```

**Agent Lifecycle:**
```
CREATED
    ↓
INITIALIZED
    ↓
READY
    ↓
RUNNING
    ├─ Can transition to WAITING
    ↓
COMPLETED (or FAILED/TIMEOUT)
```

**Agent Interface:**
```python
class BaseAgent:
    async def execute_task(task: Task) -> AgentResult
    async def perform_work() -> AgentResult  # Must implement
    def propose_task(capability, objective, reason, priority)
```

**Agent Result Format:**
```python
{
    "status": "completed",
    "summary": "...",
    "discoveries": [...],
    "findings": [...],
    "evidence": [...],
    "artifacts": [...],
    "task_proposals": [
        {
            "capability": "new_capability",
            "objective": "...",
            "reason": "...",
            "priority": 7
        }
    ],
    "knowledge_updates": [...],
    "recommendations": [...]
}
```

### Task System (`orchestrator/scheduler.py`)

**Task States:**
```
PENDING → QUEUED → RUNNING → COMPLETED
                  ↓
                  FAILED/BLOCKED/CANCELLED
```

**Scheduler Features:**
- Dependency resolution
- Concurrency limiting via Semaphore
- Priority-based execution
- Task queue management
- Completion tracking

**Execution:**
```
Ready Tasks (dependencies met)
    ↓
Semaphore (max_concurrent_agents)
    ↓
Execute Task
    ├─ Create Agent
    ├─ Run Agent
    ├─ Collect Results
    └─ Update State
    ↓
Completed Queue
```

### Knowledge Store (`knowledge/store.py`)

**Schema:**
```
targets
    ├─ assets (domains, IPs, ports)
    │   ├─ technologies
    │   ├─ endpoints
    │   └─ apis
    │
    └─ findings
        ├─ evidence
        └─ related_findings
```

**Key Operations:**
- Add/query targets, assets, technologies
- Add/retrieve findings with evidence
- Track attack paths
- Export summaries

**Agent Context:**
Rather than passing entire database, agents query for relevant information:
```python
# Minimal context
agent.context.knowledge_store.get_asset_technologies(asset_id)
agent.context.knowledge_store.get_asset_endpoints(asset_id)
agent.context.knowledge_store.get_target_findings(target_id)
```

### Tool System (`tools/`)

**Architecture:**
```
BaseAgent
    ↓
ToolManager
    ├─ Validates scope
    ├─ Checks permissions
    └─ Executes tool
    ↓
ToolRegistry
    └─ Tool
        ├─ Execute with params
        └─ Return result
```

**Tool Permissions:**
- `PASSIVE`: Information gathering
- `SAFE_ACTIVE`: Non-destructive testing
- `FULL`: Full authorization

**Tool Result:**
```python
{
    "status": "success|failed",
    "data": {...},
    "error": "optional error message"
}
```

### Scope Manager (`scope/manager.py`)

**Scope Types:**
- Allowed domains (with wildcard support)
- Allowed IPs (CIDR notation)
- Allowed URLs
- Allowed local paths

**Validation:**
```
ToolExecution
    ↓
ScopeManager.validate_tool_execution(tool, target)
    ├─ Check target in scope
    ├─ Check execution mode
    └─ Check dangerous ops
    ↓
Approve/Reject
```

**Execution Modes:**
```
PASSIVE
  └─ Read-only operations only
  
SAFE_ACTIVE
  └─ Non-destructive testing allowed
  
FULL_AUTHORIZED
  └─ Full testing authorized
```

### LLM Integration (`llm/`)

**Provider Interface:**
```python
class LLMProvider:
    async def generate(prompt, system_prompt, max_tokens, temperature)
    async def generate_json(prompt, system_prompt, schema)
```

**Current Implementation:**
- `OllamaProvider`: Local model execution
- `MockProvider`: Testing/demo

**JSON Parsing:**
```
LLM Response
    ↓
Extract JSON
    ↓
Validate against schema
    ↓
Return structured output
```

### MCP Integration (`mcp/`)

**Model Context Protocol:**
```
Agent
    ↓
ToolManager
    ↓
MCPManager
    ├─ Discover tools
    ├─ Manage connections
    └─ Execute tools
    ↓
MCPServer
    └─ Tool implementation
```

**Tool Categories:**
- Vulnerability research (CVE, CWE)
- Threat intelligence (MITRE ATT&CK)
- Browser automation
- Source analysis
- Sandbox execution

### Event Bus (`core/events.py`)

**Event Types:**
```
Agent Events:
  - AGENT_CREATED
  - AGENT_INITIALIZED
  - AGENT_STARTED
  - AGENT_COMPLETED
  - AGENT_FAILED
  - AGENT_STATE_CHANGED

Task Events:
  - TASK_CREATED
  - TASK_QUEUED
  - TASK_STARTED
  - TASK_COMPLETED
  - TASK_FAILED
  - TASK_BLOCKED

Finding Events:
  - FINDING_CREATED
  - FINDING_CONFIRMED
  - FINDING_REJECTED

Orchestration Events:
  - REPLAN_STARTED
  - REPLAN_COMPLETED
  - VALIDATION_STARTED
  - ASSESSMENT_COMPLETE
```

**Subscription:**
```python
await event_bus.subscribe(EventType.AGENT_CREATED, callback)
await event_bus.publish(event)
events = await event_bus.get_events_by_type(EventType.AGENT_CREATED)
```

### Report Generation (`reporting/generator.py`)

**Formats:**
1. **JSON Report**: Structured data for automation
2. **Markdown Report**: Human-readable assessment

**Contents:**
- Executive summary (severity breakdown)
- Findings with evidence
- Discoveries and context
- Attack paths
- Recommendations
- Execution timeline

## Execution Flow

### Typical Assessment Sequence

```
1. USER REQUEST
   └─ Define target, objective, scope

2. CENTRAL ORCHESTRATOR STARTS
   ├─ Initialize components
   ├─ Create initial plan
   └─ Enter main loop

3. ITERATION 1
   ├─ Create Recon Task
   ├─ Scheduler queues task
   ├─ ReconAgent executes
   │  └─ Discover endpoints, technologies, APIs
   ├─ Process results
   └─ Propose new tasks (API analysis, tech analysis)

4. ITERATION 2
   ├─ Create API Analysis Task
   ├─ APIAgent discovers JWT auth, REST endpoints
   └─ Propose Authentication/Authorization analysis

5. ITERATION 3
   ├─ Create Authentication Task
   └─ Propose further specialized analysis

6. ... More iterations as needed

7. FINALIZATION
   ├─ Create validation tasks
   ├─ Create correlation tasks
   ├─ ValidationAgent confirms findings
   ├─ CorrelationAgent identifies attack paths
   ├─ ReportingAgent generates report
   └─ Export findings

8. COMPLETION
   └─ Output report and execution trace
```

### Decision Points

**Central Agent Questions:**
1. What capabilities are needed?
2. Which discoveries warrant new agents?
3. Are there unresolved proposals?
4. Have we gathered sufficient evidence?
5. Should we continue exploring?
6. Is the assessment complete?

## Concurrency Model

**Max Concurrent Agents:**
- Configurable limit (default: 4)
- Enforced via `asyncio.Semaphore`
- Allows unlimited logical agents/tasks

**Example:**
```
max_concurrent_agents = 4

Iteration 1: Run tasks 1-4
Iteration 2: Run tasks 5-8
Iteration 3: Run tasks 9-12
... continues until all tasks complete
```

## Evidence Model

**Evidence Hierarchy:**
```
Finding
    ├─ Evidence (supporting data)
    │   ├─ HTTP Response
    │   ├─ Header
    │   ├─ Source Code Location
    │   ├─ Tool Output
    │   └─ Test Result
    │
    ├─ Reproduction Summary
    ├─ CWE/CVE References
    └─ Confidence Score (0.0-1.0)
```

**Finding Status Lifecycle:**
```
OBSERVED (raw discovery)
    ↓
CANDIDATE (needs validation)
    ↓
VALIDATING (validation in progress)
    ├─ CONFIRMED (validated)
    └─ REJECTED (validation failed)
```

## Error Handling

**Resilience Strategy:**
- Agent failure doesn't stop assessment
- Retry logic for transient failures
- Graceful degradation
- Timeout protection
- Structured exception hierarchy

**Exception Types:**
```
SecurityAssessmentException
    ├─ AgentException
    ├─ TaskException
    ├─ ScopeViolationException
    ├─ ToolExecutionException
    ├─ KnowledgeStoreException
    ├─ LLMException
    ├─ MCPException
    ├─ ValidationException
    └─ TimeoutException
```

## Performance Considerations

**Resource Limits:**
```
max_concurrent_agents: 4
max_total_tasks: 100
max_task_runtime: 300s
max_agent_iterations: 10
global_execution_timeout: 1800s
```

**Optimization:**
- Parallel task execution
- Selective knowledge retrieval (not entire database)
- Efficient discovery storage
- Early completion detection

## Security Measures

1. **Scope Enforcement**: All tool calls validated
2. **Permission Checking**: Mode-based operation restrictions
3. **Evidence Preservation**: No unsubstantiated claims
4. **Timeout Protection**: Prevents infinite loops
5. **Error Containment**: Failures don't cascade

## Future Enhancements

1. **Advanced Correlation**: ML-based attack path discovery
2. **Real-time Streaming**: WebSocket-based result streaming
3. **Distributed Execution**: Multi-machine agent coordination
4. **ML Models**: Custom vulnerability detection
5. **Fuzzing Integration**: Automated input generation
6. **Exploit Validation**: Proof-of-concept execution
7. **Report Formatting**: PDF, HTML, SARIF output
8. **Custom Tools**: Plugin architecture for community tools

---

**Version:** 1.0.0  
**Last Updated:** 2024
