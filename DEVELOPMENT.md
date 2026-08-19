# Development Guide

This guide explains how to extend and customize the cybersecurity assessment platform.

## Adding a New Agent Type

### 1. Create Agent Class

Create a new file or add to `agents/specialists.py`:

```python
from agents.base import BaseAgent
from core.models import AgentResult, Finding, FindingSeverity, FindingStatus, TaskProposal

class MyCustomAgent(BaseAgent):
    def __init__(self, agent_id: str, context: Any):
        super().__init__(
            agent_id=agent_id,
            role="Custom Role Name",
            capability="my_custom_capability",
            context=context
        )
    
    async def perform_work(self) -> AgentResult:
        """Main work method - must be implemented."""
        result = AgentResult(
            status="completed",
            summary="Work completed successfully"
        )
        
        # Your analysis logic here
        
        # Add discoveries
        result.discoveries.append({
            "type": "custom_discovery",
            "data": "..."
        })
        
        # Add findings if issues found
        finding = Finding(
            title="Issue Title",
            description="Detailed description",
            severity=FindingSeverity.MEDIUM,
            confidence=0.8,
            status=FindingStatus.CANDIDATE,
            category="custom_category",
            source_agent_id=self.agent_id
        )
        result.findings.append(finding)
        
        # Propose follow-up work
        result.task_proposals.append(TaskProposal(
            capability="next_analysis",
            objective="Analyze finding further",
            reason="Initial discovery requires deeper analysis",
            priority=7,
            proposed_by=self.agent_id
        ))
        
        return result
```

### 2. Register Agent in Factory

Edit `agents/factory.py` in the `_register_default_agents()` method:

```python
def _register_default_agents(self):
    # ... existing registrations ...
    self.register("my_custom_capability", MyCustomAgent)
```

### 3. Test the Agent

Create a test file `tests/test_my_agent.py`:

```python
import pytest
from core.context import ExecutionContext
from core.models import Task
from agents.specialists import MyCustomAgent

@pytest.mark.asyncio
async def test_my_agent():
    # Create mock context
    context = ExecutionContext(
        target="test_target",
        objective="test",
        mode="DEMO"
    )
    
    # Create agent
    agent = MyCustomAgent("TEST-001", context)
    await agent.initialize()
    
    # Create task
    task = Task(
        title="Test Task",
        description="Test",
        objective="Test",
        capability="my_custom_capability",
        priority=5
    )
    
    # Execute
    result = await agent.execute_task(task)
    
    assert result.status == "completed"
    assert len(result.discoveries) > 0
```

### 4. Add Agent-Specific Tools

If your agent needs specialized tools:

```python
# agents/specialists.py
async def perform_work(self) -> AgentResult:
    # Call tool through tool manager
    tool_result = await self.context.tool_manager.execute_tool(
        "my_tool_name",
        {"param": "value"},
        agent_id=self.agent_id
    )
    
    if tool_result.get("status") == "success":
        # Process results
        pass
```

## Adding a New Tool

### 1. Implement Tool Class

Create `tools/my_tool.py`:

```python
from tools.base import Tool, ToolInputSchema, ToolOutputSchema, ToolPermission
from typing import Dict, Any

class MyTool(Tool):
    def __init__(self):
        input_schema = ToolInputSchema(
            required_params={
                "target": "str",
                "option": "str"
            },
            optional_params={
                "timeout": "int"
            }
        )
        
        output_schema = ToolOutputSchema(
            return_type="dict",
            description="Tool output description"
        )
        
        super().__init__(
            name="my_tool",
            description="Tool description",
            input_schema=input_schema,
            output_schema=output_schema,
            permissions=[ToolPermission.PASSIVE]
        )
    
    async def execute(self, **params) -> Dict[str, Any]:
        target = params.get("target")
        option = params.get("option")
        
        # Your tool logic
        
        return {
            "status": "success",
            "data": {
                "result": "..."
            }
        }
```

### 2. Register Tool

Edit `tools/manager.py` in `_load_default_tools()`:

```python
from tools.my_tool import MyTool

def _load_default_tools(self):
    # ... existing tools ...
    self.registry.register(MyTool(), "custom_category")
```

### 3. Test Tool

Create `tests/test_my_tool.py`:

```python
import pytest
from tools.my_tool import MyTool
from tools.base import ToolPermission

@pytest.mark.asyncio
async def test_my_tool():
    tool = MyTool()
    
    result = await tool.safe_execute(
        {"target": "test", "option": "value"},
        ToolPermission.PASSIVE
    )
    
    assert result["status"] == "success"
```

## Integrating a New LLM Provider

### 1. Create Provider Class

Create `llm/my_provider.py`:

```python
from llm.base import LLMProvider
from typing import Dict, Any

class MyLLMProvider(LLMProvider):
    def __init__(self, api_key: str = None):
        self.api_key = api_key
    
    async def generate(self, prompt: str, system_prompt: str = "",
                      max_tokens: int = 2000, temperature: float = 0.7) -> str:
        # Call your LLM API
        # Return text response
        response = await self._call_api(prompt, system_prompt)
        return response
    
    async def generate_json(self, prompt: str, system_prompt: str = "",
                           schema: Dict[str, Any] = None) -> Dict[str, Any]:
        # Generate with JSON parsing
        response = await self.generate(
            f"{prompt}\n\nRespond ONLY with valid JSON.",
            system_prompt=system_prompt,
            temperature=0.1
        )
        return self.parse_json_response(response)
    
    async def _call_api(self, prompt: str, system_prompt: str):
        # Your API call logic
        pass
```

### 2. Use in Main

Edit `main.py`:

```python
from llm.my_provider import MyLLMProvider

llm_provider = MyLLMProvider(api_key=os.getenv("MY_API_KEY"))

context = ExecutionContext(
    target=target,
    objective=objective,
    llm_provider=llm_provider,
    # ... other params
)
```

## Adding MCP Server Support

### 1. Register MCP Server

```python
# In main.py or after context creation
await context.mcp_manager.register_mcp_server(
    name="my_mcp_server",
    url="https://mcp-server.example.com"
)
```

### 2. Define MCP Tools

```python
# In agent
result = await self.context.mcp_manager.call_tool(
    "my_mcp_tool",
    {"param": "value"}
)
```

## Extending the Knowledge Store

### 1. Add New Schema Table

Edit `knowledge/store.py` in `_init_database()`:

```python
cursor.execute('''
    CREATE TABLE IF NOT EXISTS my_entities (
        entity_id TEXT PRIMARY KEY,
        target_id TEXT,
        name TEXT,
        data TEXT,
        created_at TEXT,
        FOREIGN KEY(target_id) REFERENCES targets(target_id)
    )
''')
```

### 2. Add Methods

```python
def add_my_entity(self, entity_id: str, target_id: str, name: str, data: Dict):
    conn = self._get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO my_entities (entity_id, target_id, name, data, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (entity_id, target_id, name, json.dumps(data), datetime.now().isoformat()))
        conn.commit()
    finally:
        conn.close()

def get_my_entities(self, target_id: str):
    conn = self._get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM my_entities WHERE target_id = ?', (target_id,))
    entities = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return entities
```

## Customizing Execution

### 1. Modify Max Iterations

Edit execution context or `orchestrator/central.py`:

```python
orchestrator.max_iterations = 20  # Explore more
```

### 2. Change Concurrency

Edit `.env`:

```bash
MAX_CONCURRENT_AGENTS=8
```

### 3. Adjust Timeouts

```python
context.max_task_runtime = 600  # 10 minutes
context.global_execution_timeout = 3600  # 1 hour
```

## Testing Framework

### Unit Tests

```bash
pytest tests/test_core.py -v
```

### Integration Tests

Create `tests/test_integration.py`:

```python
import pytest
from orchestrator.central import CentralOrchestrator
from core.context import ExecutionContext

@pytest.mark.asyncio
async def test_full_assessment():
    context = ExecutionContext(
        target="https://example.com",
        objective="Test",
        mode="DEMO"
    )
    
    orchestrator = CentralOrchestrator(context)
    await orchestrator.run()
    
    # Verify results
    assert len(orchestrator.all_tasks) > 0
    assert context.end_time is not None
```

### Test Coverage

```bash
pytest tests/ --cov=. --cov-report=html
```

## Debugging

### Enable Debug Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Inspect Event History

```python
events = await context.event_bus.get_execution_timeline()
for event in events:
    print(event)
```

### Check Knowledge Store

```python
summary = context.knowledge_store.export_database_summary()
print(f"Targets: {summary['targets']}")
print(f"Findings: {summary['findings']}")
```

## Performance Profiling

### Measure Agent Runtime

```python
agent = await factory.create_agent("reconnaissance", context)
# ... execute ...
print(f"Runtime: {agent.get_runtime_seconds()}s")
```

### Check Concurrency

```python
print(f"Running: {scheduler.get_running_count()}")
print(f"Queued: {scheduler.get_queued_count()}")
print(f"Completed: {scheduler.get_completed_count()}")
```

## Best Practices

### 1. Agent Design
- Keep agents focused on one capability
- Return structured results
- Propose concrete follow-up work
- Always include reasoning in proposals

### 2. Error Handling
- Catch exceptions and return failed status
- Log errors with context
- Never crash the orchestrator
- Return partial results when possible

### 3. Evidence Collection
- Store tool outputs as evidence
- Include timestamps and source
- Preserve raw data for verification
- Link evidence to findings

### 4. Task Proposals
- Only propose necessary follow-up work
- Include clear reasoning
- Set appropriate priority levels
- Avoid redundant proposals

### 5. Tool Development
- Implement proper input validation
- Include descriptive error messages
- Support timeout gracefully
- Test with various inputs

## Common Patterns

### Querying Knowledge Store

```python
# Get target context
target_findings = self.context.knowledge_store.get_target_findings(target_id)
target_assets = self.context.knowledge_store.get_target_assets(target_id)

# Get asset details
technologies = self.context.knowledge_store.get_asset_technologies(asset_id)
endpoints = self.context.knowledge_store.get_asset_endpoints(asset_id)
```

### Creating Evidence

```python
evidence = Evidence(
    type="tool_output",
    content=tool_result,
    tool_name="my_tool",
    source_agent_id=self.agent_id
)
finding.evidence.append(evidence)
```

### Proposing Work

```python
result.task_proposals.append(TaskProposal(
    capability="authentication_analysis",
    objective="Analyze discovered JWT auth",
    reason="API discovery indicated JWT usage",
    priority=8,
    proposed_by=self.agent_id
))
```

---

**Version:** 1.0.0
