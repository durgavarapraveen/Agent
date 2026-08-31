import re
import os

filepath = r"c:\Users\durga\Desktop\Projects\outputs\core\central_brain.py"
with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add imports
import_block = """
from core.tool_invocation_engine import ToolInvocationEngine, InvocationSource
from core.execution_mode import ExecutionMode, get_execution_config
from core.tool_gateway import ToolGateway
from core.claude_agent_loop import ClaudeAgentLoop
"""
content = content.replace("from core.schemas import (", import_block + "\nfrom core.schemas import (")

# 2. Add to __init__
init_hook = "self.task_manager = TaskManager()"
init_add = """
        # Phase 3 Configuration
        self.execution_config = get_execution_config()
        self.audit_logger = None  # Temporary, or get from somewhere
        # Use existing registry and stores for the gateway
        self.tool_gateway = ToolGateway(self.tools, self.knowledge_store, self.audit_logger)
        self.tool_invocation_engine = ToolInvocationEngine(self.tool_gateway)
        logger.info(f"Hybrid Mode Initialized: {self.execution_config.mode.name}")
"""
content = content.replace(init_hook, init_add + "\n        " + init_hook)

# 3. Rename old _run_phase and insert new routing logic
content = content.replace("async def _run_phase(self, phase: str):", "async def _run_phase_legacy(self, phase: str):")

new_methods = """
    async def _run_phase(self, phase: str):
        if self.execution_config.should_use_mode_a_primary():
            try:
                await self._run_phase_approach_a(phase)
            except Exception as e:
                logger.error(f"Approach A failed: {e}")
                if self.execution_config.can_fallback_to_b():
                    logger.info("Falling back to Approach B...")
                    await self._run_phase_approach_b(phase)
        elif self.execution_config.should_use_mode_b_primary():
            await self._run_phase_approach_b(phase)
        else:
            await self._run_phase_legacy(phase)

    async def _run_phase_approach_a(self, phase: str):
        logger.info(f"--- Running Approach A for phase: {phase} ---")
        prompt = f"Identify capability requests for phase {phase}."
        
        # Mock LLM call using existing llm client
        response = await self.llm.generate_response(prompt, system=BRAIN_SYSTEM)
        tasks = self._parse_deepseek_response(response.content)
        
        session_id = f"session_{phase}"
        auth_context = self.auth.get_context() if hasattr(self.auth, 'get_context') else None
        
        for task in tasks:
            capability = task.capability.value if hasattr(task.capability, 'value') else task.capability
            target = task.inputs.get('target', self.ctx.target)
            params = task.inputs.get('params', {})
            
            logger.info(f"Invoking capability: {capability} on {target}")
            
            result = await self.tool_invocation_engine.invoke_from_capability(
                capability, target, params, session_id, auth_context
            )
            
            self.task_manager.start_task(task.task_id)
            if result.success:
                self.task_manager.complete_task(task.task_id, {"status": "success"})
            else:
                self.task_manager.complete_task(task.task_id, {"status": "failed"})
                
            # Mock store finding
            self.finding_store.add_finding({"task_id": task.task_id, "result": result.success})
            logger.info(f"Executed task {task.task_id} with result: {result.success}")

    async def _run_phase_approach_b(self, phase: str):
        logger.info(f"--- Running Approach B for phase: {phase} ---")
        # Claude Agent Loop creation
        claude_loop = ClaudeAgentLoop(self.tool_invocation_engine)
        objective = f"Execute tasks for phase {phase}"
        session_id = f"session_claude_{phase}"
        auth_context = self.auth.get_context() if hasattr(self.auth, 'get_context') else None
        
        result = await claude_loop.run(objective, auth_context, session_id)
        
        # ToolUseExecutor is assumed to be part of ClaudeAgentLoop internally intercepting calls
        
        self.finding_store.add_finding({"phase": phase, "claude_result": result})
        logger.info(f"Claude Loop completed for {phase}")

    def _parse_deepseek_response(self, response_text: str) -> List[TaskSpec]:
        # Helper to parse DeepSeek json and return TaskSpec objects
        import json
        tasks = []
        try:
            data = json.loads(response_text)
            for item in data.get('tasks', []):
                task = TaskSpec(
                    objective=item.get('objective', ''),
                    capability=CapabilityType(item.get('capability', 'port_scanning')),
                    inputs={"target": item.get('target', ''), "params": item.get('params', {})}
                )
                tasks.append(task)
        except Exception:
            pass
        return tasks

"""
content = content.replace("    async def _run_phase_legacy(self, phase: str):", new_methods + "\n    async def _run_phase_legacy(self, phase: str):")

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)

print("Patched central_brain.py successfully")
