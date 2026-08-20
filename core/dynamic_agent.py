"""
DynamicAgent - Generic LLM-driven agent.
No hardcoded logic. LLM decides what tool to run, reads output, repeats.
Gets ONLY the context the brain decided is relevant.
"""

import json
import logging
import re
import asyncio
from typing import Dict, List, Optional
from datetime import datetime

from agents.llm_client import LLMClient, TaskTier
from core.tool_registry import ToolRegistry, ToolResult
from core.shared_context import SharedContext

logger = logging.getLogger(__name__)

AGENT_SYSTEM_PROMPT = """You are a specialized security testing agent.
You have an objective and tools. Execute the objective step by step.

RULES:
- Run ONE tool at a time
- After each tool, analyze output and decide next step
- When objective is complete, return results
- Be precise with tool arguments (exact commands)
- Parse tool output to extract useful data

RESPONSE FORMAT (strict JSON):
{
  "thinking": "what I learned and what to do next",
  "action": "run_tool" | "done",
  "tool": "tool_name",
  "command": "exact command to run",
  "timeout": 120,
  "results": {}  // only when action=done
}

When action="done", include results:
{
  "thinking": "objective complete because...",
  "action": "done",
  "results": {
    "summary": "what was found",
    "data": { ... extracted structured data ... },
    "findings": [ {"title": "...", "severity": "...", "location": "...", "details": "..."} ]
  }
}"""


class DynamicAgent:
    """
    LLM-driven agent. Brain spawns it with:
    - objective: what to accomplish
    - tools: which tools it can use
    - context: ONLY relevant data (brain decides what to share)
    - max_steps: safety limit
    """

    def __init__(
        self,
        agent_id: str,
        objective: str,
        tool_registry: ToolRegistry,
        shared_context: SharedContext,
        agent_context: str,          # Pre-filtered context from brain
        allowed_tools: List[str],    # Which tools this agent can use
        max_steps: int = 10,
    ):
        self.agent_id = agent_id
        self.objective = objective
        self.tools = tool_registry
        self.ctx = shared_context
        self.agent_context = agent_context
        self.allowed_tools = allowed_tools
        self.max_steps = max_steps
        self.llm = LLMClient.get()
        self.history: List[Dict] = []  # Tool execution history
        self.failed_tools = set()  # NEW: Track failed tools per agent
        self.max_retries_per_tool = 1  # NEW: Don't retry failed tools
        self.step_without_progress = 0
    
    async def execute_tool(self, tool_name: str, params: dict):
        """Execute a tool and return structured result"""
        
        # Skip if already failed
        if tool_name in self.failed_tools:
            return {
                "success": False,
                "error": "tool_failed_previously",
                "output": ""
            }
        
        try:
            logger.debug(f"[{self.agent_id}] execute_tool({tool_name}, {params})")
            
            # Get tool from registry
            tool = self.tools.get(tool_name)
            if not tool:
                return {
                    "success": False,
                    "error": f"Tool '{tool_name}' not found in registry",
                    "output": ""
                }
            
            # Execute tool
            result = tool.run(**params)
            
            # Convert ToolResult to dict
            output = result.output or ""
            error = result.error or ""
            
            return {
                "success": result.success,
                "output": output,
                "error": error,
                "data": result.data
            }
            
        except Exception as e:
            logger.error(f"[{self.agent_id}] Tool execution exception: {e}")
            self.failed_tools.add(tool_name)
            return {
                "success": False,
                "error": str(e),
                "output": ""
            }    
    
    async def execute(self):
        """Execute objective step-by-step via LLM decisions"""
        
        step = 0
        max_no_progress = 0
        max_no_progress_threshold = 3
        
        logger.info(f"[{self.agent_id}] Starting execution: {self.objective}")
        logger.info(f"[{self.agent_id}] Available tools: {', '.join(self.allowed_tools[:5])}")
        
        while step < self.max_steps:
            # Fail if stuck
            if max_no_progress >= max_no_progress_threshold:
                logger.warning(f"[{self.agent_id}] No progress for {max_no_progress} steps, aborting")
                return {
                    "status": "failed",
                    "reason": "no_progress",
                    "steps": step,
                    "summary": f"Stopped after {step} steps with no progress"
                }
            
            # Build context for this step
            prompt = self._build_step_prompt(step)
            logger.debug(f"[{self.agent_id}] Step {step + 1}: Asking LLM for next action")
            
            # Get decision from LLM
            try:
                decision = await self.llm.generate_json(prompt, tier=TaskTier.SMALL)
            except Exception as e:
                logger.error(f"[{self.agent_id}] LLM error: {e}")
                max_no_progress += 1
                await asyncio.sleep(2)
                continue
            
            if not decision:
                logger.warning(f"[{self.agent_id}] LLM returned nothing")
                max_no_progress += 1
                await asyncio.sleep(2)
                step += 1
                continue
            
            # Log LLM thinking
            thinking = decision.get("thinking", "")
            if thinking:
                logger.info(f"[{self.agent_id}] LLM: {thinking[:150]}")
            
            # Check for completion
            action = decision.get("action", "").lower()
            
            if action == "done":
                results = decision.get("results", {})
                self._store_results(results)
                logger.info(f"[{self.agent_id}] ✓ OBJECTIVE COMPLETE")
                logger.info(f"[{self.agent_id}] Summary: {results.get('summary', 'N/A')}")
                return {
                    "status": "success",
                    "steps": step,
                    "results": results
                }
            
            if action != "run_tool":
                logger.warning(f"[{self.agent_id}] Invalid action: {action}")
                max_no_progress += 1
                step += 1
                continue
            
            # Extract tool call
            tool_name = decision.get("tool", "").strip()
            command = decision.get("command", "").strip()
            timeout = decision.get("timeout", 120)
            
            if not tool_name:
                logger.warning(f"[{self.agent_id}] No tool specified")
                max_no_progress += 1
                step += 1
                continue
            
            # Validate tool
            if tool_name not in self.allowed_tools:
                logger.warning(f"[{self.agent_id}] Tool '{tool_name}' not in allowed list")
                max_no_progress += 1
                step += 1
                continue
            
            if tool_name in self.failed_tools:
                logger.warning(f"[{self.agent_id}] Tool '{tool_name}' already failed, skipping")
                max_no_progress += 1
                step += 1
                continue
            
            # Execute tool
            logger.info(f"[{self.agent_id}] Running: {tool_name} {command[:50]}")
            params = {
                "command": command,
                "timeout": timeout
            }
            
            result = await self.execute_tool(tool_name, params)
            
            # Store in history
            self.history.append({
                "step": step,
                "tool": tool_name,
                "command": command,
                "success": result.get("success", False),
                "output": result.get("output", "")[:200]
            })
            
            # Check result
            if result.get("success"):
                logger.info(f"[{self.agent_id}] ✓ {tool_name} succeeded")
                max_no_progress = 0
            else:
                error = result.get("error", "unknown error")
                logger.warning(f"[{self.agent_id}] ✗ {tool_name} failed: {error[:100]}")
                max_no_progress += 1
                
                # Mark as failed if critical error
                if "not found" in error.lower() or "no such file" in error.lower():
                    self.failed_tools.add(tool_name)
            
            step += 1
            await asyncio.sleep(0.5)
        
        # Max steps reached
        logger.warning(f"[{self.agent_id}] Max steps ({self.max_steps}) reached")
        return {
            "status": "timeout",
            "steps": self.max_steps,
            "summary": f"Hit max {self.max_steps} steps"
        }
    
    def _build_step_prompt(self, step: int) -> str:
        """Build LLM prompt for next step"""
        
        # Objective
        obj_section = f"OBJECTIVE: {self.objective}\n"
        
        # Context from brain
        ctx_section = f"CONTEXT:\n{self.agent_context}\n"
        
        # History (last 3 steps)
        hist_section = ""
        if self.history:
            hist_section = "RECENT EXECUTION HISTORY:\n"
            for h in self.history[-3:]:
                status = "✓" if h.get("success") else "✗"
                out = h.get("output", "")[:80].replace("\n", " ")
                hist_section += f"  {status} {h['tool']}: {out}\n"
        
        # Available tools (limit to 10 to save tokens)
        tools_list = ", ".join(self.allowed_tools[:10])
        if len(self.allowed_tools) > 10:
            tools_list += f", ... ({len(self.allowed_tools) - 10} more)"
        
        tools_section = f"\nAVAILABLE TOOLS: {tools_list}\n"
        
        # Failed tools warning
        failed_section = ""
        if self.failed_tools:
            failed_section = f"\nFAILED (skip these): {', '.join(self.failed_tools)}\n"
        
        # Build full prompt
        prompt = f"""{obj_section}
    {ctx_section}
    {hist_section}
    {tools_section}
    {failed_section}

    STEP {step + 1}/{self.max_steps}

    RULES:
    1. Run ONE tool per step
    2. After tool runs, analyze output
    3. When objective is COMPLETE, return action="done" with results
    4. Only use tools from AVAILABLE TOOLS list
    5. Respond ONLY with valid JSON (no markdown, no backticks)

    JSON FORMAT:
    {{
    "thinking": "what you learned and next step",
    "action": "run_tool" or "done",
    "tool": "tool_name",
    "command": "exact command",
    "timeout": 120,
    "results": {{"summary": "...", "data": {{...}}}}  // only when action=done
    }}"""
        
        return prompt
    
    def _store_results(self, results: Dict):
        """Parse agent results and store in shared context"""
        data = results.get("data", {})

        # Auto-store common data types
        if data.get("subdomains"):
            self.ctx.add_subdomains(data["subdomains"], self.agent_id)
        if data.get("ips"):
            self.ctx.add_ips(data["ips"], self.agent_id)
        if data.get("ports"):
            host = data.get("host", self.ctx.target)
            self.ctx.add_ports(host, data["ports"], self.agent_id)
        if data.get("endpoints"):
            self.ctx.add_endpoints(data["endpoints"], self.agent_id)
        if data.get("directories"):
            self.ctx.add_directories(data["directories"], self.agent_id)
        if data.get("technologies"):
            host = data.get("host", self.ctx.target)
            techs = data["technologies"]
            normalized = []
            for t in techs:
                if isinstance(t, dict):
                    normalized.append(t.get("name", str(t)))
                else:
                    normalized.append(str(t))
            self.ctx.add_technologies(host, normalized)

        # Store findings as vulnerabilities
        for finding in results.get("findings", []):
            self.ctx.add_vulnerability({
                "title": finding.get("title", "Unknown"),
                "severity": finding.get("severity", "MEDIUM"),
                "location": finding.get("location", ""),
                "details": finding.get("details", ""),
                "source_agent": self.agent_id,
                "type": finding.get("type", "unknown"),
            })
    def _build_step_prompt(self, step: int) -> str:
        """Build LLM prompt for next step"""
        
        # Objective
        obj_section = f"OBJECTIVE: {self.objective}\n"
        
        # Context from brain
        ctx_section = f"CONTEXT:\n{self.agent_context}\n"
        
        # History (last 3 steps)
        hist_section = ""
        if self.history:
            hist_section = "RECENT EXECUTION HISTORY:\n"
            for h in self.history[-3:]:
                status = "✓" if h.get("success") else "✗"
                out = h.get("output", "")[:80].replace("\n", " ")
                hist_section += f"  {status} {h['tool']}: {out}\n"
        
        # Available tools
        tools_list = ", ".join(self.allowed_tools[:10])
        if len(self.allowed_tools) > 10:
            tools_list += f", ... ({len(self.allowed_tools) - 10} more)"
        
        tools_section = f"\nAVAILABLE TOOLS: {tools_list}\n"
        
        # Failed tools warning
        failed_section = ""
        if self.failed_tools:
            failed_section = f"\nFAILED (skip these): {', '.join(self.failed_tools)}\n"
        
        # Build full prompt
        prompt = f"""{obj_section}
    {ctx_section}
    {hist_section}
    {tools_section}
    {failed_section}

    STEP {step + 1}/{self.max_steps}

    RULES:
    1. Run ONE tool per step
    2. After tool runs, analyze output
    3. When objective is COMPLETE, return action="done" with results
    4. Only use tools from AVAILABLE TOOLS list
    5. Respond ONLY with valid JSON (no markdown, no backticks)

    JSON FORMAT:
    {{
    "thinking": "what you learned and next step",
    "action": "run_tool" or "done",
    "tool": "tool_name",
    "command": "exact command",
    "timeout": 120,
    "results": {{"summary": "...", "data": {{...}}}}  // only when action=done
    }}"""
        
        return prompt