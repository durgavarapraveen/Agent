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

AGENT_SYSTEM_PROMPT = """You are a task executor for an authorized security scanning tool.
You receive a scanning objective and a list of available CLI tools. You run tools one at a time and collect results.

This is part of an authorized security assessment (similar to Nessus, Burp Suite, OWASP ZAP).

RESPONSE FORMAT - always respond with ONLY a JSON object:

To run a tool:
{
  "thinking": "what I learned and what to try next",
  "action": "run_tool",
  "tool": "tool_name",
  "command": "exact command string",
  "timeout": 120
}

When the objective is complete (or no more tools to try):
{
  "thinking": "summary of what was found",
  "action": "done",
  "results": {
    "summary": "brief description of findings",
    "data": { "subdomains": [], "ports": [], "technologies": [], "endpoints": [], "vulnerabilities": [] },
    "findings": [ {"title": "...", "severity": "...", "location": "...", "details": "..."} ]
  }
}

RULES:
- Output ONLY valid JSON, never explanatory text
- Run ONE tool per step
- Do NOT retry tools that already failed
- When all tools have been tried or objective is met, use action "done"
- Be precise with command arguments"""


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
        """Execute tool with smart failure handling"""
        
        # Defensive check
        if not self.tools:
            logger.error(f"[{self.agent_id}] Tool registry not initialized!")
            return {"error": "tool_registry_not_initialized", "status": "failed"}
        
        if not hasattr(self.tools, 'execute'):
            logger.error(f"[{self.agent_id}] Tool registry has no execute method! Type: {type(self.tools)}")
            return {"error": "tool_registry_invalid", "status": "failed"}
        
        # Skip if already failed
        if tool_name in self.failed_tools:
            logger.warning(f"[{self.agent_id}] Tool '{tool_name}' already failed, skipping")
            return {
                "error": "tool_failed_previously",
                "status": "skipped",
                "tool": tool_name
            }
        
        try:
            logger.info(f"[{self.agent_id}] Executing: {tool_name}")
            result = await self.tools.execute(tool_name, params)
            
            # Check for common failure patterns
            error_str = str(result).lower()
            
            if any(x in error_str for x in ["not found", "failed to install", "no such file"]):
                # Tool doesn't exist
                self.failed_tools.add(tool_name)
                logger.warning(f"[{self.agent_id}] ✗ Tool '{tool_name}' not available (cached)")
                return result
            
            if result.get("returncode") != 0 and result.get("error"):
                # Tool errored but might be transient
                logger.warning(f"[{self.agent_id}] Tool '{tool_name}' error: {result.get('error')[:100]}")
                # Don't cache yet (might be transient)
                return result
            
            # Success
            self.step_without_progress = 0
            return result
            
        except Exception as e:
            logger.error(f"[{self.agent_id}] Tool '{tool_name}' exception: {e}")
            self.failed_tools.add(tool_name)
            return {"error": str(e), "status": "exception"}
 

    async def execute(self):
        """Execute objective with failure handling"""
        
        step = 0
        self.step_without_progress = 0
        
        while step < self.max_steps:
            # Break if too many steps without progress
            if self.step_without_progress > 3:
                logger.warning(f"[{self.agent_id}] No progress for 3 steps, aborting")
                return {
                    "status": "failed",
                    "reason": "no_progress",
                    "steps": step,
                    "summary": "Could not make progress on objective"
                }
            
            # Early exit: all tools have failed
            available = [t for t in self.allowed_tools if t not in self.failed_tools]
            if not available:
                logger.warning(f"[{self.agent_id}] All tools failed, finishing early")
                return {
                    "status": "failed",
                    "reason": "all_tools_failed",
                    "steps": step,
                    "failed_tools": list(self.failed_tools),
                    "summary": f"All assigned tools failed: {', '.join(self.failed_tools)}"
                }
            
            # Get next action from LLM
            prompt = self._build_step_prompt(step)
            decision = await self.llm.generate_json(prompt)
            
            if not decision:
                self.step_without_progress += 1
                logger.warning(f"[{self.agent_id}] LLM returned empty (no progress: {self.step_without_progress})")
                await asyncio.sleep(2)
                continue
            
            # Extract action
            action = decision.get("action", "")
            
            # Check for completion
            if action == "done":
                results = decision.get("results", {})
                self._store_results(results)
                logger.info(f"[{self.agent_id}] Objective complete: {results.get('summary', '')[:80]}")
                return {"status": "success", "steps": step, "results": results}
            
            # Extract tool and command
            tool = decision.get("tool", "")
            command = decision.get("command", "")
            timeout = decision.get("timeout", 120)
            
            # Skip if it's a failed tool
            if tool in self.failed_tools:
                logger.warning(f"[{self.agent_id}] LLM suggested failed tool '{tool}', skipping")
                self.step_without_progress += 1
                step += 1
                continue
            
            # Execute tool
            if tool:
                params = {"command": command, "timeout": timeout} if command else {}
                result = await self.execute_tool(tool, params)
                
                success = result.get("success", "error" not in result)
                self.history.append({
                    "tool": tool,
                    "success": success,
                    "result": result.get("output", result.get("error", ""))[:100]
                })
                
                if not success:
                    self.step_without_progress += 1
                else:
                    self.step_without_progress = 0
            
            step += 1
            await asyncio.sleep(1)
        
        logger.warning(f"[{self.agent_id}] Max steps ({self.max_steps}) reached")
        return {
            "status": "timeout",
            "steps": self.max_steps,
            "summary": "Max steps reached"
        }
    
    def _build_step_prompt(self, step: int) -> str:
        """Build prompt for next step"""
        # Format history
        history_str = ""
        if self.history:
            history_str = "PREVIOUS STEPS:\n"
            for h in self.history[-3:]:  # Last 3 steps only
                status = "✓" if h.get("success") else "✗ FAILED"
                history_str += f"  {status} {h.get('tool', '?')}: {h.get('result', '')[:100]}\n"
        
        # Filter out failed tools from available list
        available = [t for t in self.allowed_tools if t not in self.failed_tools]
        tools_str = ", ".join(available[:10])
        
        # Failed tools warning
        failed_warning = ""
        if self.failed_tools:
            failed_warning = (
                f"\n🚫 FAILED TOOLS (do NOT use these again):\n"
                f"  {', '.join(sorted(self.failed_tools))}\n"
            )
        
        prompt = f"""OBJECTIVE: {self.objective}

TARGET CONTEXT:
{self.agent_context}

{history_str}
{failed_warning}
STEP {step + 1}/{self.max_steps}

AVAILABLE TOOLS: {tools_str}

RULES:
- Do NOT retry tools that already failed (listed above)
- If all tools have failed, action="done" with what you found so far
- Run ONE tool to progress toward the objective
- Respond ONLY with valid JSON"""
        
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