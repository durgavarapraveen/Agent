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
        """Execute tool with smart failure handling"""
        
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
                logger.warning(f"[{self.agent_id}] No progress for 3 steps, giving up")
                return {
                    "status": "failed",
                    "reason": "no_progress",
                    "steps": step,
                    "summary": "Could not make progress on objective"
                }
            
            # Get next action from LLM
            prompt = self._build_step_prompt(step)
            decision = await self.llm.generate_json(prompt)
            
            if not decision:
                self.step_without_progress += 1
                logger.warning(f"[{self.agent_id}] LLM returned empty (no progress counter: {self.step_without_progress})")
                await asyncio.sleep(2)
                continue
            
            # Extract tool and params
            tool = decision.get("tool", "")
            params = decision.get("params", {})
            
            # Skip if it's a failed tool
            if tool in self.failed_tools:
                logger.warning(f"[{self.agent_id}] LLM suggested failed tool '{tool}', instructing to try different approach")
                # Tell LLM this tool doesn't work
                self.step_without_progress += 1
                continue
            
            # Execute tool
            if tool:
                result = await self.execute_tool(tool, params)
                
                if "error" in result and "failed_previously" not in result.get("error", ""):
                    self.step_without_progress += 1
                else:
                    self.step_without_progress = 0
            
            step += 1
            await asyncio.sleep(1)
        
        return {
            "status": "completed",
            "steps": self.max_steps,
            "summary": self.ctx.get("last_result", "Unknown")
        }
    
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