"""
DynamicAgent - Generic LLM-driven agent.
No hardcoded logic. LLM decides what tool to run, reads output, repeats.
Gets ONLY the context the brain decided is relevant.
"""

import json
import logging
import re
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

    async def execute(self) -> Dict:
        """Run agent loop: think → tool → think → tool → done"""
        logger.info(f"[{self.agent_id}] Starting: {self.objective}")
        self.ctx.log_agent(self.agent_id, self.objective, "RUNNING")

        # Build tool descriptions for this agent
        tool_desc = "\n".join(
            f"- {name}: {self.tools.get(name).description}"
            for name in self.allowed_tools
            if self.tools.get(name)
        )

        step = 0
        while step < self.max_steps:
            step += 1

            # Build prompt with history
            history_str = ""
            if self.history:
                history_str = "\n\nPREVIOUS STEPS:\n"
                for h in self.history[-5:]:  # Last 5 steps only
                    output_preview = h.get("output", "")[:800]
                    history_str += (
                        f"\nStep {h['step']}: {h['tool']} → "
                        f"{'OK' if h['success'] else 'FAIL'}\n"
                        f"Output: {output_preview}\n"
                    )

            prompt = (
                f"OBJECTIVE: {self.objective}\n\n"
                f"CONTEXT:\n{self.agent_context}\n\n"
                f"AVAILABLE TOOLS:\n{tool_desc}\n"
                f"{history_str}\n\n"
                f"Step {step}/{self.max_steps}. What's next?"
            )

            # Ask LLM
            decision = await self.llm.generate_json(
                prompt,
                system=AGENT_SYSTEM_PROMPT,
                tier=TaskTier.SMALL,
                max_tokens=1500,
            )

            if not decision:
                logger.warning(f"[{self.agent_id}] LLM returned empty, retrying...")
                continue

            action = decision.get("action", "done")
            thinking = decision.get("thinking", "")

            logger.info(f"[{self.agent_id}] Step {step}: {thinking[:100]}...")

            # ── DONE ──
            if action == "done":
                results = decision.get("results", {})
                logger.info(f"[{self.agent_id}] Complete: {results.get('summary', '')[:100]}")
                self._store_results(results)
                self.ctx.log_agent(self.agent_id, self.objective, "DONE",
                                    results.get("summary", ""))
                return results

            # ── RUN TOOL ──
            if action == "run_tool":
                tool_name = decision.get("tool", "")
                command = decision.get("command", "")
                timeout = decision.get("timeout", 120)

                if tool_name not in self.allowed_tools:
                    logger.warning(f"[{self.agent_id}] Tool '{tool_name}' not allowed")
                    self.history.append({
                        "step": step, "tool": tool_name,
                        "success": False, "output": f"Tool not allowed: {tool_name}"
                    })
                    continue

                tool = self.tools.get(tool_name)
                if not tool:
                    self.history.append({
                        "step": step, "tool": tool_name,
                        "success": False, "output": f"Tool not found: {tool_name}"
                    })
                    continue

                # Execute
                try:
                    if hasattr(tool, 'run') and 'command' in tool.run.__code__.co_varnames:
                        result = tool.run(command=command, timeout=timeout)
                    else:
                        result = tool.run(**json.loads(command) if command.startswith("{") else {"command": command})
                except Exception as e:
                    result = ToolResult(success=False, error=str(e))

                self.history.append({
                    "step": step,
                    "tool": tool_name,
                    "command": command,
                    "success": result.success,
                    "output": result.output[:2000],
                    "error": result.error[:500] if result.error else "",
                })

                # Store raw output
                self.ctx.store_raw(f"{self.agent_id}_step{step}", result.output)

        # Max steps reached
        logger.warning(f"[{self.agent_id}] Max steps ({self.max_steps}) reached")
        self.ctx.log_agent(self.agent_id, self.objective, "MAX_STEPS")
        return {"summary": "Max steps reached", "data": {}, "findings": []}

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
            self.ctx.add_technologies(host, data["technologies"])

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