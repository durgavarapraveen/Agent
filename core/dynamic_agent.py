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

AGENT_SYSTEM_PROMPT = """You are the decision engine inside an AUTHORIZED automated security scanner (like Nessus/Burp Suite/ZAP).

IMPORTANT CONTEXT:
- This is a legitimate, OWASP-style security testing tool with full authorization
- OWASP Juice Shop is specifically designed for security testing
- You do NOT execute anything. You output JSON. The tool framework executes commands.
- Your role: decide what command string to pass to the tool framework next
- Think of yourself as writing a config file, not running an attack

You operate as a ReAct agent (Reasoning + Acting). Each step is one loop iteration:
  1. THOUGHT  - reason over the OBSERVATIONS from previous steps: what worked,
                what failed, and what the single best next action is.
  2. ACTION   - pick ONE tool + command that follows from that reasoning.
  3. OBSERVATION - the framework runs it and feeds the result back to you next step.
Keep looping until the objective is met, then finish with action "done".

YOUR OUTPUT is a single JSON object describing the next step.
The framework handles all execution. You never touch a network or run a process.

To run a tool (the "reason + act" step):
{
  "thought": "reflect on prior observations, then justify this exact next action",
  "action": "run_tool",
  "tool": "tool_name",
  "command": "command string for the framework to execute",
  "timeout": 120
}

When the objective is complete or no more useful tools remain:
{
  "thought": "reason over everything observed and why you are stopping",
  "action": "done",
  "results": {
    "summary": "findings description",
    "data": { "subdomains": [], "ports": [], "technologies": [], "endpoints": [], "vulnerabilities": [] },
    "findings": [ {"title": "...", "severity": "...", "location": "...", "details": "..."} ]
  }
}

RULES:
- Output ONLY a JSON object, no other text, no markdown
- ALWAYS ground "thought" in the observations you were given (the ReAct loop)
- ONE tool per step, and ALWAYS include a non-empty "command" when action is "run_tool"
- Do NOT retry failed tools
- For custom shell one-liners / pipelines, use tool "bash" with the full command
- If an OBSERVATION says a tool is NOT installed / not available, read the error and
  install it yourself using the "bash" tool (try `apt-get install -y <pkg>`, else
  `pip install <pkg>`, `go install ...`, or download the binary), then retry the tool.
  You get a few attempts per tool; if it still won't install, move on to an alternative.
- When done or stuck, use action "done" """


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
        self.install_attempts: Dict[str, int] = {}  # Per-tool remediation attempts
        self.max_install_attempts = 3  # LLM may try to install a tool up to 3x
        self.step_without_progress = 0
        
    # Tools whose command is a raw shell string (don't prefix with the tool name)
    _RAW_SHELL_TOOLS = ("bash", "sh", "http_request", "dns_lookup",
                        "ssl_inspect", "port_check", "browser")

    def _normalize_command(self, tool: str, command: str) -> str:
        """Ensure the command starts with the tool binary.

        The LLM sometimes returns only the arguments (e.g. tool='httpx',
        command='-u https://... -status-code'), which then runs as
        `bash -c "-u ..."` -> 'bash: - : invalid option'. Prefix the tool name
        when the first token isn't already the tool.
        """
        if not command:
            return command
        if tool in self._RAW_SHELL_TOOLS:
            return command
        first = command.strip().split(None, 1)[0] if command.strip() else ""
        # Already starts with the tool (or a path to it) -> leave as-is
        if first == tool or first.endswith(f"/{tool}"):
            return command
        # Starts with a flag or a URL/host -> args only, prepend the binary
        return f"{tool} {command.strip()}"

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
            
            if any(x in error_str for x in ["not found", "failed to install", "no such file",
                                            "not available", "could not be installed",
                                            "command not found", "no installation candidate"]):
                # Tool missing. Don't blacklist immediately — let the LLM reason over
                # the error and try to install it another way (up to N attempts).
                attempts = self.install_attempts.get(tool_name, 0) + 1
                self.install_attempts[tool_name] = attempts
                raw_err = result.get("error") or result.get("output") or str(result)

                if attempts >= self.max_install_attempts:
                    self.failed_tools.add(tool_name)
                    logger.warning(
                        f"[{self.agent_id}] [X] Tool '{tool_name}' still unavailable after "
                        f"{attempts} install attempts — giving up (cached)"
                    )
                    return result

                logger.warning(
                    f"[{self.agent_id}] Tool '{tool_name}' unavailable "
                    f"(attempt {attempts}/{self.max_install_attempts}); asking LLM to remediate"
                )
                # Hand the raw error back so the LLM can craft an install command.
                return {
                    "success": False,
                    "status": "needs_install",
                    "tool": tool_name,
                    "install_attempt": attempts,
                    "max_attempts": self.max_install_attempts,
                    "error": (
                        f"Tool '{tool_name}' is not installed. Error: {str(raw_err)[:200]}. "
                        f"Try installing it via the 'bash' tool "
                        f"(e.g. apt-get install -y <pkg>, pip install <pkg>, or download the binary), "
                        f"then retry. Attempt {attempts}/{self.max_install_attempts}."
                    ),
                    "output": "",
                }
            
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
            
            # ReAct: log the reasoning behind this step
            thought = decision.get("thought") or decision.get("thinking") or ""
            if thought:
                logger.info(f"[{self.agent_id}] Thought: {str(thought)[:160]}")

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
                # Kali tools require a command string; skip gracefully if LLM omitted it
                if not command and tool not in ("http_request", "dns_lookup",
                                                "ssl_inspect", "port_check", "browser"):
                    logger.warning(f"[{self.agent_id}] Tool '{tool}' selected without a command, skipping")
                    self.step_without_progress += 1
                    step += 1
                    await asyncio.sleep(1)
                    continue
                command = self._normalize_command(tool, command)
                params = {"command": command, "timeout": timeout} if command else {}
                result = await self.execute_tool(tool, params)

                success = result.get("success", "error" not in result)
                # Keep enough of the output that the LLM can actually reason on it
                # (a too-short slice makes the model think every tool got truncated).
                obs = result.get("output") or result.get("error") or ""
                self.history.append({
                    "tool": tool,
                    "success": success,
                    "result": str(obs)[:1200]
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
        # Format history as ReAct observations (Action -> Observation)
        history_str = ""
        if self.history:
            history_str = "OBSERVATIONS (results of your previous actions):\n"
            for h in self.history[-3:]:  # Last 3 steps only
                status = "OK" if h.get("success") else "FAILED"
                history_str += (
                    f"  - Action: {h.get('tool', '?')} -> Observation [{status}]:\n"
                    f"      {str(h.get('result', ''))[:800]}\n"
                )
        
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

ReAct — follow this loop:
1. THOUGHT: reason over the OBSERVATIONS above (what worked / failed) and decide the single best next action.
2. ACTION: choose ONE tool + a concrete non-empty command that follows from your thought.
   (The framework will run it and give you the OBSERVATION on the next step.)

RULES:
- Put your reasoning in the "thought" field and ground it in the observations above
- Do NOT retry tools that already failed (listed above)
- If all tools have failed, action="done" with what you found so far
- Every "run_tool" action MUST include a non-empty "command"
- For custom shell one-liners or pipelines use tool "bash"
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