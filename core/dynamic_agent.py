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
  "operation": "operation_name (e.g. technology_detection, port_scan, etc.)",
  "params": {
    "target": "target domain, host, or URL",
    "port": 443
  },
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
- ONE tool per step, and ALWAYS include structured "params" when action is "run_tool"
- Do NOT retry failed tools
- Use structured domain tools only (e.g. nmap, subfinder, httpx, sslscan, whatweb, gobuster)
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
        agent_context: str = "",                  # Pre-filtered context from brain
        allowed_tools: Optional[List[str]] = None, # Which tools this agent can use
        max_steps: int = 10,
    ):
        self.agent_id = agent_id
        self.objective = objective
        self.tools = tool_registry
        self.ctx = shared_context
        self.agent_context = agent_context
        self.allowed_tools = allowed_tools or []
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
            
            # Check for common failure patterns (only if the tool returned success=False)
            has_failed = not result.get("success", False)
            error_msg = str(result.get("error") or "").lower()
            
            if has_failed and any(x in error_msg for x in ["not found", "failed to install", "no such file",
                                                           "not available", "could not be installed",
                                                           "command not found", "no installation candidate"]):
                # Tool missing. Don't blacklist immediately — let the LLM reason over
                # the error and try to install it another way (up to N attempts).
                attempts = self.install_attempts.get(tool_name, 0) + 1
                self.install_attempts[tool_name] = attempts
                raw_err = result.get("error") or ""

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
                # Tool errored but might be transient (full error -> file, console trims)
                logger.warning(f"[{self.agent_id}] Tool '{tool_name}' error: {result.get('error')}")
                # Don't cache yet (might be transient)
                return result

            # Success — record full tool output (console handler trims for display)
            out = result.get("output") or ""
            if out:
                logger.info(f"[{self.agent_id}] {tool_name} output:\n{out}")
            self.step_without_progress = 0
            return result
            
        except Exception as e:
            logger.error(f"[{self.agent_id}] Tool '{tool_name}' exception: {e}")
            self.failed_tools.add(tool_name)
            return {"error": str(e), "status": "exception"}
 

    async def execute(self):
        """Execute objective via CapabilityResolver and ExecutionPlanner on the Tool Intelligence platform"""
        from core.capability_worker import CapabilityWorker
        from core.normalizer import PlannerResponseNormalizer
        from core.task_evaluator import TaskCompletionEvaluator, CompletionStatus
        from core.tool_intelligence import TargetContext
        from core.capability_resolver import CapabilityResolver
        from core.execution_planner import ExecutionPlanner

        # 1. Normalize target and resolve canonical capability
        raw_target = self.ctx.target if hasattr(self.ctx, "target") else "unknown"
        target_ctx = TargetContext.from_target(raw_target)
        
        task_spec = PlannerResponseNormalizer._normalize_task_spec({
            "objective": self.objective,
            "target": target_ctx.url or target_ctx.hostname or raw_target
        })
        capability = task_spec.capability
        target = task_spec.inputs.get("target") or target_ctx.url or target_ctx.hostname

        logger.info(f"[{self.agent_id}] Dynamic agent executing capability={capability.value} target={target}")

        # 2. Dynamic Capability Resolution (no hardcoded tools)
        resolver = CapabilityResolver()
        resolved_tools = resolver.resolve_tools(
            capability=capability.value,
            objective=self.objective,
            task_spec=task_spec
        )

        # 3. Execute capability workflow via CapabilityWorker
        worker = CapabilityWorker(
            agent_id=self.agent_id,
            tool_registry=self.tools,
            shared_context=self.ctx
        )

        agent_result = await worker.execute_capability(
            capability=capability,
            target=target,
            task_id=task_spec.task_id,
            objective=self.objective,
            params=task_spec.inputs
        )

        # 3. Deterministic evaluation with TaskCompletionEvaluator
        has_extracted_data = any(bool(v) for obs in agent_result.observations for v in obs.get("data", {}).values() if isinstance(v, (list, dict, set)))
        tool_results_dicts = [
            {
                "success": has_extracted_data or agent_result.status == "completed",
                "data": obs.get("data", {}),
                "warnings": obs.get("warnings", []),
                "status": agent_result.status
            }
            for obs in agent_result.observations
        ]
        comp_status, comp_reason = TaskCompletionEvaluator.evaluate(
            spec=task_spec,
            tool_results=tool_results_dicts,
            agent_result=agent_result.dict() if agent_result.status != "failed" else None
        )

        if comp_status == CompletionStatus.SUCCEEDED:
            logger.info(f"[{self.agent_id}] Task completed deterministically via TaskCompletionEvaluator: {comp_reason}")
            return {
                "status": "success",
                "steps": 1,
                "results": {
                    "summary": f"Capability {capability.value} completed successfully on {target}",
                    "data": {k: v for obs in agent_result.observations for k, v in obs.get("data", {}).items()}
                }
            }
        elif comp_status == CompletionStatus.PARTIAL:
            logger.info(f"[{self.agent_id}] Task partially completed via TaskCompletionEvaluator: {comp_reason}")
            return {
                "status": "partial",
                "steps": 1,
                "results": {
                    "summary": f"Capability {capability.value} partially completed on {target}",
                    "data": {k: v for obs in agent_result.observations for k, v in obs.get("data", {}).items()}
                }
            }

        logger.warning(f"[{self.agent_id}] Task failed to meet success criteria: {comp_reason}")
        return {
            "status": "failed",
            "reason": comp_reason,
            "steps": 1,
            "summary": f"Capability {capability.value} failed on {target}"
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


# Dynamic Agent + Tool Intelligence alias
ControlledDynamicAgent = DynamicAgent