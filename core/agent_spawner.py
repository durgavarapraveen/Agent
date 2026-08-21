"""
AgentSpawner - Creates agents from brain decisions.

Two agent types:
  1. DynamicAgent     — generic LLM-driven (recon, analysis, misc)
  2. UniversalExploit — LLM-driven exploitation for ANY vuln type
     Brain just says "exploit XSS" or "exploit SQLi" — agent handles it.
"""

import logging
from typing import Dict, Union

from core.dynamic_agent import DynamicAgent
from core.tool_registry import ToolRegistry
from core.shared_context import SharedContext

logger = logging.getLogger(__name__)

# Keywords that trigger the universal exploit agent
EXPLOIT_KEYWORDS = [
    "exploit", "xss", "sqli", "sql injection", "lfi", "rce",
    "command injection", "ssrf", "idor", "xxe", "ssti",
    "template injection", "file inclusion", "path traversal",
    "code execution", "open redirect", "cors", "auth bypass",
    "file upload", "deserialization", "cve-", "vulnerability",
    "injection", "bypass",
]


class AgentSpawner:
    """Creates agents on-the-fly from brain decisions"""

    def __init__(self, tool_registry: ToolRegistry, shared_context: SharedContext):
        self.tools = tool_registry
        self.ctx = shared_context
        self.counter = 0

    def spawn(self, spec: Dict) -> Union[DynamicAgent, object]:
        """
        Brain provides spec:
        {
            "objective": "Exploit SQL injection in login form",
            "tools": ["http_request", "sqlmap"],
            "context_keys": ["target", "endpoints", "vulnerabilities"],
            "max_steps": 15,
            "vuln_type": "sqli",         ← optional, auto-detected if missing
            "target_params": [...]        ← optional, injection points
        }

        If objective matches exploitation → UniversalExploitAgent
        Otherwise → generic DynamicAgent (recon, analysis, etc.)
        """
        self.counter += 1
        agent_id = f"AGENT-{self.counter:03d}"

        objective = spec.get("objective", "")
        allowed_tools = spec.get("tools", [])
        context_keys = spec.get("context_keys", ["target"])
        max_steps = spec.get("max_steps", 10)
        vuln_type = spec.get("vuln_type", "")
        target_params = spec.get("target_params", [])

        # Decide: exploitation or generic?
        is_exploit = (
            vuln_type
            or any(kw in objective.lower() for kw in EXPLOIT_KEYWORDS)
        )

        # Exploit agents always get the intercepted request inventory + endpoints
        # so they can replay/fuzz real requests rather than guessing.
        if is_exploit:
            for k in ("captured_requests", "endpoints"):
                if k not in context_keys:
                    context_keys = list(context_keys) + [k]

        # Build filtered context
        agent_context = self.ctx.get_context_for_agent(objective, context_keys)

        if is_exploit:
            agent = self._spawn_exploit(
                agent_id, objective, agent_context,
                vuln_type, target_params, max_steps
            )
            agent_label = f"exploit:{agent.vuln_type}"
        else:
            agent = DynamicAgent(
                agent_id=agent_id,
                objective=objective,
                tool_registry=self.tools,
                shared_context=self.ctx,
                agent_context=agent_context,
                allowed_tools=allowed_tools,
                max_steps=max_steps,
            )
            agent_label = "dynamic"

        logger.info(
            f"Spawned {agent_id} [{agent_label}]: {objective[:60]}..."
        )
        return agent

    def _spawn_exploit(self, agent_id, objective, agent_context,
                        vuln_type, target_params, max_steps):
        """Create UniversalExploitAgent"""
        from agents.exploit_agent import UniversalExploitAgent
        from core.config import get_config

        config = get_config()
        tier = config.get("MAX_EXPLOITATION_TIER", "POC")

        return UniversalExploitAgent(
            agent_id=agent_id,
            objective=objective,
            tool_registry=self.tools,
            shared_context=self.ctx,
            agent_context=agent_context,
            vuln_type=vuln_type,
            target_params=target_params,
            max_steps=max_steps,
            tier=tier,
        )