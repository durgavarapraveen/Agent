"""
AgentSpawner - Creates agents from brain decisions.

Two agent types:
  1. DynamicAgent     — generic LLM-driven (recon, analysis, misc)
  2. UniversalExploit — LLM-driven exploitation for ANY vuln type
     Brain just says "exploit XSS" or "exploit SQLi" — agent handles it.
"""

import logging
from typing import Dict, Union

from core.orchestration.dynamic_agent import DynamicAgent
from core.tools.tool_registry import ToolRegistry
from core.memory.shared_context import SharedContext
from core.common.schemas import CapabilityType

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
        objective = spec.get("objective", "")
        allowed_tools = spec.get("tools", [])
        context_keys = spec.get("context_keys", ["target"])
        max_steps = spec.get("max_steps", 10)
        vuln_type = spec.get("vuln_type", "")
        target_params = spec.get("target_params", [])

        # Parameter-aware gravity vector calculation
        capability_name = str(spec.get("capability") or spec.get("vuln_type") or "general").lower().strip()
        # Extract raw target without fallback to check validity
        raw_target = spec.get("target") or spec.get("inputs", {}).get("target")

        # Validate Target Before Dedup
        if not raw_target or not str(raw_target).strip():
            logger.info(f"DEDUP_VALIDATION_FAILED: target={raw_target!r} or empty, forcing fresh spawn")
            skip_dedup = True
        else:
            skip_dedup = False

        inputs_target = spec.get("target") or spec.get("inputs", {}).get("target") or spec.get("url") or spec.get("inputs", {}).get("url") or spec.get("subdomain") or spec.get("inputs", {}).get("subdomain")
        exact_target = str(inputs_target or raw_target or (self.ctx.target if hasattr(self.ctx, "target") else "")).lower().strip()
        if "://" in exact_target:
            exact_target = exact_target.split("://", 1)[1]
        if "/" in exact_target:
            exact_target = exact_target.split("/", 1)[0]

        target_val = exact_target
        subdomain_val = str(spec.get("subdomain") or spec.get("inputs", {}).get("subdomain") or "").lower().strip()
        port_val = str(spec.get("port") or spec.get("inputs", {}).get("port") or "").strip()
        ip_val = str(spec.get("ip") or spec.get("inputs", {}).get("ip") or "").strip()
        params = spec.get("target_params") or spec.get("inputs") or spec.get("params") or {}
        if isinstance(params, list):
            sorted_params = ",".join(sorted(str(x) for x in params))
        elif isinstance(params, dict):
            sorted_params = ",".join(f"{k}={v}" for k, v in sorted(params.items()))
        else:
            sorted_params = str(params)

        import hashlib
        import re
        ctx_hash = hashlib.md5(",".join(sorted(context_keys)).encode("utf-8")).hexdigest()[:8]
        obj_clean = re.sub(r'\s+', ' ', (objective or "").lower().strip())
        tools_str = ",".join(sorted(str(t).lower().strip() for t in allowed_tools))
        obj_hash = hashlib.md5(f"{obj_clean}:{tools_str}".encode("utf-8")).hexdigest()[:8]
        gravity_vector = f"{capability_name}:{target_val}:{subdomain_val}:{port_val}:{ip_val}:{sorted_params}:{ctx_hash}:{obj_hash}"

        logger.info(f"GRAVITY_VECTOR: task='{objective[:50]}' vector='{gravity_vector}'")

        from core.memory.dedup_tracker import DeduplicationTracker
        dedup = DeduplicationTracker()

        # Only compare gravity vectors when target field is populated and valid
        if not skip_dedup and dedup.is_duplicate(tool="spawner", finding_type="task_gravity", data=gravity_vector):
            logger.info(f"TASK_DEDUPLICATED: target='{target_val}' objective='{objective[:60]}' gravity='{gravity_vector}' (already spawned)")
            return None

        if not skip_dedup:
            dedup.register_finding(tool="spawner", finding_type="task_gravity", data=gravity_vector)

        self.counter += 1
        agent_id = f"AGENT-{self.counter:03d}"

        logger.info(f"SPAWN_ATTEMPT: agent_id={agent_id} capability={capability_name} objective='{objective[:60]}'")

        # BUG-004: Disambiguate objective type (RECON vs EXPLOIT)
        recon_keywords = ["analyze", "discover", "enumerate", "extract", "scan", "fingerprint", "crawl"]
        is_explicit_recon = any(kw in objective.lower() for kw in recon_keywords)
        is_exploit_kw = any(kw in objective.lower() for kw in EXPLOIT_KEYWORDS)

        if vuln_type:
            is_exploit = True
        elif is_explicit_recon and is_exploit_kw:
            logger.warning(f"OBJECTIVE_AMBIGUOUS: '{objective}' - selecting Dynamic Recon Agent (safest)")
            is_exploit = False
        else:
            is_exploit = is_exploit_kw

        # Exploit agents always get the intercepted request inventory + endpoints
        # so they can replay/fuzz real requests rather than guessing.
        if is_exploit:
            for k in ("captured_requests", "endpoints"):
                if k not in context_keys:
                    context_keys = list(context_keys) + [k]

        # Pre-Spawn Agent Validation
        valid_capabilities = {c.value for c in CapabilityType} | {c.name.lower() for c in CapabilityType} | {"general", "exploit", "recon", "dynamic"}
        if capability_name and capability_name not in valid_capabilities:
            logger.error(f"AGENT_VALIDATION_FAILED: capability='{capability_name}' is not in valid_capabilities")
            return None

        # Fallback capability tool mapping
        default_capability_tools = {
            "dns_enumeration": ["subfinder", "amass", "dns_lookup", "httpx"],
            "port_scanning": ["nmap", "port_check"],
            "endpoint_discovery": ["gobuster", "feroxbuster", "ffuf", "katana", "http_request", "curl"],
            "technology_fingerprinting": ["httpx", "whatweb", "http_request"],
            "http_analysis": ["http_request", "curl", "sslscan"],
            "javascript_analysis": ["http_request", "katana", "curl"],
            "tls_analysis": ["sslscan", "openssl", "http_request"],
            "authentication_testing": ["http_request", "curl", "hydra"],
            "vulnerability_scanning": ["nuclei", "http_request", "payload_tester", "curl"],
            "web_crawling": ["katana", "http_request", "browser"]
        }

        if not allowed_tools and not is_exploit:
            try:
                from core.orchestration.capability_resolver import CapabilityResolver
                resolver = CapabilityResolver()
                resolved = resolver.resolve_tools(capability=capability_name, objective=objective)
                if resolved:
                    allowed_tools = [t.name for t in resolved]
            except Exception as e:
                logger.warning(f"Failed resolving tools for capability '{capability_name}': {e}")

        if not allowed_tools and not is_exploit:
            allowed_tools = default_capability_tools.get(capability_name, ["http_request", "curl"])
            logger.info(f"CAPABILITY_TOOL_FALLBACK: capability='{capability_name}' resolved tools={allowed_tools}")

        if not allowed_tools and not is_exploit:
            logger.error(f"AGENT_VALIDATION_FAILED: tools list is empty for agent task '{objective[:50]}'")
            return None

        # Build filtered context
        agent_context = self.ctx.get_context_for_agent(objective, context_keys)
        valid_context_keys = {"target", "scope", "subdomains", "ips", "ports", "technologies",
                              "endpoints", "captured_requests", "parameters", "directories",
                              "headers", "js_files", "secrets", "ssl_info", "vulnerabilities",
                              "attack_chains", "exploit_results"}
        missing_keys = [k for k in context_keys if k not in valid_context_keys and not hasattr(self.ctx, k)]
        if missing_keys:
            logger.error(f"AGENT_VALIDATION_FAILED: missing context_keys={missing_keys} in context dict")
            return None

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

        executor = getattr(agent, "executor", None) or getattr(self.tools, "execute", None) or "local"
        if executor is None:
            logger.error(f"AGENT_VALIDATION_FAILED: executor is None for agent_id={agent_id}")
            return None

        logger.info(f"SPAWN_SUCCESS: agent_id={agent_id} label='{agent_label}' capability={capability_name} tools={len(allowed_tools)}")
        return agent

    def _spawn_exploit(self, agent_id, objective, agent_context,
                        vuln_type, target_params, max_steps):
        """Create UniversalExploitAgent"""
        from agents.exploit_agent import UniversalExploitAgent
        from core.common.config import get_config

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