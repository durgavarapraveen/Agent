"""
Planner Response Normalizer.
Eliminates planner schema drift and ensures only canonical BrainDecision/TaskSpec
flows into the TaskManager and core application.
"""

import json
import logging
from uuid import uuid4
from typing import Dict, Any, Union, Optional
from core.schemas import BrainDecision, BrainDecisionAction, TaskSpec, CapabilityType, SuccessCriterion, SuccessCriterionType
from core.exceptions import AutonomousPentestException

logger = logging.getLogger(__name__)


class PlannerSchemaError(AutonomousPentestException):
    """Raised when planner response cannot be normalized into canonical schema"""
    pass


class PlannerResponseNormalizer:
    """Canonical normalizer for LLM planner outputs"""

    @classmethod
    def normalize(cls, raw: Union[Dict[str, Any], str, None]) -> BrainDecision:
        """
        Convert raw LLM response dict/json into a canonical BrainDecision.
        Logs PLANNER_DECISION_ACCEPTED or PLANNER_DECISION_REJECTED.
        """
        if raw is None:
            logger.warning("PLANNER_DECISION_REJECTED: Empty response received from planner")
            raise PlannerSchemaError("Empty response from planner")

        if isinstance(raw, BrainDecision):
            return raw

        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception as e:
                logger.error(f"PLANNER_DECISION_REJECTED: Invalid JSON ({e})")
                raise PlannerSchemaError(f"Invalid JSON from planner: {e}")

        if not isinstance(raw, dict):
            logger.error("PLANNER_DECISION_REJECTED: Planner output is not a dictionary")
            raise PlannerSchemaError("Planner output must be a dictionary")

        try:
            # 1. Normalize action
            raw_action = raw.get("action", "spawn_agents")
            if not raw_action and "tasks" in raw:
                raw_action = "spawn_agents"
            
            action_str = str(raw_action).lower().strip()
            
            # Map legacy action strings
            action_map = {
                "spawn_tasks": BrainDecisionAction.SPAWN_AGENTS,
                "spawn_agents": BrainDecisionAction.SPAWN_AGENTS,
                "run_task": BrainDecisionAction.RUN_TASK,
                "wait": BrainDecisionAction.WAIT,
                "replan": BrainDecisionAction.REPLAN,
                "complete": BrainDecisionAction.COMPLETE,
                "phase_complete": BrainDecisionAction.COMPLETE,
                "assessment_complete": BrainDecisionAction.COMPLETE,
                "done": BrainDecisionAction.COMPLETE,
                "blocked": BrainDecisionAction.BLOCKED,
                "abort": BrainDecisionAction.BLOCKED,
            }
            
            canonical_action = action_map.get(action_str, BrainDecisionAction.SPAWN_AGENTS)

            # 2. Extract and normalize tasks list (handling agent_spec singular vs agents plural)
            singular_spec = raw.get("agent_spec") or raw.get("task_spec") or raw.get("task") or raw.get("agent")
            plural_specs = raw.get("tasks") or raw.get("agent_specs") or raw.get("agents")

            if singular_spec and not plural_specs:
                logger.warning(
                    "[PlannerNormalizer] FORMAT_CONVERSION: Brain output singular 'agent_spec'. "
                    "Auto-converting to 'agents' array."
                )
                raw_tasks = [singular_spec] if isinstance(singular_spec, dict) else singular_spec
            else:
                raw_tasks = plural_specs or []

            if isinstance(raw_tasks, dict):
                raw_tasks = [raw_tasks]
            elif not isinstance(raw_tasks, list):
                raw_tasks = [raw_tasks] if raw_tasks else []

            canonical_tasks = []
            for item in raw_tasks:
                if not isinstance(item, dict):
                    continue
                task_spec = cls._normalize_task_spec(item)
                canonical_tasks.append(task_spec)

            if canonical_action in (BrainDecisionAction.SPAWN_AGENTS, BrainDecisionAction.SPAWN_TASKS) and not canonical_tasks:
                logger.error("PLANNER_DECISION_REJECTED: Final agents/tasks array is empty after normalization")
                raise PlannerSchemaError("Action requires non-empty agents/tasks list")

            thought = raw.get("thought") or raw.get("thinking") or raw.get("reason") or ""
            reason = raw.get("reason") or thought

            decision = BrainDecision(
                action=canonical_action,
                thought=thought,
                reason=reason,
                tasks=canonical_tasks,
                wait_seconds=raw.get("wait_seconds"),
                metadata=raw.get("metadata", {})
            )

            logger.info(f"PLANNER_DECISION_ACCEPTED: action={decision.action.value}, task_count={len(decision.tasks)}")
            return decision

        except Exception as e:
            logger.error(f"PLANNER_DECISION_REJECTED: Schema validation error: {e}")
            raise PlannerSchemaError(f"Schema normalization failed: {e}")

    @classmethod
    def _normalize_task_spec(cls, data: Dict[str, Any]) -> TaskSpec:
        """Normalize an individual task specification"""
        objective = data.get("objective") or data.get("goal") or data.get("description") or "Unspecified task"
        
        # Determine capability: prioritize objective text keyword inference first
        capability = cls._infer_capability(objective, data)

        # Log capability selection
        logger.info(f"CAPABILITY_SELECTED: capability={capability.value} objective='{objective[:60]}'")

        # Dependencies
        deps = data.get("dependencies") or data.get("depends_on") or []
        if isinstance(deps, str):
            deps = [deps]

        # Max steps / retries
        max_steps = data.get("max_steps") or data.get("max_retries") or 10
        max_retries = data.get("max_retries") or data.get("max_steps") or 3

        # Inputs - strip raw 'tools' to prevent LLM tool commanding
        inputs = data.get("inputs") or {}
        if not inputs and "target" in data:
            inputs["target"] = data["target"]
        if "params" in data and isinstance(data["params"], dict):
            inputs.update(data["params"])
        if "tools" in inputs:
            del inputs["tools"]

        # Success criteria
        raw_criteria = data.get("success_criteria") or []
        criteria = []
        if isinstance(raw_criteria, list):
            for sc in raw_criteria:
                if isinstance(sc, SuccessCriterion):
                    criteria.append(sc)
                elif isinstance(sc, dict):
                    try:
                        criteria.append(SuccessCriterion(**sc))
                    except Exception:
                        pass

        # If no success criteria provided, assign default based on capability
        if not criteria:
            criteria = cls._default_criteria_for_capability(capability)

        return TaskSpec(
            task_id=data.get("task_id") or data.get("id") or str(uuid4()),
            objective=objective,
            capability=capability,
            inputs=inputs,
            dependencies=deps,
            depends_on=deps,
            success_criteria=criteria,
            timeout_seconds=data.get("timeout_seconds", 300),
            max_steps=max_steps,
            max_retries=max_retries,
            priority=data.get("priority", 5)
        )

    @classmethod
    def _infer_capability(cls, objective: str, data: Dict[str, Any]) -> CapabilityType:
        """Infer capability type with word-boundary matching and priority ranking"""
        import re
        obj_text = (objective or "").lower().strip()

        # Check explicitly supplied capability field first if valid
        raw_cap = data.get("capability")
        if isinstance(raw_cap, CapabilityType):
            return raw_cap
        elif isinstance(raw_cap, str) and raw_cap.strip():
            cap_str = raw_cap.lower().strip()
            if cap_str in ("security_headers_analyzer", "headers", "cors", "http_headers", "header_analysis"):
                return CapabilityType.HTTP_ANALYSIS
            try:
                return CapabilityType(cap_str)
            except ValueError:
                pass

        # Check tool hints in data if provided
        tools_hint = [str(t).lower() for t in (data.get("tools") or [])]
        if any(t in ("nmap", "masscan", "port_check") for t in tools_hint):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective[:60]}' matched_capability={CapabilityType.PORT_SCANNING.value} via tools_hint")
            return CapabilityType.PORT_SCANNING
        if any(t in ("subfinder", "amass", "dig") for t in tools_hint):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective[:60]}' matched_capability={CapabilityType.DNS_ENUMERATION.value} via tools_hint")
            return CapabilityType.DNS_ENUMERATION
        if any(t in ("gobuster", "feroxbuster", "ffuf", "katana") for t in tools_hint):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective[:60]}' matched_capability={CapabilityType.ENDPOINT_DISCOVERY.value} via tools_hint")
            return CapabilityType.ENDPOINT_DISCOVERY
        if any(t in ("whatweb", "wafw00f") for t in tools_hint):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective[:60]}' matched_capability={CapabilityType.TECHNOLOGY_FINGERPRINTING.value} via tools_hint")
            return CapabilityType.TECHNOLOGY_FINGERPRINTING
        if any(t in ("nuclei", "sqlmap", "nikto") for t in tools_hint):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective[:60]}' matched_capability={CapabilityType.VULNERABILITY_SCANNING.value} via tools_hint")
            return CapabilityType.VULNERABILITY_SCANNING

        # Prioritized mappings with word boundary regex matching.
        # ORDER IS CRITICAL — first match wins.
        mappings = [
            # 1. Port scanning — specifically for port and service detection
            (r'\b(?:port\s+scan(?:ning)?|open\s+(?:[a-z0-9_\-]+\s+)?ports?|scan\s+(?:[a-z0-9_\-]+\s+)?ports?|port\s+and\s+service|nmap|masscan|tcp\s+scan|udp\s+scan|service\s+(?:scan|detection))\b',
             CapabilityType.PORT_SCANNING, 0.98),

            # 2. Subdomain & DNS enumeration (Prioritize subdomain discovery objectives)
            (r'\b(?:subdomains?|dns\s+records?|dns\s+enumeration|dns\s+lookup|resolve\s+(?:ips?|ip\s+addresses)|domain\s+enumeration|dns\s+brute|subfinder|amass|crt\.sh)\b',
             CapabilityType.DNS_ENUMERATION, 0.95),

            # 3. Vulnerability scanning & Exploitation
            (r'\b(?:exploit|payload|vuln|vulnerability|nuclei|cve|sqli|rce|idor|ssrf|xss|lfi|rfi|ssti|xxe|injection|upload\s+bypass)\b',
             CapabilityType.VULNERABILITY_SCANNING, 0.95),

            # 4. Endpoint & Directory discovery
            (r'\b(?:hidden\s+directories|directories|gobuster|feroxbuster|ffuf|endpoints?|crawl|katana|directory\s+(?:brute|scan|discovery))\b',
             CapabilityType.ENDPOINT_DISCOVERY, 0.95),

            # 5. Technology fingerprinting
            (r'\b(?:tech\s+stack|technology\s+stack|technologies|framework|cms|web\s+server|whatweb|wafw00f|fingerprint)\b',
             CapabilityType.TECHNOLOGY_FINGERPRINTING, 0.95),

            # 6. Authentication testing
            (r'\b(?:authenticate|login|credentials|auth_bypass|auth|brute\s+force|hydra)\b',
             CapabilityType.AUTHENTICATION_TESTING, 0.95),

            # 7. HTTP & Header Analysis
            (r'\b(?:header|security\s+headers|csp|cors|cookie|config)\b',
             CapabilityType.HTTP_ANALYSIS, 0.95),

            # 8. TLS Analysis
            (r'\b(?:ssl|tls|cipher|certificate|sslscan|openssl|starttls)\b',
             CapabilityType.TLS_ANALYSIS, 0.95),

            # 9. JavaScript Analysis
            (r'\b(?:js|javascript|bundle|source\s+map)\b',
             CapabilityType.JAVASCRIPT_ANALYSIS, 0.90),

            # 10. Web Crawling
            (r'\b(?:web\s+crawling|spider)\b',
             CapabilityType.WEB_CRAWLING, 0.90),

            # OSINT capabilities
            (r'\b(?:employee|enumerate\s+employees|linkedin|email|staff|roles|directory)\b',
             CapabilityType.EMPLOYEE_ENUMERATION, 0.95),
            (r'\b(?:github|gitlab|bitbucket|repository|credential|secret|api.?key)\b',
             CapabilityType.GITHUB_SCANNING, 0.95),
            (r'\b(?:dns\s+intel|mx\s+record|spf\s+policy|dkim|dmarc|smtp\s+server)\b',
             CapabilityType.DNS_INTELLIGENCE, 0.90),
            (r'\b(?:certificate.?transparency|virtual.?host)\b',
             CapabilityType.SUBDOMAIN_ENUMERATION, 0.95),
            (r'\b(?:threat.?intel|abuse\.ch|shodan|censys|reputation|compromised)\b',
             CapabilityType.THREAT_INTELLIGENCE, 0.90),
        ]

        for pattern, cap, conf in mappings:
            if re.search(pattern, obj_text):
                logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective[:60]}' matched_capability={cap.value} confidence={conf}")
                return cap

        # Fallback neutral capability
        logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective[:60]}' fallback_capability={CapabilityType.TECHNOLOGY_FINGERPRINTING.value} confidence=0.75")
        return CapabilityType.TECHNOLOGY_FINGERPRINTING

    @classmethod
    def _default_criteria_for_capability(cls, capability: CapabilityType) -> list[SuccessCriterion]:
        """Return deterministic success criteria for each capability type"""
        return [
            SuccessCriterion(
                criterion_type=SuccessCriterionType.TOOL_SUCCESS,
                capability=capability.value
            )
        ]
