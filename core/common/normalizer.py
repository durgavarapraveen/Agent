
import json
import logging
from uuid import uuid4
from typing import Dict, Any, Union
from core.common.schemas import BrainDecision, BrainDecisionAction, TaskSpec, CapabilityType, SuccessCriterion, SuccessCriterionType
from core.common.exceptions import AutonomousPentestException

logger = logging.getLogger(__name__)


class PlannerSchemaError(AutonomousPentestException):
    pass


class PlannerResponseNormalizer:

    @classmethod
    def _loads_lenient(cls, text: str):
        import re as _re
        if not text or not text.strip():
            return None
        t = text.strip()

        # 1. Strip a ```json ... ``` (or ``` ... ```) fence if present.
        fence = _re.search(r"```(?:json)?\s*(.*?)```", t, _re.DOTALL)
        if fence:
            t = fence.group(1).strip()

        # 2. Direct parse.
        try:
            return json.loads(t)
        except Exception:
            pass

        # 3. Extract balanced {...} blocks and pick the best one.
        #    Scoring: prefer objects with plan-relevant keys (action/agents/tasks),
        #    then by number of keys, then by size. This avoids picking empty `{}`
        #    or small example snippets from chain-of-thought reasoning.
        _PLAN_KEYS = {"action", "agents", "tasks", "agent_specs", "agent_spec", "task_spec"}
        candidates = []
        start = t.find('{')
        while start != -1:
            depth = 0
            in_str = False
            esc = False
            for i in range(start, len(t)):
                ch = t[i]
                if in_str:
                    if esc:
                        esc = False
                    elif ch == '\\':
                        esc = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                elif ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        try:
                            obj = json.loads(t[start:i + 1])
                            if isinstance(obj, dict):
                                has_plan_keys = len(set(obj.keys()) & _PLAN_KEYS)
                                num_keys = len(obj)
                                size = i - start + 1
                                candidates.append((has_plan_keys, num_keys, size, obj))
                        except Exception:
                            pass
                        break
            start = t.find('{', start + 1)
        if candidates:
            candidates.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
            return candidates[0][3]
        return None

    @classmethod
    def normalize(cls, raw: Union[Dict[str, Any], str, None]) -> BrainDecision:
        if raw is None:
            logger.warning("PLANNER_DECISION_REJECTED: Empty response received from planner")
            raise PlannerSchemaError("Empty response from planner")

        if isinstance(raw, BrainDecision):
            return raw

        if isinstance(raw, str):
            parsed = cls._loads_lenient(raw)
            if parsed is None:
                logger.error("PLANNER_DECISION_REJECTED: Invalid JSON (no JSON object found in response)")
                logger.debug(f"RAW_LLM_RESPONSE (first 500 chars): {raw[:500]}")
                raise PlannerSchemaError("Invalid JSON from planner: no JSON object found")
            raw = parsed
            logger.debug(f"PARSED_LLM_JSON keys={list(raw.keys()) if isinstance(raw, dict) else type(raw).__name__}")

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
                logger.error(f"PLANNER_DECISION_REJECTED: Final agents/tasks array is empty after normalization")
                logger.warning(f"PLANNER_DEBUG: action='{raw_action}' raw_tasks_count={len(raw_tasks)} raw_keys={list(raw.keys())}")
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

    # Known tool binaries the planner may name in an objective.
    KNOWN_TOOLS = (
        "subfinder", "amass", "assetfinder", "dnsenum", "fierce", "httpx", "whatweb",
        "wafw00f", "nmap", "masscan", "rustscan", "nuclei", "nikto", "sqlmap", "wpscan",
        "dalfox", "katana", "gau", "waybackurls", "gobuster", "feroxbuster", "ffuf",
        "dirsearch", "dirb", "sslscan", "sslyze", "hydra", "john", "hashcat",
        "theharvester", "arjun", "paramspider", "dig", "whois",
    )

    @classmethod
    def _extract_tools_from_text(cls, text: str) -> list:
        import re as _re
        if not text:
            return []
        low = text.lower()
        found = [t for t in cls.KNOWN_TOOLS if _re.search(r'\b' + _re.escape(t) + r'\b', low)]
        return found

    @classmethod
    def _normalize_task_spec(cls, data: Dict[str, Any]) -> TaskSpec:
        objective = data.get("objective") or data.get("goal") or data.get("description") or "Unspecified task"
        
        # Determine capability: prioritize objective text keyword inference first
        capability = cls._infer_capability(objective, data)

        # Log capability selection
        logger.info(f"CAPABILITY_SELECTED: capability={capability.value} objective='{objective}'")

        # Dependencies
        deps = data.get("dependencies") or data.get("depends_on") or []
        if isinstance(deps, str):
            deps = [deps]

        # Max steps / retries
        max_steps = data.get("max_steps") or data.get("max_retries") or 10
        max_retries = data.get("max_retries") or data.get("max_steps") or 3

        # Inputs - move raw 'tools' to 'tools_hint' (advisory only; the framework's
        # ToolRouter still picks the actual tool). Keeping it: (a) lets the router prefer
        # the requested tool, and (b) makes distinct tools (subfinder vs amass) produce
        # distinct task signatures so they aren't wrongly deduplicated into one run.
        inputs = data.get("inputs") or {}
        if not inputs and "target" in data:
            inputs["target"] = data["target"]
        if "params" in data and isinstance(data["params"], dict):
            inputs.update(data["params"])
        # Also capture a top-level 'tools' hint from the task spec, not just inputs.
        _raw_tools = inputs.pop("tools", None) or data.get("tools")
        if _raw_tools:
            inputs["tools_hint"] = _raw_tools if isinstance(_raw_tools, list) else [_raw_tools]
        else:
            # Fallback: the planner often names the tool only in the objective text
            # ("...using amass...", "...using subfinder..."). Extract it so distinct
            # tools produce distinct task signatures (avoiding wrong dedup) and the
            # router can honor the preference.
            _extracted = cls._extract_tools_from_text(objective)
            if _extracted:
                inputs["tools_hint"] = _extracted

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
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.PORT_SCANNING.value} via tools_hint")
            return CapabilityType.PORT_SCANNING
        if any(t in ("subfinder", "amass", "dig", "assetfinder") for t in tools_hint):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.DNS_ENUMERATION.value} via tools_hint")
            return CapabilityType.DNS_ENUMERATION
        if any(t in ("gobuster", "feroxbuster", "ffuf") for t in tools_hint):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.ENDPOINT_DISCOVERY.value} via tools_hint")
            return CapabilityType.ENDPOINT_DISCOVERY
        if any(t in ("katana", "gau", "waybackurls") for t in tools_hint):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.WEB_CRAWLING.value} via tools_hint")
            return CapabilityType.WEB_CRAWLING
        if any(t in ("whatweb", "wafw00f", "httpx") for t in tools_hint):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.TECHNOLOGY_FINGERPRINTING.value} via tools_hint")
            return CapabilityType.TECHNOLOGY_FINGERPRINTING
        if any(t in ("nuclei", "sqlmap", "nikto", "wpscan", "dalfox") for t in tools_hint):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.VULNERABILITY_SCANNING.value} via tools_hint")
            return CapabilityType.VULNERABILITY_SCANNING
        if any(t in ("sslscan", "sslyze") for t in tools_hint):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.TLS_ANALYSIS.value} via tools_hint")
            return CapabilityType.TLS_ANALYSIS
        if any(t in ("hydra", "john", "hashcat") for t in tools_hint):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.AUTHENTICATION_TESTING.value} via tools_hint")
            return CapabilityType.AUTHENTICATION_TESTING

        # Check tool keywords directly mentioned in objective text
        if re.search(r'\b(?:httpx|whatweb|wafw00f)\b', obj_text):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.TECHNOLOGY_FINGERPRINTING.value} via tool_keyword")
            return CapabilityType.TECHNOLOGY_FINGERPRINTING
        if re.search(r'\b(?:nmap|masscan|rustscan)\b', obj_text):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.PORT_SCANNING.value} via tool_keyword")
            return CapabilityType.PORT_SCANNING
        if re.search(r'\b(?:subfinder|amass|assetfinder|dnsenum|fierce)\b', obj_text):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.DNS_ENUMERATION.value} via tool_keyword")
            return CapabilityType.DNS_ENUMERATION
        if re.search(r'\b(?:nuclei|nikto|sqlmap|wpscan|dalfox)\b', obj_text):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.VULNERABILITY_SCANNING.value} via tool_keyword")
            return CapabilityType.VULNERABILITY_SCANNING
        if re.search(r'\b(?:katana|gau|waybackurls)\b', obj_text):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.WEB_CRAWLING.value} via tool_keyword")
            return CapabilityType.WEB_CRAWLING
        if re.search(r'\b(?:gobuster|feroxbuster|ffuf|dirsearch|dirb)\b', obj_text):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.ENDPOINT_DISCOVERY.value} via tool_keyword")
            return CapabilityType.ENDPOINT_DISCOVERY
        if re.search(r'\b(?:sslscan|sslyze)\b', obj_text):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.TLS_ANALYSIS.value} via tool_keyword")
            return CapabilityType.TLS_ANALYSIS
        if re.search(r'\b(?:hydra|john|hashcat)\b', obj_text):
            logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={CapabilityType.AUTHENTICATION_TESTING.value} via tool_keyword")
            return CapabilityType.AUTHENTICATION_TESTING

        # Prioritized mappings with word boundary regex matching.
        # ORDER IS CRITICAL — first match wins.
        mappings = [
            # 1. Port scanning — specifically for port and service detection
            (r'\b(?:port\s+scan(?:ning)?|open\s+(?:[a-z0-9_\-]+\s+)?ports?|scan\s+(?:[a-z0-9_\-]+\s+)?ports?|port\s+and\s+service|nmap|masscan|tcp\s+scan|udp\s+scan|service\s+(?:scan|detection))\b',
             CapabilityType.PORT_SCANNING, 0.98),

            # 2. HTTP & Header Analysis — BEFORE dns_enumeration so "headers audit on subdomains" doesn't match dns
            (r'\b(?:security\s+headers?|headers?\s+audit|headers?\s+check|missing\s+headers?|csp|cors|cookie\s+(?:flag|security)|http\s+(?:security|header)|x-frame|hsts|x-content-type)\b',
             CapabilityType.HTTP_ANALYSIS, 0.97),

            # 3. TLS Analysis — BEFORE dns_enumeration so "TLS/SSL configuration" doesn't fall through
            (r'\b(?:ssl|tls|cipher|certificate|sslscan|sslyze|openssl|starttls|weak\s+(?:cipher|ssl|tls))\b',
             CapabilityType.TLS_ANALYSIS, 0.96),

            # 4. Vulnerability scanning & Exploitation
            (r'\b(?:exploit|payload|vuln|vulnerability|nuclei|cve|sqli|rce|idor|ssrf|xss|lfi|rfi|ssti|xxe|injection|upload\s+bypass)\b',
             CapabilityType.VULNERABILITY_SCANNING, 0.95),

            # 5. Subdomain & DNS enumeration
            (r'\b(?:subdomain\s+(?:enum|discov|brute|scan)|enumerate\s+subdomains?|dns\s+records?|dns\s+enumeration|dns\s+lookup|resolve\s+(?:ips?|ip\s+addresses)|domain\s+enumeration|dns\s+brute|subfinder|amass|crt\.sh)\b',
             CapabilityType.DNS_ENUMERATION, 0.95),

            # 6. Endpoint & Directory discovery
            (r'\b(?:hidden\s+directories|directories|gobuster|feroxbuster|ffuf|endpoints?|crawl|katana|directory\s+(?:brute|scan|discovery))\b',
             CapabilityType.ENDPOINT_DISCOVERY, 0.95),

            # 7. Technology fingerprinting
            (r'\b(?:tech\s+stack|technology\s+stack|technologies|framework|cms|web\s+server|whatweb|wafw00f|fingerprint)\b',
             CapabilityType.TECHNOLOGY_FINGERPRINTING, 0.95),

            # 8. Authentication testing
            (r'\b(?:authenticate|login|credentials|auth_bypass|auth|brute\s+force|hydra)\b',
             CapabilityType.AUTHENTICATION_TESTING, 0.95),

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
                logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' matched_capability={cap.value} confidence={conf}")
                return cap

        # Fallback neutral capability
        logger.info(f"CAPABILITY_CLASSIFICATION: objective='{objective}' fallback_capability={CapabilityType.TECHNOLOGY_FINGERPRINTING.value} confidence=0.75")
        return CapabilityType.TECHNOLOGY_FINGERPRINTING

    @classmethod
    def _default_criteria_for_capability(cls, capability: CapabilityType) -> list[SuccessCriterion]:
        return [
            SuccessCriterion(
                criterion_type=SuccessCriterionType.TOOL_SUCCESS,
                capability=capability.value
            )
        ]
