"""
Agentic Executor — LLM-driven tool-calling loop.

Instead of "plan N tasks → execute all → plan again", this gives the LLM
direct tool access. The LLM sees every result (stdout, stderr, errors),
reasons about what happened, adapts its strategy, chains discoveries,
and filters noise — exactly like a human pentester would.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AgenticResult:
    findings: List[Dict[str, Any]] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    steps_taken: int = 0
    total_cost: float = 0.0
    summary: str = ""
    raw_endpoints: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    errors_encountered: List[str] = field(default_factory=list)


# Tool definitions the LLM can call
from core.exploitation.custom_probe import (
    CUSTOM_PROBE_TOOL_SCHEMAS as _CUSTOM_TOOLS,
    run_custom_probe as _run_custom_probe,
    run_custom_python as _run_custom_python,
)
from core.intel.skill_library import SKILL_TOOL_SCHEMAS as _SKILL_TOOLS
from core.intel.security_kb import KB_TOOL_SCHEMA as _KB_TOOL
from core.intel.tool_authoring import (
    AUTHOR_TOOL_SCHEMA as _AUTHOR_TOOL,
    RUN_AUTHORED_TOOL_SCHEMA as _RUN_AUTHORED_TOOL,
    run_authored_tool as _run_authored_tool,
)

PENTESTING_TOOLS = _CUSTOM_TOOLS + _SKILL_TOOLS + [_KB_TOOL, _AUTHOR_TOOL, _RUN_AUTHORED_TOOL] + [
    {
        "type": "function",
        "function": {
            "name": "run_tool",
            "description": (
                "Execute a security tool against a target. The tool runs in a Kali Docker container. "
                "You will see the full stdout/stderr output. Analyze the results, adapt your strategy, "
                "and call more tools based on what you find."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tool": {
                        "type": "string",
                        "description": "Tool name: nmap, masscan, subfinder, amass, assetfinder, httpx, whatweb, "
                                       "wafw00f, nikto, nuclei, sqlmap, ffuf, gobuster, katana, dalfox, sslscan, "
                                       "wpscan, hydra, arjun, dirb, dirsearch, feroxbuster, dnsenum, fierce, "
                                       "theharvester, whois, dig, curl"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target URL, domain, or IP address"
                    },
                    "args": {
                        "type": "string",
                        "description": "Additional command-line arguments for the tool (e.g., '-p 80,443,8080' for nmap, "
                                       "'--batch --level=5' for sqlmap, '-t cve,misconfig' for nuclei)"
                    }
                },
                "required": ["tool", "target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": (
                "Make a raw HTTP request to inspect endpoints, test parameters, check headers, "
                "or verify vulnerabilities. Use this for manual testing when specialized tools aren't needed."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]},
                    "url": {"type": "string", "description": "Full URL to request"},
                    "headers": {"type": "object", "description": "Custom headers as key-value pairs"},
                    "body": {"type": "string", "description": "Request body (for POST/PUT)"},
                    "follow_redirects": {"type": "boolean", "description": "Follow HTTP redirects (default: true)"}
                },
                "required": ["method", "url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_results",
            "description": (
                "Record a finding, discovery, or insight. Call this whenever you discover something: "
                "a vulnerability, a subdomain, an interesting endpoint, a technology, or any security-relevant observation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "type": {
                        "type": "string",
                        "enum": ["vulnerability", "subdomain", "endpoint", "technology", "credential",
                                 "misconfiguration", "information", "port"],
                        "description": "Type of finding"
                    },
                    "title": {"type": "string", "description": "Short title of the finding"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "details": {"type": "string", "description": "Detailed description of what was found"},
                    "evidence": {"type": "string", "description": "Raw evidence (headers, response body snippets, etc.)"},
                    "target": {"type": "string", "description": "Specific target this finding applies to"},
                    "next_steps": {"type": "string", "description": "What should be investigated next based on this finding"}
                },
                "required": ["type", "title", "details"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "filter_endpoints",
            "description": (
                "Filter a list of discovered endpoints/URLs to keep only security-relevant ones. "
                "Removes static assets (.js, .css, .png, .svg, .woff, .ico, .map), "
                "keeps API endpoints, form handlers, authenticated pages, and parameterized URLs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "endpoints": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of URLs/endpoints to filter"
                    },
                    "keep_patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional patterns to keep (e.g., '/api/', '/admin/', '?id=')"
                    }
                },
                "required": ["endpoints"]
            }
        }
    },
]


AGENTIC_SYSTEM_PROMPT = """You are an expert penetration tester with deep knowledge of web application security.
You have direct access to security tools running in a Kali Linux container.

## How to work

1. **Think before acting**: Before each tool call, reason about what you expect to find and why.
2. **Read results carefully**: After each tool, analyze the output. Look for:
   - Vulnerabilities to exploit further
   - New endpoints or subdomains to investigate
   - Error messages that reveal technology stack
   - Misconfigurations that chain with other findings
3. **Adapt on errors**: If a tool fails or returns nothing useful:
   - Don't just retry the same thing — understand WHY it failed
   - Try a different tool for the same goal
   - Try different parameters or targets
   - The error itself may reveal information (WAF, technology, etc.)
4. **Chain discoveries**: When you find something, investigate deeper:
   - Found a subdomain? Fingerprint it, scan its ports
   - Found an API endpoint? Test it for injection, auth bypass
   - Found a technology? Check for known CVEs with nuclei
   - Found credentials? Try them on login endpoints
5. **Filter noise**: Not all endpoints matter:
   - Skip .js, .css, .png, .svg, .woff, .ico, .map files
   - Focus on: /api/*, endpoints with parameters, admin panels, login pages
   - Prioritize endpoints that accept user input
6. **Record everything**: Use analyze_results for every finding, even informational ones.
   They help build the attack surface picture.

## Tool tips
- nmap: Use -sT (TCP connect) for unprivileged scans, -Pn to skip ping
- sqlmap: Always use --batch, add --level=3 --risk=2 for thorough testing
- nuclei: Use -tags cve,misconfig,exposure for broad coverage
- nikto: Good for quick header/config checks
- httpx: Use -status-code -title -tech-detect for fingerprinting
- subfinder/amass: Run both, they find different subdomains
- ffuf/gobuster: Use for directory/endpoint brute forcing with good wordlists
- curl: Use for manual endpoint testing and header inspection

## Important rules
- NEVER scan targets outside the authorized scope
- The AUTHORIZED TARGET is: {authorized_target}
- The AUTHORIZED DOMAIN is: {authorized_domain}
- SCOPE ENFORCEMENT (CRITICAL):
  - Only scan {authorized_domain} and paths under {authorized_target}
  - Do NOT run subfinder, amass, dig, whois, theharvester, or ANY enumeration tool against a PARENT domain
  - Example: if target is "staging.app.example.org", do NOT scan "app.example.org" or "example.org"
  - Example: if target is "staging.api.example.com", do NOT scan "api.example.com" or "example.com"
  - Every tool invocation MUST target {authorized_domain} or {authorized_target} exactly
  - If a tool requires a domain, use {authorized_domain} — never strip subdomains
- Record ALL findings with analyze_results — even "info" severity
- When you've exhausted what you can do, stop. Don't repeat tools pointlessly.
- If you discover a new attack surface (subdomain, API), investigate it before moving on.
- If a tool fails with "No tools available", do NOT retry the same tool. Use http_request as a fallback for manual testing.
- **SKIP ALREADY FOUND**: If "Already Found Vulnerabilities" is listed, do NOT re-test those exact findings. Focus on NEW attack vectors, endpoints, and vulnerability types not yet covered.
- **Be concise**: Keep your reasoning brief. State what you'll do and why in 1-2 sentences, not paragraphs.
- **Stop when done**: Once you've tested the objective's scope and recorded findings, stop. Don't loop looking for more.
"""


class AgenticExecutor:
    """
    LLM-driven agentic execution loop.

    The LLM gets tools, sees every result, and drives the entire process:
    - Picks which tool to run and with what args
    - Reads stdout/stderr and reasons about the output
    - Adapts strategy based on errors and results
    - Chains discoveries into new investigations
    - Filters noise and focuses on what matters
    """

    TOOL_TIMEOUTS = {
        "fierce": 900, "amass": 900, "theharvester": 900,
        "nmap": 900, "masscan": 900, "nikto": 900,
        "sqlmap": 900, "nuclei": 900, "wpscan": 900,
        "ffuf": 900, "gobuster": 900, "feroxbuster": 900,
        "dirb": 900, "dirsearch": 900, "hydra": 900,
        "dig": 900, "subfinder": 900, "assetfinder": 900,
        "httpx": 900, "whatweb": 900, "wafw00f": 900,
        "sslscan": 900, "katana": 900, "arjun": 900,
        "dalfox": 900, "dnsenum": 900, "whois": 900,
        "curl": 900,
    }

    def __init__(self, llm_harness, tool_invocation_engine, shared_context, auth_context):
        self.llm = llm_harness
        self.tool_engine = tool_invocation_engine
        self.ctx = shared_context
        self.auth_context = auth_context
        self.result = AgenticResult()
        self._available_tools = None
        # Per-host captured JWTs, auto-injected on subsequent same-host requests
        # so the loop can actually test authenticated endpoints once login succeeds.
        # Keyed by netloc (host[:port]). Populated by _capture_auth_from_response.
        self._captured_tokens: dict = {}
        # Scan id — used by _persist_auth_bypass to link rows to the running scan
        # in the auth_bypasses table.
        self.scan_id = getattr(shared_context, "scan_id", None) or getattr(shared_context, "_scan_id", "")
        # Live-agent tracker (nullable — set by execute() so parallel launcher
        # can pass an id in from outside).
        self._tracker = None

    async def execute(
        self,
        objective: str,
        phase: str,
        max_rounds: int = 15,
        context_hint: str = "",
    ) -> AgenticResult:
        """
        Run the agentic loop for a given objective.

        The LLM drives the process — calling tools, analyzing results,
        adapting strategy, and chaining discoveries until it determines
        the objective is met or no more useful actions can be taken.
        """
        self._phase = phase or ""
        self._available_tools = self._probe_tool_availability()
        available_tools_str = ", ".join(sorted(self._available_tools)) if self._available_tools else "none (use http_request for all testing)"

        known_subdomains = ", ".join(self.ctx.subdomains[:10]) if self.ctx.subdomains else "none"
        known_endpoints = str(len(self.ctx.endpoints)) + " endpoints"
        known_techs = json.dumps(self.ctx.technologies, default=str)[:500] if self.ctx.technologies else "unknown"
        # Surface active auth so the LLM knows it holds live sessions and can
        # target authenticated attacks (basket, admin panels, IDOR across roles).
        _sessions = getattr(self.ctx, "auth_sessions", {}) or {}
        _has_bearer = bool((getattr(self.ctx, "auth_headers", {}) or {}).get("Authorization"))
        _tokens_here = list(getattr(self, "_captured_tokens", {}).keys())
        auth_state_lines = []
        if _has_bearer:
            auth_state_lines.append("- Active Bearer token loaded (auto-attached to same-host requests)")
        if _tokens_here:
            auth_state_lines.append(f"- Captured JWTs for hosts: {', '.join(_tokens_here)}")
        if _sessions:
            auth_state_lines.append(f"- Multi-role sessions available: {', '.join(sorted(_sessions.keys()))}")
        auth_state = "\n".join(auth_state_lines) if auth_state_lines else "- No authenticated session yet"

        vuln_summary = self._build_known_vulns_summary()

        # Feed prior phase summaries (this scan) so this phase builds on
        # earlier discoveries instead of starting blind.
        prior_phases_ctx = ""
        try:
            if self.scan_id:
                from core.database.pg_store import LLMMemoryRepo
                prior = LLMMemoryRepo.get_by_scan(self.scan_id, kind="summary", limit=8)
                if prior:
                    prior_phases_ctx = "## What earlier phases learned (build on this)\n" + \
                        "\n".join(f"- **{p.get('phase','phase')}**: {(p.get('content') or '')[:400]}"
                                    for p in prior) + "\n\n"
        except Exception:
            pass

        # Novel-attack directive — pushes LLM beyond the standard catalog.
        novel_attack_directive = (
            "## Beyond the standard catalog\n"
            "You are NOT limited to a fixed vulnerability catalog. After the standard "
            "coverage, propose and EXECUTE 2-3 NOVEL attacks tailored to what you've "
            "discovered about THIS specific target's stack, framework, and behaviours. "
            "Chain findings — if you confirm a weakness, immediately test what it "
            "unlocks (data exfil, session pivot, admin access, secondary injection). "
            "Use `run_custom_probe` to craft arbitrary HTTP tests when the standard "
            "tools don't cover an angle. When you confirm a vulnerability, reflect "
            "for one round: what related weakness would the same class of bug enable?\n\n"
        )

        user_message = (
            f"## Objective\n{objective}\n\n"
            f"## Phase\n{phase}\n\n"
            f"## Target\n{self.ctx.target}\n\n"
            f"## Current Knowledge\n"
            f"- Subdomains: {known_subdomains}\n"
            f"- Endpoints: {known_endpoints}\n"
            f"- Technologies: {known_techs}\n"
            f"## Authentication State\n{auth_state}\n\n"
            f"{prior_phases_ctx}"
            f"{novel_attack_directive}"
        )
        if vuln_summary:
            user_message += f"## Already Found Vulnerabilities (DO NOT re-test these)\n{vuln_summary}\n\n"
        if context_hint:
            user_message += f"## Additional Context\n{context_hint}\n\n"

        user_message += (
            f"## Available Tools (in Docker)\n"
            f"These tools are confirmed available: {available_tools_str}\n"
            f"Do NOT call run_tool with any tool NOT in this list — it will fail. "
            f"Use http_request as fallback for anything not available.\n\n"
            "Start by assessing what we know and what we need to find out. "
            "Then use the available tools to achieve the objective. "
            "Analyze every result and adapt your approach. "
            "Record all findings with analyze_results."
        )

        from urllib.parse import urlparse
        _parsed = urlparse(self.ctx.target)
        authorized_domain = _parsed.netloc or _parsed.path.split("/")[0]
        system_prompt = AGENTIC_SYSTEM_PROMPT.format(
            authorized_target=self.ctx.target,
            authorized_domain=authorized_domain,
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        logger.info(f"[AgenticExecutor] Starting: objective='{objective}' phase={phase} max_rounds={max_rounds}")

        # Register a live-agent card so the UI can show what this phase is doing.
        try:
            from core.orchestration.parallel_agents import AgentTracker
            if self._tracker is None:
                self._tracker = AgentTracker(
                    self.scan_id, agent_id=f"{phase}",
                    label=phase, phase=phase,
                    target=self.ctx.target)
            self._tracker.start(current_step=objective[:120])
        except Exception:
            pass

        response = await self.llm.generate_with_tools(
            messages=messages,
            tools=PENTESTING_TOOLS,
            tool_executor=self._execute_tool_call,
            max_rounds=max_rounds,
            max_tokens=4096,
        )

        # Expert-mode persistence: if the LLM stopped without calling more
        # tools, re-prompt up to REPROMPT_ROUNDS times asking it to enumerate
        # attack vectors it hasn't tried. An expert never says "I'm done" —
        # they always try more angles.
        REPROMPT_ROUNDS = 3
        for i in range(REPROMPT_ROUNDS):
            steps_before = self.result.steps_taken
            reprompt_messages = list(messages)
            reprompt_messages.append({"role": "assistant", "content": response.content or ""})
            reprompt_messages.append({
                "role": "user",
                "content": (
                    "You stopped calling tools. Before you finish, an expert pentester with "
                    "20 years of experience would still try more angles. Enumerate 5 concrete "
                    "attack vectors you have NOT yet tried on this target — think about auth "
                    "bypass, IDOR, business logic, injection on newly discovered params, "
                    "misconfigurations, cache poisoning, prototype pollution, JWT algorithm "
                    "confusion, request smuggling, timing side-channels — and then EXECUTE "
                    "them using the tools. Do not summarize; act. If a probe fails, adapt "
                    "and try a variant."
                ),
            })
            follow = await self.llm.generate_with_tools(
                messages=reprompt_messages,
                tools=PENTESTING_TOOLS,
                tool_executor=self._execute_tool_call,
                max_rounds=max(6, max_rounds // 3),
                max_tokens=4096,
            )
            self.result.total_cost += follow.cost_usd
            if follow.content:
                self.result.summary = (self.result.summary or "") + "\n\n" + follow.content
            new_steps = self.result.steps_taken - steps_before
            logger.info(f"[AgenticExecutor] Re-prompt {i+1}/{REPROMPT_ROUNDS} triggered {new_steps} extra tool call(s)")
            if new_steps == 0:
                break   # LLM truly has nothing more; stop re-prompting
            response = follow

        self.result.total_cost = self.result.total_cost or response.cost_usd

        logger.info(
            f"[AgenticExecutor] Completed: steps={self.result.steps_taken} "
            f"tools={self.result.tools_used} findings={len(self.result.findings)} "
            f"cost=${self.result.total_cost:.4f}"
        )

        # Post-finding reflection loop — for each pending HIGH/CRITICAL finding,
        # ask the LLM to enumerate + execute 3-5 follow-up probes chasing what
        # this weakness might unlock (session pivot, secondary injection,
        # blind time-based confirm, WAF bypass variants, related endpoints).
        pending = getattr(self, "_pending_reflections", []) or []
        for i, finding in enumerate(pending[:3]):
            try:
                reflect_prompt = (
                    f"You just confirmed a HIGH/CRITICAL vulnerability. Reflect: what does "
                    f"THIS specific finding UNLOCK on this target? Propose and EXECUTE 3-5 "
                    f"follow-up probes chasing implications (session pivot, secondary/blind "
                    f"variants, related endpoints with the same weakness class, data exfil "
                    f"escalation, WAF-bypass tampers). Use `run_custom_probe` or "
                    f"`query_security_kb` to find angles you haven't tried.\n\n"
                    f"CONFIRMED FINDING:\n"
                    f"- Title: {finding.get('title','')}\n"
                    f"- Type: {finding.get('type','')}\n"
                    f"- Target: {finding.get('target','')}\n"
                    f"- Details: {(finding.get('details') or '')[:600]}\n"
                    f"- Evidence: {(finding.get('evidence') or '')[:400]}\n"
                )
                reflect_msgs = list(messages)
                reflect_msgs.append({"role": "user", "content": reflect_prompt})
                follow = await self.llm.generate_with_tools(
                    messages=reflect_msgs,
                    tools=PENTESTING_TOOLS,
                    tool_executor=self._execute_tool_call,
                    max_rounds=6,
                    max_tokens=2048,
                )
                self.result.total_cost += (follow.cost_usd or 0)
                logger.info(f"[Reflection] {i+1}/{len(pending[:3])} finished after {follow.cost_usd:.4f} USD")
            except Exception as e:
                logger.warning(f"[Reflection] failed for finding {i}: {e}")
        self._pending_reflections = []

        self._ingest_to_shared_context()
        # Persist the LLM's own scan-time reasoning so the chatbot can reuse
        # it later instead of re-deriving conclusions from raw DB rows.
        try:
            from core.database.pg_store import LLMMemoryRepo
            sid = getattr(self, "scan_id", "") or ""
            if sid and (self.result.summary or "").strip():
                LLMMemoryRepo.append(sid, phase=phase, kind="summary",
                                       content=self.result.summary,
                                       target=getattr(self.ctx, "target", ""))
        except Exception:
            pass
        try:
            if self._tracker:
                self._tracker.finish(
                    status="completed",
                    findings=self.result.findings,
                    cost_usd=self.result.total_cost)
        except Exception:
            pass
        return self.result

    async def _execute_tool_call(self, fn_name: str, fn_args: Dict[str, Any]) -> str:
        """
        Bridge between LLM tool calls and actual tool execution.
        Returns the result as a string the LLM can read.
        """
        self.result.steps_taken += 1
        # Per-agent heartbeat — feeds the UI's live agent panel.
        try:
            if self._tracker:
                tool_id = fn_args.get("tool_id") or fn_args.get("tool") or fn_name
                target = fn_args.get("target") or fn_args.get("url") or self.ctx.target
                self._tracker.heartbeat(
                    tool=tool_id,
                    step=f"{fn_name}({str(target)[:70]})",
                    steps_taken=self.result.steps_taken,
                    findings_count=len(self.result.findings),
                    cost_usd=self.result.total_cost,
                )
        except Exception:
            pass
        # Live chain-of-thought — persist the LLM's rationale for THIS tool
        # call so the UI can stream it as a "thought bubble" per agent.
        #
        # Delegated to a background thread so a slow DB commit never blocks
        # the LLM planning loop. Failure is swallowed at the caller (see the
        # bare `except`) — reasoning rows are best-effort telemetry, not
        # audit-critical.
        try:
            if self.scan_id and self._tracker:
                thought = fn_args.get("rationale") or fn_args.get("reasoning") \
                            or fn_args.get("why") or ""
                if not thought:
                    thought = f"call {fn_name} on {fn_args.get('target') or fn_args.get('url') or ''}"
                tool_planned = str(fn_args.get("tool_id") or fn_args.get("tool") or fn_name)[:60]

                def _write_reasoning_row(sid, aid, step, thg, tp):
                    from core.database.pg_store import DatabaseManager
                    with DatabaseManager.get_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO agent_reasoning
                                  (scan_id, agent_id, step, thought, tool_planned)
                                VALUES (%s, %s, %s, %s, %s)
                            """, (sid, aid, step, thg, tp))
                            conn.commit()

                import asyncio as _aio
                _aio.get_event_loop().create_task(
                    _aio.to_thread(_write_reasoning_row,
                                    self.scan_id, self._tracker.agent_id,
                                    self.result.steps_taken, str(thought)[:800],
                                    tool_planned)
                )
        except Exception:
            pass

        if fn_name == "run_tool":
            return await self._run_security_tool(fn_args)
        elif fn_name == "http_request":
            return await self._run_http_request(fn_args)
        elif fn_name == "run_custom_probe":
            from core.orchestration.adversarial_critic import critique_and_run, enabled as _crit_on
            if _crit_on():
                return await critique_and_run(fn_args, self.ctx, self._tracker)
            return await _run_custom_probe(fn_args, self.ctx, self._tracker)
        elif fn_name == "run_custom_python":
            return await _run_custom_python(fn_args, self.ctx, self._tracker)
        elif fn_name == "run_skill":
            from core.intel.skill_library import run_skill as _rs
            return await _rs(fn_args, self.ctx, self._tracker)
        elif fn_name == "list_skills":
            from core.intel.skill_library import list_skills as _ls
            return _ls(self.ctx)
        elif fn_name == "query_security_kb":
            from core.intel.security_kb import query_kb_async
            return await query_kb_async(fn_args.get("topic",""), fn_args.get("tech_stack",""))
        elif fn_name == "author_tool":
            from core.intel.tool_authoring import author_tool
            return await author_tool(fn_args, self.ctx)
        elif fn_name == "run_authored_tool":
            return await _run_authored_tool(fn_args, self.ctx, self._tracker)
        elif fn_name == "analyze_results":
            return self._record_finding(fn_args)
        elif fn_name == "filter_endpoints":
            return self._filter_endpoints(fn_args)
        else:
            return f"Unknown function: {fn_name}"

    TOOL_TO_OPERATION = {
        "nmap": "port_scanning", "masscan": "port_scanning",
        "subfinder": "subdomain_enumeration", "amass": "subdomain_enumeration",
        "assetfinder": "subdomain_enumeration", "dnsenum": "dns_enumeration",
        "fierce": "dns_enumeration", "dig": "dns_intelligence", "whois": "dns_intelligence",
        "httpx": "technology_fingerprinting", "whatweb": "technology_fingerprinting",
        "wafw00f": "waf_detection",
        "nuclei": "vulnerability_scanning", "nikto": "vulnerability_scanning",
        "sqlmap": "sql_injection", "wpscan": "vulnerability_scanning",
        "ffuf": "endpoint_discovery", "gobuster": "endpoint_discovery",
        "feroxbuster": "endpoint_discovery", "dirb": "endpoint_discovery",
        "dirsearch": "endpoint_discovery", "katana": "web_crawling",
        "sslscan": "tls_analysis", "sslyze": "tls_analysis",
        "hydra": "authentication_testing", "arjun": "parameter_discovery",
        "dalfox": "xss_scanning", "theharvester": "employee_enumeration",
        "curl": "http_analysis",
    }

    def _build_known_vulns_summary(self) -> str:
        """Compact summary of already-discovered vulns so LLM doesn't re-find them."""
        vulns = self.ctx.vulnerabilities
        if not vulns:
            return ""
        seen = {}
        for v in vulns:
            vtype = (v.get("type") or "").upper()
            title = v.get("title") or ""
            loc = v.get("location") or v.get("target") or ""
            sev = v.get("severity") or "INFO"
            key = f"{vtype}|{title[:40]}|{loc}"
            if key not in seen:
                seen[key] = sev
        lines = []
        for key, sev in list(seen.items())[:40]:
            parts = key.split("|", 2)
            lines.append(f"- [{sev}] {parts[0]}: {parts[1]} @ {parts[2]}")
        if len(seen) > 40:
            lines.append(f"- ... and {len(seen) - 40} more")
        return "\n".join(lines)

    def _probe_tool_availability(self) -> set:
        """Check which tools are actually available before the loop starts."""
        all_tools = [
            "nmap", "masscan", "subfinder", "amass", "assetfinder", "httpx", "whatweb",
            "wafw00f", "nikto", "nuclei", "sqlmap", "ffuf", "gobuster", "katana", "dalfox",
            "sslscan", "wpscan", "hydra", "arjun", "dirb", "dirsearch", "feroxbuster",
            "dnsenum", "fierce", "theharvester", "whois", "dig", "curl",
        ]
        available = set()
        gateway = self.tool_engine.gateway
        for tool_id in all_tools:
            if gateway._is_tool_available(tool_id):
                operation = self.TOOL_TO_OPERATION.get(tool_id, tool_id)
                tools_for_op = gateway.router._get_tools_for_operation(operation)
                if tools_for_op:
                    available.add(tool_id)
        logger.info(f"[AgenticExecutor] Available tools: {sorted(available)}")
        return available

    async def _run_security_tool(self, args: Dict[str, Any]) -> str:
        tool_id = args.get("tool", "")
        target = args.get("target", self.ctx.target)
        extra_args = args.get("args", "")

        if self._available_tools and tool_id not in self._available_tools:
            self.result.errors_encountered.append(f"{tool_id}: not available")
            return f"[FAILED] {tool_id} is not available in Docker. Use http_request instead."

        self.result.tools_used.append(tool_id)
        logger.info(f"[AgenticExecutor] Tool call: {tool_id} {target} {extra_args}")

        from core.tools.tool_invocation_engine import ToolInvocationContext, InvocationSource

        params = {}
        if extra_args:
            params["extra_args"] = extra_args
        params["timeout"] = self.TOOL_TIMEOUTS.get(tool_id, 900)

        operation = self.TOOL_TO_OPERATION.get(tool_id, tool_id)

        context = ToolInvocationContext(
            tool_id=tool_id,
            operation=operation,
            target=target,
            params=params,
            session_id="agentic_session",
            source=InvocationSource.TOOL_USE,
            auth_context=self.auth_context,
        )

        try:
            result = await self.tool_engine.invoke(context)

            output_parts = []
            if result.success:
                output_parts.append(f"[SUCCESS] {tool_id} completed")
            else:
                output_parts.append(f"[FAILED] {tool_id} failed")
                if result.error:
                    err_msg = result.error.message if hasattr(result.error, 'message') else str(result.error)
                    output_parts.append(f"Error: {err_msg}")
                    self.result.errors_encountered.append(f"{tool_id}: {err_msg}")

            if result.stdout:
                stdout_trimmed = str(result.stdout)[:4000]
                output_parts.append(f"\n--- STDOUT ({len(str(result.stdout))} bytes) ---\n{stdout_trimmed}")

            if result.stderr:
                stderr_trimmed = str(result.stderr)[:1000]
                output_parts.append(f"\n--- STDERR ---\n{stderr_trimmed}")

            if result.data:
                data_str = json.dumps(result.data, default=str)[:2000]
                output_parts.append(f"\n--- Parsed Data ---\n{data_str}")

            # Persist raw output for the Recon UI.
            _sid = getattr(self.ctx, "scan_id", "")
            _stdout_len = len(str(result.stdout or ""))
            if _sid:
                try:
                    from core.database.pg_store import ToolOutputRepo
                    _exit = getattr(result, "exit_code", None)
                    _dur = getattr(result, "duration_seconds", 0.0) or 0.0
                    ToolOutputRepo.save(
                        scan_id=_sid, tool_name=tool_id,
                        operation=operation, target=target,
                        command=f"{tool_id} {target} {extra_args}".strip(),
                        stdout=str(result.stdout or ""),
                        stderr=str(result.stderr or ""),
                        exit_code=_exit if _exit is not None else -1,
                        duration_s=_dur,
                    )
                except Exception:
                    pass

            # Record tool execution in SharedContext and DB
            _cmd = f"{tool_id} {target} {extra_args}".strip()
            exec_record = {
                "tool": tool_id, "command": _cmd[:500], "target": target,
                "capability": operation, "success": bool(result.success),
                "stdout_bytes": _stdout_len,
            }
            if hasattr(self.ctx, "add_tool_execution"):
                self.ctx.add_tool_execution(exec_record)
            if _sid:
                try:
                    from core.database.pg_store import ToolExecutionRepo
                    ToolExecutionRepo.save(
                        scan_id=_sid, tool=tool_id,
                        command=_cmd[:500], target=target,
                        capability=operation, success=bool(result.success),
                        stdout_bytes=_stdout_len,
                        duration_s=getattr(result, "duration_seconds", 0.0) or 0.0)
                except Exception:
                    pass

            # Extract recon data from tool stdout into SharedContext
            if result.success and result.stdout:
                await self._extract_recon_from_stdout(tool_id, str(result.stdout), target, operation)

            # Persist current recon snapshot to DB after every tool
            if _sid:
                try:
                    from core.database.pg_store import ReconRepo
                    raw_subs = list(getattr(self.ctx, "subdomains", []) or [])
                    sub_status = dict(getattr(self.ctx, "subdomain_status", {}) or {})
                    seen = set()
                    subs_out = []
                    for s in raw_subs:
                        host = s if isinstance(s, str) else (s.get("name") if isinstance(s, dict) else str(s))
                        host_n = str(host).replace("https://", "").replace("http://", "").rstrip("/").lower()
                        if host_n in seen:
                            continue
                        seen.add(host_n)
                        st = sub_status.get(host_n, {})
                        subs_out.append({
                            "name": host_n,
                            "live": bool(st.get("live")),
                            "status": "live" if st.get("live") else ("dead" if st else "unknown"),
                            "status_code": st.get("status_code", 0),
                            "note": st.get("note", ""),
                        })
                    raw_ports = getattr(self.ctx, "ports", []) or []
                    ports_out = list(raw_ports) if isinstance(raw_ports, list) else []
                    recon_snapshot = {
                        "subdomains": subs_out,
                        "subdomain_status": sub_status,
                        "subdomain_summary": {
                            "total": len(subs_out),
                            "live": sum(1 for s in subs_out if s.get("live")),
                            "dead": sum(1 for s in subs_out if not s.get("live")),
                        },
                        "technologies": dict(getattr(self.ctx, "technologies", {}) or {}),
                        "ports": ports_out,
                        "endpoints": list(getattr(self.ctx, "endpoints", []) or []) if isinstance(getattr(self.ctx, "endpoints", []), list) else [],
                        "tool_executions": list(getattr(self.ctx, "tool_executions", []) or []),
                        "dns_records": list(getattr(self.ctx, "dns_records", []) or []),
                        "tool_results": dict(getattr(self.ctx, "tool_results", {}) or {}),
                    }
                    ReconRepo.save(_sid, target, recon_snapshot)
                except Exception:
                    pass

            return "\n".join(output_parts)

        except Exception as e:
            error_msg = f"[ERROR] Tool execution crashed: {e}"
            self.result.errors_encountered.append(f"{tool_id}: {e}")
            logger.error(f"[AgenticExecutor] {error_msg}")
            return error_msg

    async def _extract_recon_from_stdout(self, tool_id: str, stdout: str, target: str, operation: str = ""):
        """Parse tool stdout and feed subdomains/IPs/technologies/endpoints/ssl into SharedContext."""
        import re
        target_base = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        domain_parts = target_base.split(".")
        root_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else target_base

        subdomain_tools = {"dig", "subfinder", "assetfinder", "amass", "dnsenum", "fierce", "whois", "theharvester"}
        tech_tools = {"httpx", "whatweb", "wafw00f"}
        port_tools = {"nmap", "masscan"}

        if tool_id in subdomain_tools:
            subs = set()
            dns_records = []
            for line in stdout.splitlines():
                stripped = line.strip().rstrip(".")
                if not stripped or stripped.startswith(("#", ";", "/")):
                    continue
                if tool_id == "dig":
                    parts = stripped.split()
                    # Parse DNS answer records: "name TTL IN TYPE value"
                    if len(parts) >= 5 and parts[2] == "IN":
                        rec_name = parts[0].rstrip(".")
                        rec_type = parts[3]
                        ttl = int(parts[1]) if parts[1].isdigit() else 0
                        # MX/SRV: preference (+ weight/port for SRV) precedes the host;
                        # SOA: mname rname serial refresh retry expire minimum;
                        # TXT: value may be multiple quoted chunks; preserve full remainder.
                        rest = parts[4:]
                        if rec_type == "MX" and len(rest) >= 2:
                            rec_value = f"{rest[0]} {rest[1].rstrip('.')}"
                        elif rec_type == "SRV" and len(rest) >= 4:
                            rec_value = f"{rest[0]} {rest[1]} {rest[2]} {rest[3].rstrip('.')}"
                        elif rec_type == "SOA":
                            rec_value = " ".join(p.rstrip(".") for p in rest)
                        elif rec_type == "TXT":
                            rec_value = " ".join(rest)
                        else:
                            rec_value = rest[0].rstrip(".")
                        if rec_type in ("A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "SRV", "PTR"):
                            dns_records.append({
                                "name": rec_name, "type": rec_type,
                                "value": rec_value, "ttl": ttl,
                            })
                    for p in parts:
                        p = p.rstrip(".")
                        if root_domain in p and re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', p):
                            subs.add(p.lower())
                else:
                    candidate = stripped.split()[0] if stripped.split() else ""
                    candidate = candidate.split(":")[0].rstrip(".")
                    if root_domain in candidate and re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', candidate):
                        subs.add(candidate.lower())
            if subs and hasattr(self.ctx, "add_subdomains"):
                self.ctx.add_subdomains(list(subs), source=tool_id)
                logger.info(f"[AgenticExecutor] Extracted {len(subs)} subdomains from {tool_id}")
            if dns_records:
                existing_dns = getattr(self.ctx, "dns_records", []) or []
                seen = {(r["name"], r["type"], r["value"]) for r in existing_dns}
                for r in dns_records:
                    key = (r["name"], r["type"], r["value"])
                    if key not in seen:
                        existing_dns.append(r)
                        seen.add(key)
                self.ctx.dns_records = existing_dns
                logger.info(f"[AgenticExecutor] Extracted {len(dns_records)} DNS records from {tool_id}")
            # Extract IPs / hosts / ASNs / URLs / LinkedIn from
            # theharvester's section-based stdout format:
            #   [*] SECTION found: N
            #   --------------------
            #   line
            #   line
            #   \n
            if tool_id in ("theharvester", "whois"):
                sections = self._parse_theharvester_sections(stdout)
                # IPs
                ips = set(sections.get("IPs", set()))
                for h in sections.get("Hosts", []):
                    if ":" in h:
                        left, right = h.rsplit(":", 1)
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', right):
                            ips.add(right)
                if ips and hasattr(self.ctx, "ips"):
                    existing = set(self.ctx.ips or [])
                    new_ips = ips - existing
                    if new_ips:
                        self.ctx.ips = list(existing | ips)
                        logger.info(f"[AgenticExecutor] Extracted {len(new_ips)} IPs from {tool_id}")
                # Hosts / subdomains
                harv_subs = set()
                for h in sections.get("Hosts", []):
                    hostname = h.split(":", 1)[0].lstrip("*.").strip()
                    if hostname and "." in hostname and target_base in hostname:
                        harv_subs.add(hostname.lower())
                if harv_subs and hasattr(self.ctx, "subdomains"):
                    existing = set(self.ctx.subdomains or [])
                    new_subs = harv_subs - existing
                    if new_subs:
                        self.ctx.subdomains = sorted(existing | harv_subs)
                        logger.info(f"[AgenticExecutor] Extracted {len(new_subs)} subdomains from theharvester")
                # ASNs → osint.domain_intelligence.asns
                asns = sections.get("ASNS", [])
                interesting_urls = sections.get("Interesting Urls", [])
                linkedin_links = sections.get("LinkedIn Links", []) + sections.get("LinkedIn users", [])
                if asns or interesting_urls or linkedin_links:
                    osint = dict(self.ctx.get("osint", {}) or {}) if hasattr(self.ctx, "get") else {}
                    if asns:
                        di = dict(osint.get("domain_intelligence", {}) or {})
                        existing = set(di.get("asns", []) or [])
                        di["asns"] = sorted(existing | set(asns))
                        osint["domain_intelligence"] = di
                    if interesting_urls:
                        other = dict(osint.get("other", {}) or {})
                        existing = set(other.get("interesting_urls", []) or [])
                        other["interesting_urls"] = sorted(existing | set(interesting_urls))
                        osint["other"] = other
                        # Also drop them into endpoints so the crawler sees them
                        if hasattr(self.ctx, "add_endpoints"):
                            self.ctx.add_endpoints(
                                [{"url": u, "status": 0} for u in interesting_urls],
                                source="theharvester")
                    if linkedin_links:
                        other = dict(osint.get("other", {}) or {})
                        existing = set(other.get("linkedin_links", []) or [])
                        other["linkedin_links"] = sorted(existing | set(linkedin_links))
                        osint["other"] = other
                    # Recompute summary counts so the UI badge shows something
                    summary = dict(osint.get("summary", {}) or {})
                    if asns: summary["asns"] = len(osint["domain_intelligence"]["asns"])
                    if interesting_urls: summary["interesting_urls"] = len(osint["other"]["interesting_urls"])
                    if linkedin_links: summary["linkedin_links"] = len(osint["other"]["linkedin_links"])
                    osint["summary"] = summary
                    if hasattr(self.ctx, "update"):
                        self.ctx.update("osint", osint)
                    logger.info(f"[AgenticExecutor] theharvester → ASNs={len(asns)} urls={len(interesting_urls)} linkedin={len(linkedin_links)}")

        if tool_id in (tech_tools | port_tools) and hasattr(self.ctx, "update"):
            try:
                await self._llm_extract_recon(tool_id, stdout, target_base)
            except Exception as e:
                logger.warning(f"[AgenticExecutor] LLM recon extraction failed, using regex fallback: {e}")
                self._regex_extract_recon(tool_id, stdout, target_base, re)

        # Endpoint extraction from crawlers/brute-forcers
        endpoint_tools = {"katana", "gobuster", "feroxbuster", "dirb", "ffuf"}
        endpoint_caps = {"endpoint_discovery", "web_crawling", "directory_bruteforce", "api_enumeration"}
        if tool_id in endpoint_tools or operation in endpoint_caps:
            endpoints = []
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                m = re.search(r'(https?://\S+)\s+\[Status:\s*(\d+)', line)
                if m:
                    endpoints.append({"url": m.group(1), "status": int(m.group(2))})
                    continue
                m = re.search(r'^(\d{3})\s+\S+\s+(https?://\S+)', line)
                if m:
                    endpoints.append({"url": m.group(2), "status": int(m.group(1))})
                    continue
                m = re.match(r'^(https?://\S+)$', line)
                if m:
                    url = m.group(1)
                    if not re.search(r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map)(\?|$)', url, re.I):
                        endpoints.append({"url": url, "status": 0})
            if endpoints and hasattr(self.ctx, "add_endpoints"):
                self.ctx.add_endpoints(endpoints, source=tool_id)
                logger.info(f"[AgenticExecutor] Extracted {len(endpoints)} endpoints from {tool_id}")

        # Directory extraction from brute-forcers
        dir_tools = {"gobuster", "feroxbuster", "dirb", "ffuf"}
        if tool_id in dir_tools or operation == "directory_bruteforce":
            for line in stdout.splitlines():
                line = line.strip()
                m = re.search(r'(https?://\S+/)\s', line)
                if m and hasattr(self.ctx, "add_directory"):
                    self.ctx.add_directory(m.group(1))
                m = re.search(r'(/[a-zA-Z0-9._-]+/)\s', line)
                if m and len(m.group(1)) > 2 and hasattr(self.ctx, "add_directory"):
                    self.ctx.add_directory(f"{target.rstrip('/')}{m.group(1)}")

        # SSL/TLS parsing from sslscan
        if tool_id == "sslscan" or operation == "tls_analysis":
            tls_findings = []
            ssl_data = {"protocols": [], "ciphers": [], "certificate": {}}
            for line in stdout.splitlines():
                m_proto = re.search(r'((?:SSL|TLS)v[\d.]+)\s+(\d+)\s+bits\s+(\S+)\s+(Accepted|Rejected)', line)
                if m_proto:
                    entry = {"protocol": m_proto.group(1), "bits": int(m_proto.group(2)),
                             "cipher": m_proto.group(3), "status": m_proto.group(4)}
                    ssl_data["ciphers"].append(entry)
                    if m_proto.group(4) == "Accepted":
                        proto = m_proto.group(1)
                        if proto not in ssl_data["protocols"]:
                            ssl_data["protocols"].append(proto)
                        if proto in ("SSLv2", "SSLv3"):
                            tls_findings.append({
                                "type": "TLS_WEAKNESS", "title": f"Deprecated SSL protocol: {proto}",
                                "severity": "HIGH", "target": target, "location": target,
                                "proof": line.strip(), "tool": "sslscan",
                            })
                m_subj = re.search(r'Subject:\s+(.+)', line)
                if m_subj:
                    ssl_data["certificate"]["subject"] = m_subj.group(1).strip()
                m_issuer = re.search(r'Issuer:\s+(.+)', line)
                if m_issuer:
                    ssl_data["certificate"]["issuer"] = m_issuer.group(1).strip()
                m_exp = re.search(r'Not valid after:\s+(.+)', line)
                if m_exp:
                    ssl_data["certificate"]["expires"] = m_exp.group(1).strip()
            if "Heartbleed" in stdout and "vulnerable" in stdout.lower() and "not vulnerable" not in stdout.lower():
                tls_findings.append({
                    "type": "TLS_WEAKNESS", "title": "Heartbleed vulnerability detected",
                    "severity": "CRITICAL", "target": target, "location": target,
                    "proof": "sslscan Heartbleed test positive", "tool": "sslscan",
                })
            if tls_findings:
                for v in tls_findings:
                    if hasattr(self.ctx, "add_vulnerability"):
                        self.ctx.add_vulnerability(v)
                logger.info(f"[AgenticExecutor] Extracted {len(tls_findings)} TLS findings from sslscan")
            if (ssl_data["protocols"] or ssl_data["certificate"]) and hasattr(self.ctx, "add_ssl_info"):
                self.ctx.add_ssl_info(target_base, ssl_data)
                logger.info(f"[AgenticExecutor] Stored SSL info for {target_base}: {len(ssl_data['protocols'])} protocols, {len(ssl_data['ciphers'])} ciphers")

        # Vulnerability extraction from nikto/nuclei
        vuln_tools = {"nikto", "nuclei"}
        if tool_id in vuln_tools or operation == "vulnerability_scanning":
            vulns = []
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("{") and ('"template-id"' in line or '"template_id"' in line):
                    try:
                        import json as _json
                        ndata = _json.loads(line)
                        info = ndata.get("info", {})
                        tid = ndata.get("template-id") or ndata.get("template_id") or "unknown"
                        title = info.get("name") or tid
                        sev = (info.get("severity") or "medium").upper()
                        matched_at = ndata.get("matched-at") or ndata.get("matched") or target
                        classification = info.get("classification", {})
                        cve_ids = classification.get("cve-id") or classification.get("cve_id") or []
                        if isinstance(cve_ids, str):
                            cve_ids = [cve_ids]
                        vulns.append({
                            "type": "NUCLEI_MATCH", "title": f"Nuclei: {title}",
                            "severity": sev, "target": target, "location": matched_at,
                            "template_id": tid, "cve": ", ".join(cve_ids) if cve_ids else "",
                            "proof": f"Nuclei template '{tid}' matched at {matched_at}",
                            "tool": "nuclei",
                        })
                        continue
                    except Exception:
                        pass
                m = re.match(r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)', line)
                if m:
                    vulns.append({
                        "type": "NUCLEI_MATCH", "title": f"Nuclei: {m.group(1)}",
                        "severity": m.group(2).upper(), "target": target, "location": m.group(4),
                        "template_id": m.group(1), "proof": line, "tool": "nuclei",
                    })
                    continue
                _nikto_noise = ("+ Target", "+ Start", "+ End", "+ Server:", "+ SSL Info:",
                                "+ Platform:", "+ No CGI Dir", "+ Scan terminated", "+ host(s) tested",
                                "+ Multiple IPs", "+ Hostname:")
                m = re.match(r'^\+\s+(OSVDB-\d+:\s*)?(.+)', line)
                if m and not any(line.startswith(p) for p in _nikto_noise):
                    desc = m.group(2).strip()
                    if len(desc) > 10 and not re.match(r'^\d+\s+host\(s\)\s+tested', desc):
                        sev = "MEDIUM"
                        if any(k in desc.lower() for k in ("xss", "inject", "rce", "remote code")):
                            sev = "HIGH"
                        elif any(k in desc.lower() for k in ("missing", "header", "cookie", "info")):
                            sev = "LOW"
                        vulns.append({
                            "type": "NIKTO_FINDING", "title": desc[:120], "severity": sev,
                            "target": target, "location": target, "proof": f"nikto: {line.strip()}",
                            "tool": tool_id,
                        })
            if vulns and hasattr(self.ctx, "add_vulnerability"):
                for v in vulns:
                    v.setdefault("status", "CONFIRMED")
                    v.setdefault("confirmed", True)
                    self.ctx.add_vulnerability(v)
                logger.info(f"[AgenticExecutor] Extracted {len(vulns)} vulnerability findings from {tool_id}")
            elif not vulns and len(stdout) > 1000:
                # Sizable output but nothing parsed — surface it so the LLM can act on it,
                # and log a warning so we know a parser rule may be missing.
                logger.warning(
                    f"[AgenticExecutor] {tool_id} produced {len(stdout)} bytes of stdout but "
                    f"no vulnerabilities were extracted by the parser — LLM will need to summarize"
                )
                snippet = stdout[:800]
                if hasattr(self.ctx, "get") and hasattr(self.ctx, "update"):
                    try:
                        unparsed = self.ctx.get("unparsed_tool_outputs", []) or []
                        unparsed.append({
                            "tool": tool_id, "target": target,
                            "size": len(stdout), "snippet": snippet,
                        })
                        self.ctx.update("unparsed_tool_outputs", unparsed[-50:])
                    except Exception:
                        pass

    def _parse_theharvester_sections(self, stdout: str) -> dict:
        """Parse theHarvester's section-based stdout format.

        Sections look like:
            [*] SECTION_NAME found: N
            --------------------
            <line>
            <line>
            <blank line ends section>

        Returns dict of {section_name: [values]}. Handles: Hosts, IPs,
        ASNS, Interesting Urls, LinkedIn Links, LinkedIn users, Emails,
        People, Sub-domains.
        """
        import re as _re
        sections = {}
        current = None
        buf = []
        HEADER_RE = _re.compile(r'^\[\*\]\s+([A-Za-z][A-Za-z /\-]*?)\s+found[:]?\s*(\d+)?\s*$')
        for raw in stdout.splitlines():
            line = raw.rstrip()
            m = HEADER_RE.match(line)
            if m:
                if current and buf:
                    sections.setdefault(current, []).extend(buf)
                current = m.group(1).strip()
                buf = []
                continue
            if current is None:
                continue
            stripped = line.strip()
            if not stripped or stripped.startswith("-"):
                if not stripped and buf:
                    sections.setdefault(current, []).extend(buf)
                    current = None
                    buf = []
                continue
            # Skip auxiliary "No X found." / "[*] Performing ..." lines
            if stripped.startswith("[*]") or stripped.startswith("[!]"):
                continue
            buf.append(stripped)
        if current and buf:
            sections.setdefault(current, []).extend(buf)
        return sections

    def _regex_extract_recon(self, tool_id, stdout, target_base, re):
        """Fallback regex-based extraction if LLM call fails."""
        techs = {}
        ports = {}
        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            port_match = re.search(r'(\d+)/(tcp|udp)\s+open\s+(\S+)', stripped)
            if port_match:
                port_num = int(port_match.group(1))
                service = port_match.group(3)
                if target_base not in ports:
                    ports[target_base] = []
                ports[target_base].append({"port": port_num, "service": service, "protocol": port_match.group(2), "host": target_base})
            if tool_id == "httpx":
                url_match = re.match(r'(https?://[\w\.\-]+)', stripped)
                status_match = re.search(r'\[(\d{3})\]', stripped)
                if url_match and status_match:
                    host = url_match.group(1).replace("https://", "").replace("http://", "").rstrip("/").lower()
                    code = int(status_match.group(1))
                    if not hasattr(self.ctx, "subdomain_status"):
                        self.ctx.subdomain_status = {}
                    self.ctx.subdomain_status[host] = {"live": code < 500, "status_code": code, "note": f"httpx {code}"}
        if ports:
            all_ports = [p for pl in ports.values() for p in pl]
            if hasattr(self.ctx, "add_ports"):
                self.ctx.add_ports(all_ports)
            logger.info(f"[AgenticExecutor] Regex fallback extracted {len(all_ports)} ports from {tool_id}")

    async def _llm_extract_recon(self, tool_id: str, stdout: str, target_base: str):
        """Send tool output to LLM for clean per-subdomain data extraction.

        Skip LLM entirely for tools where regex is authoritative (httpx, nmap, subfinder,
        assetfinder) — they emit line-oriented output the regex path parses correctly and
        the LLM call just burns tokens. Also skip on empty/tiny output.
        """
        import re as _re
        REGEX_AUTHORITATIVE = {"httpx", "nmap", "masscan", "subfinder", "assetfinder", "dig", "amass"}
        if tool_id in REGEX_AUTHORITATIVE:
            self._regex_extract_recon(tool_id, stdout, target_base, _re)
            return
        if not stdout or len(stdout.strip()) < 40:
            return
        # Expert mode: send the full 6000-char window so the LLM sees enough of
        # the output to catch every fingerprint / port / subtle vuln signal
        # (nuclei/nikto/whatweb produce dense output where later lines matter).
        truncated = stdout[:6000] if len(stdout) > 6000 else stdout

        # Tool stdout is untrusted (contains attacker-controlled response bodies
        # captured by scanners like nikto/nuclei). Fence it so a crafted target
        # response can't inject planner directives.
        from core.llm.prompt_safety import fence_untrusted
        _fenced_output = fence_untrusted(truncated, label=f"tool_output_{tool_id}", max_chars=6100)
        prompt = f"""Analyze this {tool_id} security tool output. Extract ONLY real, useful recon data per subdomain. Return JSON.

TOOL: {tool_id}
TARGET: {target_base}

OUTPUT:
{_fenced_output}

Return JSON:
{{
  "technologies": {{"host.example.com": ["Apache:2.4.41", "jQuery:3.6.0"]}},
  "ports": [{{"host": "host.example.com", "port": 80, "service": "http", "protocol": "tcp"}}],
  "subdomain_status": {{"host.example.com": {{"live": true, "status_code": 200, "note": "httpx 200"}}}},
  "summary": "Brief 1-2 sentence summary of what this tool found"
}}

RULES:
- Technologies: ONLY real software/frameworks/libraries (Apache, Nginx, jQuery, React, PHP, WordPress, etc.)
- Do NOT include as tech: HTTP headers (HSTS, X-Frame-Options), error messages, page titles, status codes, IPs, URLs
- Group everything by specific subdomain/host
- Version format: "Name:Version" when available
- Ports: numeric port + service + protocol (tcp/udp)
- subdomain_status: live if status < 500
- summary: what this specific tool discovered (used for UI display)
- Empty object/array if nothing found for a category
- JSON only, no explanations"""

        try:
            data = await self.llm.generate_json(prompt, max_tokens=2048)
            if not data or not isinstance(data, dict):
                logger.warning("[AgenticExecutor] LLM recon extraction returned empty")
                return

            llm_techs = data.get("technologies", {})
            if isinstance(llm_techs, dict):
                for host, tech_list in llm_techs.items():
                    if isinstance(tech_list, list) and tech_list:
                        clean_host = host.replace("https://", "").replace("http://", "").rstrip("/").lower()
                        if hasattr(self.ctx, "add_technologies"):
                            self.ctx.add_technologies(clean_host, tech_list)
                        logger.info(f"[AgenticExecutor] LLM extracted {len(tech_list)} techs for {clean_host}")

            llm_ports = data.get("ports", [])
            valid_ports = []
            if isinstance(llm_ports, list) and llm_ports:
                for p in llm_ports:
                    if isinstance(p, dict) and "port" in p and isinstance(p["port"], int):
                        p.setdefault("host", target_base)
                        p.setdefault("protocol", "tcp")
                        p.setdefault("service", "unknown")
                        valid_ports.append(p)
                if valid_ports and hasattr(self.ctx, "add_ports"):
                    self.ctx.add_ports(valid_ports)
                    logger.info(f"[AgenticExecutor] LLM extracted {len(valid_ports)} ports")

            llm_status = data.get("subdomain_status", {})
            if isinstance(llm_status, dict) and llm_status:
                if not hasattr(self.ctx, "subdomain_status"):
                    self.ctx.subdomain_status = {}
                for host, status in llm_status.items():
                    if isinstance(status, dict):
                        clean_host = host.replace("https://", "").replace("http://", "").rstrip("/").lower()
                        self.ctx.subdomain_status[clean_host] = {
                            "live": bool(status.get("live", False)),
                            "status_code": int(status.get("status_code") or 0),
                            "note": str(status.get("note") or ""),
                        }
                logger.info(f"[AgenticExecutor] LLM extracted status for {len(llm_status)} hosts")

            # Store per-tool parsed results (aggregated by tool name)
            if not hasattr(self.ctx, "tool_results"):
                self.ctx.tool_results = {}
            existing = self.ctx.tool_results.get(tool_id, {})
            # Merge technologies
            ex_techs = existing.get("technologies", {})
            for h, tl in (llm_techs if isinstance(llm_techs, dict) else {}).items():
                ch = h.replace("https://", "").replace("http://", "").rstrip("/").lower()
                prev = set(ex_techs.get(ch, []))
                prev.update(tl if isinstance(tl, list) else [])
                ex_techs[ch] = sorted(prev)
            # Merge ports (dedup by host+port)
            ex_ports = existing.get("ports", [])
            seen_ports = {(p["host"], p["port"]) for p in ex_ports if isinstance(p, dict)}
            for p in valid_ports:
                key = (p["host"], p["port"])
                if key not in seen_ports:
                    ex_ports.append(p)
                    seen_ports.add(key)
            # Merge status
            ex_status = existing.get("subdomain_status", {})
            for h, s in (llm_status if isinstance(llm_status, dict) else {}).items():
                ch = h.replace("https://", "").replace("http://", "").rstrip("/").lower()
                if isinstance(s, dict):
                    ex_status[ch] = s
            summary = data.get("summary", "")
            prev_summary = existing.get("summary", "")
            if summary and prev_summary and summary != prev_summary:
                summary = f"{prev_summary}; {summary}"
            elif not summary:
                summary = prev_summary
            self.ctx.tool_results[tool_id] = {
                "technologies": ex_techs,
                "ports": ex_ports,
                "subdomain_status": ex_status,
                "summary": summary,
            }

        except json.JSONDecodeError as e:
            logger.warning(f"[AgenticExecutor] LLM returned invalid JSON for recon: {e}")
            import re as re_mod
            self._regex_extract_recon(tool_id, stdout, target_base, re_mod)
        except Exception as e:
            logger.warning(f"[AgenticExecutor] LLM recon extraction error: {e}")
            import re as re_mod
            self._regex_extract_recon(tool_id, stdout, target_base, re_mod)

    async def _run_http_request(self, args: Dict[str, Any]) -> str:
        method = args.get("method", "GET")
        url = args.get("url", "")
        headers = args.get("headers", {})
        body = args.get("body", "")
        follow = args.get("follow_redirects", True)

        self.result.tools_used.append(f"http_{method}")
        # Log the request body (truncated) for POST/PUT so we can diagnose failing
        # auth flows (register 201 → login 401 mismatches, missing Content-Type, …).
        if method.upper() in ("POST", "PUT", "PATCH") and body:
            body_preview = (body if isinstance(body, str) else str(body))[:400]
            logger.info(f"[AgenticExecutor] HTTP {method} {url} body={body_preview}")
        else:
            logger.info(f"[AgenticExecutor] HTTP {method} {url}")

        # Auto-inject a captured JWT for this host if the LLM didn't set one itself.
        # Once /rest/user/login (or similar) hands us a Bearer token we keep using it
        # for every subsequent request to the same netloc so authenticated endpoints
        # (basket, admin, IDOR targets) actually get tested.
        try:
            from urllib.parse import urlparse as _up
            _netloc = _up(url).netloc.lower()
            _has_auth = any(k.lower() == "authorization" for k in (headers or {}).keys())
            _tok = self._captured_tokens.get(_netloc)
            if _tok and not _has_auth:
                headers = dict(headers or {})
                headers["Authorization"] = f"Bearer {_tok}"
                logger.info(f"[AgenticExecutor] Auto-attached captured Bearer to {method} {url}")
        except Exception:
            pass

        try:
            import httpx as httpx_lib
            async with httpx_lib.AsyncClient(follow_redirects=follow, timeout=30, verify=False) as client:
                resp = await client.request(method, url, headers=headers, content=body if body else None)

                # Only include security-relevant headers to save tokens.
                sec_headers = {k: v for k, v in resp.headers.items()
                               if k.lower() in ("content-type", "server", "x-powered-by",
                                   "set-cookie", "www-authenticate", "location",
                                   "x-frame-options", "content-security-policy",
                                   "strict-transport-security", "access-control-allow-origin",
                                   "x-content-type-options", "authorization")}
                hdr_str = "\n".join(f"{k}: {v}" for k, v in sec_headers.items())
                body_text = resp.text[:3000] if resp.text else "(empty)"
                output_parts = [
                    f"HTTP {resp.status_code} {resp.reason_phrase} | {resp.url}",
                    hdr_str,
                    f"\n--- Body ({len(resp.text)}b) ---\n{body_text}",
                ]

                self._auto_detect_vulns(method, url, body, resp.status_code, resp.text)
                self._capture_auth_from_response(url, resp, req_method=method, req_body=body)
                self._harvest_emails_and_hashes(url, resp.text)
                # Chain: if a POST to /api/Users (or similar registration endpoint)
                # succeeded and the response echoes "role":"admin", immediately try
                # to log in as the new user and capture the admin JWT.
                try:
                    if (method.upper() == "POST" and resp.status_code in (200, 201)
                            and body and 'role' in (body if isinstance(body, str) else str(body)).lower()
                            and '"role":"admin"' in resp.text.replace(" ", "")):
                        await self._chain_login_after_mass_assign(url, body, resp)
                except Exception:
                    pass

                return "\n".join(output_parts)

        except Exception as e:
            return f"[ERROR] HTTP request failed: {e}"

    async def _chain_login_after_mass_assign(self, register_url: str, register_body, register_resp) -> None:
        """After a successful admin-role self-register, log in with those creds
        so the captured JWT is a fresh admin session usable by downstream tests."""
        try:
            import json as _json, re as _re
            from urllib.parse import urlparse as _up
            body_str = register_body if isinstance(register_body, str) else str(register_body)
            try:
                creds = _json.loads(body_str)
            except Exception:
                em = _re.search(r'"email"\s*:\s*"([^"]+)"', body_str)
                pw = _re.search(r'"password"\s*:\s*"([^"]+)"', body_str)
                creds = {"email": em.group(1) if em else "", "password": pw.group(1) if pw else ""}
            email = creds.get("email") or creds.get("username")
            password = creds.get("password")
            if not (email and password):
                return
            # Generic login discovery — first try the same host's discovered
            # login endpoints, fall back to standard paths on the registration
            # URL's host if none were seen.
            from core.common.endpoint_hints import discover_endpoints
            pu = _up(register_url)
            login_candidates = [u for u in discover_endpoints(self.ctx, "login", max_results=8)
                                 if _up(u).netloc == pu.netloc]
            if not login_candidates:
                login_candidates = [f"{pu.scheme}://{pu.netloc}{p}"
                                     for p in ("/login", "/api/login", "/signin",
                                                "/oauth/token", "/session")]
            import httpx as _httpx
            async with _httpx.AsyncClient(follow_redirects=True, timeout=20, verify=False) as client:
                for login_url in login_candidates:
                    r = await client.post(login_url, json={"email": email, "password": password})
                    if r.status_code in (200, 201) and "token" in (r.text or "").lower():
                        break
                logger.info(f"[AgenticExecutor] Chain-login as new admin {email} -> HTTP {r.status_code}")
                if r.status_code == 200:
                    self._capture_auth_from_response(
                        login_url, r, req_method="POST",
                        req_body=_json.dumps({"email": email, "password": password}))
        except Exception as _e:
            logger.debug(f"[AgenticExecutor] chain-login failed: {_e}")

    def _harvest_emails_and_hashes(self, url: str, resp_text: str) -> None:
        """Scan HTTP response bodies for emails and password hashes.

        Fills the gap where the crawler fetches /rest/memories, /api/Users,
        /api/Feedbacks (which leak emails + MD5/bcrypt hashes) but only
        theHarvester/whois stdout was ever regex-scanned. CredentialSpray reads
        ctx.discovered_employees and ctx.leaked_credentials so seeding them
        from live responses expands its attack surface.
        """
        if not resp_text:
            return
        try:
            import re as _re
            text = resp_text[:200_000]  # cap for perf
            # Emails
            email_re = _re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
            emails = set()
            for m in email_re.finditer(text):
                e = m.group(0).lower()
                if not e.endswith(('.png', '.jpg', '.gif', '.svg', '.webp')):
                    emails.add(e)
            if emails:
                existing = list(getattr(self.ctx, "discovered_employees", []) or [])
                existing_set = {(e.get("email") or "").lower() for e in existing if isinstance(e, dict)}
                for e in emails:
                    if e not in existing_set:
                        local = e.split("@")[0].replace(".", " ").replace("_", " ")
                        existing.append({"email": e, "name": local.title(),
                                         "source": f"response:{url[:80]}"})
                self.ctx.discovered_employees = existing
                logger.info(f"[AgenticExecutor] Harvested {len(emails)} emails from response body")
            # Password hashes: md5(32 hex), sha1(40 hex), bcrypt ($2[aby]$…), sha256(64 hex)
            hash_patterns = [
                (r'"password"\s*:\s*"([a-f0-9]{32})"', "md5"),
                (r'"password"\s*:\s*"([a-f0-9]{40})"', "sha1"),
                (r'"password"\s*:\s*"([a-f0-9]{64})"', "sha256"),
                (r'"password"\s*:\s*"(\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53})"', "bcrypt"),
                (r'"passwordHash"\s*:\s*"([a-f0-9]{32,128}|\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53})"', "unknown"),
            ]
            leaked = list(getattr(self.ctx, "leaked_credentials", []) or [])
            existing_hashes = {(c.get("hash") or c.get("password") or "") for c in leaked if isinstance(c, dict)}
            for pat, algo in hash_patterns:
                for m in _re.finditer(pat, text):
                    h = m.group(1)
                    if h in existing_hashes:
                        continue
                    existing_hashes.add(h)
                    # Correlate with nearest email in the same JSON object
                    window = text[max(0, m.start() - 300):m.end() + 100]
                    ee = email_re.search(window)
                    leaked.append({
                        "username": ee.group(0).lower() if ee else "",
                        "email": ee.group(0).lower() if ee else "",
                        "password": "",           # hashed only
                        "hash": h, "algo": algo,
                        "source": f"response:{url[:80]}",
                        "type": "password_hash",
                    })
            if len(leaked) > (len(getattr(self.ctx, "leaked_credentials", []) or [])):
                self.ctx.leaked_credentials = leaked
                logger.info(f"[AgenticExecutor] Harvested {len(leaked)} password hashes from response body")
        except Exception:
            pass

    def _persist_auth_bypass(self, *, host: str, login_url: str, technique: str,
                              payload: str = "", token: str = "",
                              response_status: int = 0, response_snippet: str = "",
                              username: str = "", password: str = "",
                              role: str = "") -> None:
        """Record a successful auth bypass / login into the auth_bypasses table so
        the UI can show 'Access Gained' with the exact payload and proof-of-entry."""
        try:
            scan_id = getattr(self, "scan_id", None) or getattr(self.ctx, "scan_id", None) or ""
            if not scan_id:
                return
            from core.database.pg_store import AuthBypassRepo
            AuthBypassRepo.insert(
                scan_id, host, technique, login_url,
                method="POST", username=username, password=password,
                payload=payload, token=token,
                response_status=response_status,
                response_snippet=response_snippet, role=role,
            )
            logger.info(f"[AuthBypass] Persisted {technique} on {host} (user={username or '-'}, role={role or '-'})")
        except Exception as _e:
            logger.debug(f"[AuthBypass] persist failed: {_e}")

    def _capture_auth_from_response(self, url: str, resp, req_method: str = "POST",
                                     req_body: str = "") -> None:
        """Extract a JWT/bearer from a successful auth response and cache it per host.

        Recognises Juice-Shop-style {"authentication":{"token":"..."}} and generic
        {"access_token":"..."} / {"token":"..."} / Set-Cookie: token=<jwt>. The
        first bearer found for a host is kept for the rest of the scan so any
        subsequent request to that host is authenticated automatically.

        When a token IS captured, also persists a proof-of-entry row into the
        auth_bypasses table so the UI can display 'Access Gained' with the exact
        payload/technique.
        """
        try:
            from urllib.parse import urlparse as _up
            netloc = _up(url).netloc.lower()
            if netloc in self._captured_tokens:
                return  # already have one
            token = None
            # Response body JSON
            try:
                import json as _json
                data = _json.loads(resp.text or "")
                if isinstance(data, dict):
                    auth = data.get("authentication") or {}
                    token = (auth.get("token") if isinstance(auth, dict) else None) \
                        or data.get("access_token") or data.get("token") or data.get("id_token")
            except Exception:
                pass
            # Set-Cookie: token=<jwt>
            if not token:
                import re as _re
                for _c in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]:
                    m = _re.search(r'(?:token|jwt|access_token|session|auth)=([A-Za-z0-9._\-]+)', _c or "")
                    if m and m.group(1).startswith("eyJ"):
                        token = m.group(1)
                        break
            if token and isinstance(token, str) and token.count(".") >= 2 and token.startswith("eyJ"):
                self._captured_tokens[netloc] = token
                logger.info(f"[AgenticExecutor] Captured JWT for {netloc} (len={len(token)}) — will auto-inject on future requests")
                # Also expose to the shared context so downstream scanners
                # (IDOR/access-control/JWT-forge/Tier-4-8) that read
                # ctx.auth_headers reuse this session automatically.
                try:
                    hdrs = dict(getattr(self.ctx, "auth_headers", {}) or {})
                    if "Authorization" not in hdrs:
                        hdrs["Authorization"] = f"Bearer {token}"
                        self.ctx.auth_headers = hdrs
                        # Push to the executor auth registry so downstream
                        # V2 executors (generic.py, authz, IDOR, JWT, mass-assign)
                        # pick up the new session immediately.
                        try:
                            from core.execution.executors.auth_registry import set_active_auth
                            set_active_auth(
                                headers=hdrs,
                                cookies=getattr(self.ctx, "auth_cookies", {}) or {},
                                sessions=getattr(self.ctx, "auth_sessions", {}) or {},
                            )
                        except Exception:
                            pass
                    # Record the credential source so _setup_auth_session on the
                    # next phase can rebuild a full role session if needed.
                    hc = list(getattr(self.ctx, "harvested_creds", []) or [])
                    hc.append({
                        "source": "agentic_capture",
                        "netloc": netloc,
                        "token": token,
                        "type": "jwt_bearer",
                        "acquired_via": "http_response",
                    })
                    self.ctx.harvested_creds = hc[-100:]
                except Exception:
                    pass
                # Persist proof-of-entry: infer technique from the request body,
                # decode JWT to extract user/role/email, snapshot response body.
                try:
                    import json as _json, base64 as _b64, re as _re
                    body_s = req_body if isinstance(req_body, str) else str(req_body or "")
                    # Classify the technique from the payload
                    technique = "credential_replay"
                    if _re.search(r"'\s*(or|OR)\s+['\"]?1['\"]?\s*=\s*['\"]?1|--\s*$|/\*", body_s):
                        technique = "sqli_bypass"
                    elif '"role"' in body_s.replace(" ", "") and 'admin' in body_s.lower():
                        technique = "mass_assign_admin"
                    elif "/api/users" in url.lower() or "/register" in url.lower() or "/signup" in url.lower():
                        technique = "self_register"
                    elif "/login" in url.lower() or "/signin" in url.lower() or "/token" in url.lower():
                        technique = "credential_replay"
                    # Decode username/role from JWT payload
                    username, role = "", ""
                    try:
                        payload_b64 = token.split(".")[1]
                        payload_b64 += "=" * (-len(payload_b64) % 4)
                        jwt_payload = _json.loads(_b64.urlsafe_b64decode(payload_b64).decode("utf-8", "ignore"))
                        data = jwt_payload.get("data") or jwt_payload
                        if isinstance(data, dict):
                            username = data.get("email") or data.get("username") or data.get("sub") or ""
                            role = data.get("role") or ""
                    except Exception:
                        pass
                    # Pull username/password from body if we didn't get it from JWT
                    if not username and body_s:
                        try:
                            b = _json.loads(body_s)
                            username = b.get("email") or b.get("username") or b.get("user") or username
                        except Exception:
                            pass
                    password = ""
                    if body_s:
                        try:
                            b = _json.loads(body_s)
                            password = b.get("password") or ""
                        except Exception:
                            pass
                    self._persist_auth_bypass(
                        host=netloc, login_url=url, technique=technique,
                        payload=body_s, token=token,
                        response_status=getattr(resp, "status_code", 200),
                        response_snippet=(getattr(resp, "text", "") or "")[:600],
                        username=username, password=password, role=role,
                    )
                except Exception:
                    pass
        except Exception:
            pass

    def _auto_detect_vulns(self, method: str, url: str, req_body: str, status: int, resp_text: str):
        import re as _re
        from urllib.parse import urlparse, unquote
        url_decoded = unquote(url)
        url_lower = url_decoded.lower()
        body_lower = unquote(req_body or "").lower()
        resp_lower = resp_text[:8000].lower() if resp_text else ""
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        target_base = url.split("?")[0]
        netloc = parsed.netloc

        def _record(typ, title, sev, details, evidence=""):
            self._record_finding({
                "type": typ, "title": title, "severity": sev,
                "details": details, "evidence": (evidence or resp_text[:500]) if resp_text else "",
                "target": target_base,
            })

        # ── 1. SQL INJECTION ──
        sqli_patterns = [
            r"union\s+select", r"'\s*or\s+['\d]", r"'\s*--", r"order\s+by\s+\d",
            r"and\s+1\s*=\s*1", r"sleep\s*\(", r"benchmark\s*\(", r"extractvalue\s*\(",
            r"updatexml\s*\(", r"load_file\s*\(", r"waitfor\s+delay",
            r"'\s*or\s+''='", r"1\s*=\s*1\s*--", r"having\s+1\s*=\s*1",
            r"group\s+by\s+\w+\s+having", r"convert\s*\(", r"cast\s*\(",
        ]
        sqli_in_req = any(_re.search(p, url_lower) or _re.search(p, body_lower) for p in sqli_patterns)

        sqli_error_sigs = [
            "you have an error in your sql syntax", "mysql_fetch", "mysql_num_rows",
            "mysql_query", "pg_query", "pg_exec", "unterminated quoted string",
            "sqlite3.operationalerror", "sqlite_error", "ora-00933", "ora-01756",
            "ora-00942", "microsoft ole db provider", "unclosed quotation mark",
            "sqlstate[", "pdo::query", "pgsql error", "syntax error at or near",
            "jdbc.sqltransientconnectionexception", "com.mysql.jdbc",
            "org.postgresql.util.psqlexception", "quoted string not properly terminated",
            "sql command not properly ended", "invalid column name",
            "column count doesn't match", "subquery returns more than",
        ]
        has_sqli_error = any(sig in resp_lower for sig in sqli_error_sigs)

        if sqli_in_req and status == 200 and len(resp_text) > 50:
            _record("vulnerability", f"SQL Injection — {method} {target_base[-60:]}", "critical",
                    f"HTTP {status} response to SQL payload. URL: {url[:200]}")
            logger.info(f"[AutoDetect] SQLi confirmed: {method} {url[:120]} → HTTP {status}")
        elif sqli_in_req and status == 500:
            _record("vulnerability", f"Error-based SQL Injection — {method} {target_base[-60:]}", "high",
                    f"HTTP 500 triggered by SQL payload. URL: {url[:200]}")
            logger.info(f"[AutoDetect] SQLi error-triggered: {method} {url[:120]} → HTTP 500")
        elif has_sqli_error:
            _record("vulnerability", f"Error-based SQL Injection — {target_base[-60:]}", "high",
                    f"SQL error leaked in HTTP {status} response. URL: {url[:200]}")
            logger.info(f"[AutoDetect] SQLi error-based: {method} {url[:120]} → HTTP {status}")

        # ── 2. XSS (Reflected + Stored indicators) ──
        xss_payloads = [r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
                        r"onfocus\s*=", r"onmouseover\s*=", r"<img\s+src\s*=",
                        r"<svg\s+onload", r"<iframe", r"<body\s+onload",
                        r"document\.cookie", r"alert\s*\(", r"prompt\s*\(",
                        r"confirm\s*\(", r"eval\s*\("]
        xss_in_req = any(_re.search(p, url_lower) or _re.search(p, body_lower) for p in xss_payloads)
        if xss_in_req and status in (200, 500):
            for p in xss_payloads:
                if _re.search(p, resp_lower):
                    _record("vulnerability", f"Reflected XSS — {target_base[-60:]}", "high",
                            f"XSS payload reflected in HTTP {status} response. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] XSS reflected: {method} {url[:120]}")
                    break

        # ── 3. COMMAND INJECTION / RCE ──
        cmdi_patterns = [r";\s*(?:ls|cat|id|whoami|uname|pwd|dir|ping|nslookup|curl|wget)",
                         r"\|\s*(?:ls|cat|id|whoami|uname|pwd|dir)",
                         r"`(?:ls|cat|id|whoami|uname|pwd)`",
                         r"\$\((?:ls|cat|id|whoami|uname|pwd)\)",
                         r"\|\|.*(?:ls|cat|id|whoami)", r"&&.*(?:ls|cat|id|whoami)"]
        cmdi_in_req = any(_re.search(p, url_lower) or _re.search(p, body_lower) for p in cmdi_patterns)
        cmdi_resp_sigs = [r"uid=\d+\(\w+\)", r"root:x:0:0:", r"linux\s+\d+\.\d+",
                          r"/bin/(?:ba)?sh", r"windows nt \d+\.\d+",
                          r"total\s+\d+\s+drwx", r"directory of c:\\"]
        cmdi_in_resp = any(_re.search(p, resp_lower) for p in cmdi_resp_sigs)
        if cmdi_in_req and cmdi_in_resp and status == 200:
            _record("vulnerability", f"OS Command Injection — {target_base[-60:]}", "critical",
                    f"Command output detected in HTTP {status} response. URL: {url[:200]}")
            logger.info(f"[AutoDetect] Command injection: {method} {url[:120]}")

        # ── 4. PATH TRAVERSAL / LFI ──
        lfi_patterns = [r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e/", r"\.\.%2f",
                        r"etc/passwd", r"etc/shadow", r"windows/win\.ini",
                        r"boot\.ini", r"proc/self"]
        lfi_in_req = any(_re.search(p, url_lower) or _re.search(p, body_lower) for p in lfi_patterns)
        lfi_resp_sigs = ["root:x:0:0:", "daemon:x:", "bin:x:", "[boot loader]",
                         "[operating systems]", "; for 16-bit app support",
                         "nobody:x:", "www-data:x:"]
        lfi_in_resp = any(sig in resp_lower for sig in lfi_resp_sigs)
        if lfi_in_req and lfi_in_resp and status == 200:
            _record("vulnerability", f"Local File Inclusion — {target_base[-60:]}", "critical",
                    f"System file content in HTTP {status} response. URL: {url[:200]}")
            logger.info(f"[AutoDetect] LFI confirmed: {method} {url[:120]}")

        # ── 5. SSRF ──
        ssrf_patterns = [r"url=https?://", r"target=https?://", r"dest=https?://",
                         r"uri=https?://", r"path=https?://", r"domain=",
                         r"url=file://", r"url=dict://", r"url=gopher://",
                         r"169\.254\.169\.254", r"127\.0\.0\.1", r"localhost",
                         r"0\.0\.0\.0", r"\[::1\]", r"metadata\.google"]
        ssrf_in_req = any(_re.search(p, url_lower) or _re.search(p, body_lower) for p in ssrf_patterns)
        ssrf_resp_sigs = ["ami-id", "instance-id", "instance-type", "iam/security-credentials",
                          "computemetadata", "latest/meta-data", "169.254.169.254"]
        ssrf_in_resp = any(sig in resp_lower for sig in ssrf_resp_sigs)
        if ssrf_in_req and ssrf_in_resp and status == 200:
            _record("vulnerability", f"Server-Side Request Forgery — {target_base[-60:]}", "critical",
                    f"Internal/cloud metadata in response. URL: {url[:200]}")
            logger.info(f"[AutoDetect] SSRF confirmed: {method} {url[:120]}")

        # ── 6. XXE (XML External Entity) ──
        xxe_patterns = [r"<!entity", r"<!doctype.*\[", r"system\s+[\"']file://",
                        r"system\s+[\"']http://", r"public\s+[\"']"]
        xxe_in_req = any(_re.search(p, body_lower) for p in xxe_patterns)
        if xxe_in_req and status == 200 and lfi_in_resp:
            _record("vulnerability", f"XML External Entity (XXE) — {target_base[-60:]}", "critical",
                    f"XXE payload returned system file content. URL: {url[:200]}")
            logger.info(f"[AutoDetect] XXE confirmed: {method} {url[:120]}")

        # ── 7. SSTI (Server-Side Template Injection) ──
        ssti_payloads = {"{{7*7}}": "49", "{{7*'7'}}": "7777777", "${7*7}": "49",
                         "<%=7*7%>": "49", "{7*7}": "49", "#{7*7}": "49"}
        for payload, expected in ssti_payloads.items():
            if payload in url or payload in (req_body or ""):
                if expected in (resp_text or ""):
                    _record("vulnerability", f"Server-Side Template Injection — {target_base[-60:]}", "critical",
                            f"SSTI payload '{payload}' evaluated to '{expected}'. URL: {url[:200]}",
                            f"Sent: {payload}, Got: {expected} in response")
                    logger.info(f"[AutoDetect] SSTI confirmed: {method} {url[:120]}")
                    break

        # ── 8. NOSQL INJECTION ──
        nosql_patterns = [r'\$gt', r'\$ne', r'\$regex', r'\$where', r'\$exists',
                          r'true,\s*\$where', r'\{\s*"\$gt"\s*:', r'\[\$ne\]']
        nosql_in_req = any(_re.search(p, url_lower) or _re.search(p, body_lower) for p in nosql_patterns)
        if nosql_in_req and status == 200 and len(resp_text) > 50:
            _record("vulnerability", f"NoSQL Injection — {target_base[-60:]}", "high",
                    f"NoSQL operator in request got HTTP {status}. URL: {url[:200]}")
            logger.info(f"[AutoDetect] NoSQL injection: {method} {url[:120]}")

        # ── 9. LDAP INJECTION ──
        ldap_patterns = [r"\)\(\|", r"\)\(&", r"\*\)\(", r"admin\)\(&",
                         r"\)\(\w+=\*", r"objectclass=\*"]
        ldap_in_req = any(_re.search(p, url_lower) or _re.search(p, body_lower) for p in ldap_patterns)
        if ldap_in_req and status == 200 and len(resp_text) > 50:
            _record("vulnerability", f"LDAP Injection — {target_base[-60:]}", "high",
                    f"LDAP filter injection got HTTP {status}. URL: {url[:200]}")
            logger.info(f"[AutoDetect] LDAP injection: {method} {url[:120]}")

        # ── 10. CRLF / HTTP HEADER INJECTION ──
        if "%0d%0a" in url_lower or "%0D%0A" in url:
            crlf_marker = _re.search(r'%0[dD]%0[aA]([^%&/]+)', url)
            if crlf_marker:
                injected_hdr = crlf_marker.group(1).split(":")[0].strip().lower()
                if injected_hdr and injected_hdr in resp_lower[:2000]:
                    _record("vulnerability", f"CRLF / Header Injection — {netloc}{parsed.path[:40]}", "high",
                            f"Injected header '{injected_hdr}' reflected. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] CRLF injection: {netloc} — header '{injected_hdr}' reflected")

        # ── 11. OPEN REDIRECT ──
        redirect_params = _re.search(r'[?&](?:to|url|redirect|next|return|goto|dest|continue|returnurl|rurl|redir)=([^&]+)', url_lower)
        if redirect_params and status in (200, 301, 302, 303, 307, 308):
            redir_val = unquote(redirect_params.group(1))
            redir_domain = urlparse(redir_val).netloc if "://" in redir_val else ""
            if redir_domain and redir_domain != netloc:
                _record("vulnerability", f"Open Redirect — {netloc}{parsed.path}", "medium",
                        f"Redirect to external domain {redir_domain}. URL: {url[:200]}",
                        f"Redirected from {netloc} to {redir_domain}")
                logger.info(f"[AutoDetect] Open redirect: {netloc} → {redir_domain}")

        # ── 12. SENSITIVE PATHS / INFORMATION DISCLOSURE ──
        sensitive_paths = {
            "/encryptionkeys": ("Encryption keys exposed", "critical"),
            "/.git/config": ("Git config exposed", "high"),
            "/.git/head": ("Git HEAD exposed", "high"),
            "/.git/": ("Git directory exposed", "high"),
            "/.svn/entries": ("SVN entries exposed", "high"),
            "/.svn/": ("SVN directory exposed", "high"),
            "/.hg/": ("Mercurial directory exposed", "high"),
            "/.env": ("Environment file exposed", "critical"),
            "/.env.bak": ("Environment backup exposed", "critical"),
            "/.env.local": ("Local env file exposed", "critical"),
            "/.env.production": ("Production env exposed", "critical"),
            "/.aws/credentials": ("AWS credentials exposed", "critical"),
            "/.docker/config.json": ("Docker config exposed", "critical"),
            "/ftp": ("FTP directory listing exposed", "high"),
            "/metrics": ("Metrics endpoint exposed", "medium"),
            "/server-status": ("Server status page exposed", "medium"),
            "/server-info": ("Server info page exposed", "medium"),
            "/debug": ("Debug endpoint exposed", "high"),
            "/actuator": ("Spring Actuator exposed", "high"),
            "/actuator/env": ("Actuator env exposed", "critical"),
            "/actuator/configprops": ("Actuator config exposed", "high"),
            "/actuator/heapdump": ("Heap dump exposed", "critical"),
            "/graphql": ("GraphQL endpoint exposed", "medium"),
            "/phpinfo": ("PHP info page exposed", "medium"),
            "/phpinfo.php": ("PHP info page exposed", "medium"),
            "/info.php": ("PHP info page exposed", "medium"),
            "/wp-admin": ("WordPress admin panel", "medium"),
            "/wp-login.php": ("WordPress login exposed", "medium"),
            "/wp-config.php.bak": ("WordPress config backup", "critical"),
            "/elmah.axd": ("Error log handler exposed", "medium"),
            "/trace": ("Trace endpoint exposed", "high"),
            "/heapdump": ("Heap dump exposed", "critical"),
            "/backup": ("Backup directory exposed", "high"),
            "/console": ("Console endpoint exposed", "high"),
            "/swagger-ui.html": ("Swagger UI exposed", "medium"),
            "/swagger-ui/": ("Swagger UI exposed", "medium"),
            "/api-docs": ("API docs exposed", "medium"),
            "/v2/api-docs": ("API docs exposed", "medium"),
            "/v3/api-docs": ("OpenAPI docs exposed", "medium"),
            "/api/swagger.json": ("Swagger JSON exposed", "medium"),
            "/robots.txt": ("Robots.txt accessible", "info"),
            "/sitemap.xml": ("Sitemap accessible", "info"),
            "/crossdomain.xml": ("Crossdomain policy exposed", "medium"),
            "/clientaccesspolicy.xml": ("Client access policy exposed", "medium"),
            "/web.config": ("Web.config exposed", "high"),
            "/config.php": ("Config file exposed", "critical"),
            "/config.yml": ("Config file exposed", "high"),
            "/config.json": ("Config file exposed", "high"),
            "/database.yml": ("Database config exposed", "critical"),
            "/application.yml": ("App config exposed", "high"),
            "/application.properties": ("App properties exposed", "high"),
            "/.htaccess": ("Htaccess file exposed", "medium"),
            "/.htpasswd": ("Htpasswd file exposed", "critical"),
            "/admin": ("Admin panel exposed", "medium"),
            "/admin/": ("Admin panel exposed", "medium"),
            "/administrator": ("Admin panel exposed", "medium"),
            "/phpmyadmin": ("phpMyAdmin exposed", "high"),
            "/adminer.php": ("Adminer DB tool exposed", "high"),
            "/cgi-bin/": ("CGI directory exposed", "medium"),
            "/test": ("Test endpoint exposed", "low"),
            "/test/": ("Test directory exposed", "low"),
            "/temp": ("Temp directory exposed", "medium"),
            "/tmp": ("Tmp directory exposed", "medium"),
            "/logs": ("Log directory exposed", "high"),
            "/log": ("Log directory exposed", "high"),
            "/error_log": ("Error log exposed", "high"),
            "/access.log": ("Access log exposed", "high"),
            "/.bash_history": ("Bash history exposed", "critical"),
            "/.ssh/": ("SSH directory exposed", "critical"),
            "/id_rsa": ("SSH private key exposed", "critical"),
            "/server.key": ("Server private key exposed", "critical"),
            "/private.key": ("Private key exposed", "critical"),
            "/.npmrc": ("NPM config exposed", "high"),
            "/package.json": ("Package.json exposed", "low"),
            "/composer.json": ("Composer config exposed", "low"),
            "/Gemfile": ("Gemfile exposed", "low"),
            "/Dockerfile": ("Dockerfile exposed", "medium"),
            "/docker-compose.yml": ("Docker compose exposed", "medium"),
            "/.dockerignore": ("Docker ignore exposed", "low"),
            "/Vagrantfile": ("Vagrantfile exposed", "medium"),
            "/Procfile": ("Procfile exposed", "low"),
            "/.travis.yml": ("CI config exposed", "medium"),
            "/Jenkinsfile": ("Jenkinsfile exposed", "medium"),
            "/.circleci/config.yml": ("CircleCI config exposed", "medium"),
            "/api/": ("API root exposed", "info"),
            "/api/v1/": ("API v1 root exposed", "info"),
            "/api/v2/": ("API v2 root exposed", "info"),
            "/health": ("Health endpoint", "info"),
            "/healthcheck": ("Health check", "info"),
            "/status": ("Status endpoint", "info"),
            "/version": ("Version endpoint exposed", "low"),
            "/info": ("Info endpoint exposed", "low"),
        }
        if status == 200 and len(resp_text) > 20:
            for sens_path, (title, sev) in sensitive_paths.items():
                if path_lower.rstrip("/") == sens_path.rstrip("/") or path_lower.startswith(sens_path):
                    _record("information_disclosure", f"{title} — {netloc}", sev,
                            f"Path {parsed.path} returned HTTP {status} ({len(resp_text)} bytes). URL: {url[:200]}")
                    logger.info(f"[AutoDetect] Sensitive path: {parsed.path} on {netloc} → HTTP {status}")
                    break

        # ── 13. SECURITY HEADERS MISSING ──
        if status == 200 and method == "GET" and resp_text and len(resp_text) > 100:
            resp_headers_lower = resp_text[:2000].lower()
            if "<!doctype html" in resp_lower or "<html" in resp_lower:
                missing_headers = []
                if "x-frame-options" not in resp_headers_lower and "frame-ancestors" not in resp_headers_lower:
                    missing_headers.append("X-Frame-Options (Clickjacking)")
                if "x-content-type-options" not in resp_headers_lower:
                    missing_headers.append("X-Content-Type-Options (MIME sniffing)")
                if "content-security-policy" not in resp_headers_lower:
                    missing_headers.append("Content-Security-Policy")
                if "strict-transport-security" not in resp_headers_lower:
                    missing_headers.append("Strict-Transport-Security (HSTS)")
                if "x-xss-protection" not in resp_headers_lower:
                    missing_headers.append("X-XSS-Protection")
                if missing_headers and len(missing_headers) >= 3:
                    _record("misconfiguration", f"Missing Security Headers — {netloc}", "medium",
                            f"Missing: {', '.join(missing_headers[:5])}. URL: {url[:200]}",
                            f"Missing headers: {', '.join(missing_headers)}")
                    logger.info(f"[AutoDetect] Missing headers on {netloc}: {', '.join(missing_headers[:3])}")

        # ── 14. INFORMATION LEAKAGE (stack traces, debug info, version) ──
        info_leak_sigs = [
            ("stacktrace", r"(?:at\s+\w+\.\w+\.\w+\(|traceback \(most recent|file \".*\", line \d+|exception in thread)", "Stack trace in response", "medium"),
            ("debug_info", r"(?:debug\s*=\s*true|debug mode|django debug|laravel.*exception|symfony.*exception)", "Debug information exposed", "medium"),
            ("db_connection", r"(?:jdbc:|mongodb://|mysql://|postgres://|redis://|amqp://)", "Database connection string exposed", "high"),
            ("api_key_leak", r"(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token)\s*[:=]\s*['\"][a-zA-Z0-9]{16,}", "API key/secret exposed in response", "high"),
            ("aws_key", r"(?:AKIA[0-9A-Z]{16}|aws_access_key_id|aws_secret_access_key)", "AWS credentials exposed", "critical"),
            ("private_key", r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private key exposed in response", "critical"),
            ("internal_ip", r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})", "Internal IP address exposed", "low"),
        ]
        for leak_name, pattern, title, sev in info_leak_sigs:
            if _re.search(pattern, resp_lower if sev != "critical" else (resp_text[:5000] if resp_text else "")):
                _record("information_disclosure", f"{title} — {netloc}{parsed.path[:30]}", sev,
                        f"{title} in HTTP {status} response. URL: {url[:200]}")
                logger.info(f"[AutoDetect] Info leak ({leak_name}): {url[:120]}")
                break

        # ── 15. CORS MISCONFIGURATION ──
        if "origin" in url_lower or "origin" in body_lower:
            cors_sigs = ["access-control-allow-origin: *", "access-control-allow-credentials: true"]
            if any(sig in resp_lower for sig in cors_sigs):
                _record("misconfiguration", f"CORS Misconfiguration — {netloc}", "medium",
                        f"Permissive CORS policy detected. URL: {url[:200]}")
                logger.info(f"[AutoDetect] CORS misconfiguration: {url[:120]}")

        # ── 16. HOST HEADER INJECTION ──
        if method in ("GET", "POST") and resp_text:
            evil_hosts = ["evil.com", "attacker.com", "burpcollaborator"]
            for evil in evil_hosts:
                if evil in body_lower or evil in url_lower:
                    if evil in resp_lower:
                        _record("vulnerability", f"Host Header Injection — {netloc}", "medium",
                                f"Injected host '{evil}' reflected in response. URL: {url[:200]}")
                        logger.info(f"[AutoDetect] Host header injection: {url[:120]}")
                        break

        # ── 17. DIRECTORY LISTING ──
        if status == 200 and resp_text:
            dir_listing_sigs = ["index of /", "directory listing for", "<title>directory listing",
                                "parent directory</a>", "[to parent directory]",
                                '<a href="?c=n&o=a">', "last modified</a>"]
            if any(sig in resp_lower for sig in dir_listing_sigs):
                _record("information_disclosure", f"Directory Listing — {netloc}{parsed.path}", "medium",
                        f"Directory listing enabled at {parsed.path}. URL: {url[:200]}")
                logger.info(f"[AutoDetect] Directory listing: {url[:120]}")

        # ── 18. JWT ISSUES ──
        if resp_text and status == 200:
            jwt_match = _re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', resp_text[:3000])
            if jwt_match:
                import base64
                try:
                    header = jwt_match.group(0).split('.')[0]
                    padding = 4 - len(header) % 4
                    decoded = base64.urlsafe_b64decode(header + "=" * padding).decode()
                    if '"alg":"none"' in decoded.lower() or '"alg": "none"' in decoded.lower():
                        _record("vulnerability", f"JWT None Algorithm — {netloc}", "critical",
                                f"JWT with alg:none in response. URL: {url[:200]}")
                        logger.info(f"[AutoDetect] JWT none algorithm: {url[:120]}")
                    elif '"alg":"hs256"' in decoded.lower():
                        _record("information_disclosure", f"JWT Token Exposed — {netloc}", "low",
                                f"JWT token in HTTP response. URL: {url[:200]}")
                except Exception:
                    pass

        # ── 19. INSECURE DESERIALIZATION INDICATORS ──
        deser_patterns = [r"rO0ABX", r"aced0005", r"O:4:\"", r"a:2:\{",
                          r"java\.lang\.runtime", r"__reduce__"]
        deser_in_req = any(_re.search(p, url_lower) or _re.search(p, body_lower) for p in deser_patterns)
        deser_resp_sigs = ["classnotfoundexception", "java.io.invalidclassexception",
                           "unserialize()", "objectinputstream", "deserializ"]
        deser_in_resp = any(sig in resp_lower for sig in deser_resp_sigs)
        if deser_in_req and deser_in_resp:
            _record("vulnerability", f"Insecure Deserialization — {target_base[-60:]}", "critical",
                    f"Deserialization error in response to serialized payload. URL: {url[:200]}")
            logger.info(f"[AutoDetect] Deserialization: {method} {url[:120]}")

        # ── 20. BROKEN ACCESS CONTROL / IDOR ──
        if method in ("GET", "PUT", "DELETE", "PATCH") and status == 200:
            idor_path = _re.search(r'/(?:user|account|profile|order|invoice|document|file|admin)/(\d+)', path_lower)
            if idor_path:
                _record("vulnerability", f"Potential IDOR — {netloc}{parsed.path[:50]}", "medium",
                        f"Resource accessed with numeric ID {idor_path.group(1)}. Verify authorization. URL: {url[:200]}",
                        f"Path: {parsed.path}, Method: {method}, Status: {status}")
                logger.info(f"[AutoDetect] Potential IDOR: {method} {url[:120]}")

        # ── 21. HTTP VERB TAMPERING ──
        if method in ("PUT", "DELETE", "PATCH", "OPTIONS", "TRACE") and status == 200 and len(resp_text) > 50:
            if method == "TRACE" and method.lower() in resp_lower:
                _record("vulnerability", f"HTTP TRACE Enabled — {netloc}", "medium",
                        f"TRACE method reflected request. URL: {url[:200]}")
                logger.info(f"[AutoDetect] TRACE enabled: {url[:120]}")
            elif method in ("PUT", "DELETE") and "api" not in path_lower:
                _record("misconfiguration", f"Unsafe HTTP Method {method} Allowed — {netloc}{parsed.path[:30]}", "medium",
                        f"HTTP {method} accepted on non-API path. URL: {url[:200]}")
                logger.info(f"[AutoDetect] Unsafe method {method}: {url[:120]}")

        # ── 22. SUBDOMAIN TAKEOVER INDICATORS ──
        takeover_sigs = [
            "there is no app configured at that hostname",
            "nosuchchannel", "no such app", "herokucdn.com/error-pages",
            "the thing you were looking for is no longer here",
            "do you want to register", "domain is not configured",
            "this domain is not connected", "project not found",
            "repository not found", "this page is reserved",
            "nosuchbucket", "the specified bucket does not exist",
            "invalidbucketname", "bucket not found",
        ]
        if any(sig in resp_lower for sig in takeover_sigs):
            _record("vulnerability", f"Subdomain Takeover Possible — {netloc}", "high",
                    f"Unclaimed service indicator in response. URL: {url[:200]}")
            logger.info(f"[AutoDetect] Subdomain takeover indicator: {netloc}")

        # ── 23. DEFAULT CREDENTIALS / WEAK AUTH ──
        weak_creds = [("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                       ("root", "root"), ("root", "toor"), ("test", "test"),
                       ("guest", "guest"), ("user", "user"), ("admin", "")]
        for uname, pwd in weak_creds:
            if (f'"username":"{uname}"' in body_lower or f"username={uname}" in body_lower) and \
               (f'"password":"{pwd}"' in body_lower or f"password={pwd}" in body_lower):
                if status == 200 and ("token" in resp_lower or "session" in resp_lower or
                                      "welcome" in resp_lower or "dashboard" in resp_lower or
                                      "authenticated" in resp_lower):
                    _record("vulnerability", f"Default Credentials — {netloc}", "critical",
                            f"Login succeeded with {uname}:{pwd or '(empty)'}. URL: {url[:200]}",
                            f"Credentials: {uname}:{pwd or '(empty)'}")
                    logger.info(f"[AutoDetect] Default creds: {uname}:{pwd} on {netloc}")
                    break

        # ── 24. XML/SOAP INJECTION ──
        if "<?xml" in body_lower or "text/xml" in url_lower or "soap" in path_lower:
            xml_error_sigs = ["xmlparseentityref", "xml parsing error", "premature end",
                              "not well-formed", "entityref:", "invalid xml"]
            if any(sig in resp_lower for sig in xml_error_sigs):
                _record("vulnerability", f"XML Injection — {target_base[-60:]}", "medium",
                        f"XML parsing error in response. URL: {url[:200]}")
                logger.info(f"[AutoDetect] XML injection: {method} {url[:120]}")

        # ── 25. SERVER VERSION DISCLOSURE ──
        if status == 200 and resp_text:
            version_patterns = [
                (r"(?:apache|nginx|iis|lighttpd|caddy)/[\d.]+", "Web server version disclosed", "low"),
                (r"(?:php|asp\.net|express|django|flask|rails|spring|laravel)/[\d.]+", "Framework version disclosed", "low"),
                (r"x-powered-by:\s*[\w./]+", "X-Powered-By header exposed", "low"),
                (r"server:\s*[\w./-]+\s*[\d.]+", "Server header with version", "low"),
            ]
            for vp, vtitle, vsev in version_patterns:
                if _re.search(vp, resp_lower):
                    _record("information_disclosure", f"{vtitle} — {netloc}", vsev,
                            f"{vtitle} in response. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] Version disclosure: {url[:120]}")
                    break

        # ── 26. PROTOTYPE POLLUTION (JS) ──
        proto_patterns = ["__proto__", "constructor.prototype", "constructor[prototype]"]
        proto_in_req = any(p in url_lower or p in body_lower for p in proto_patterns)
        if proto_in_req and status == 200 and ("__proto__" in resp_lower or "polluted" in resp_lower):
            _record("vulnerability", f"Prototype Pollution — {target_base[-60:]}", "high",
                    f"Prototype pollution payload accepted. URL: {url[:200]}")
            logger.info(f"[AutoDetect] Prototype pollution: {method} {url[:120]}")

        # ── 27. MASS ASSIGNMENT ──
        mass_assign_fields = ["isadmin", "is_admin", "role", "admin", "permission",
                              "is_superuser", "user_type", "access_level"]
        if method in ("POST", "PUT", "PATCH"):
            mass_in_body = any(f in body_lower for f in mass_assign_fields)
            if mass_in_body and status == 200:
                if any(f in resp_lower for f in mass_assign_fields):
                    _record("vulnerability", f"Mass Assignment — {target_base[-60:]}", "high",
                            f"Privileged field accepted and reflected. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] Mass assignment: {method} {url[:120]}")

        # ── 28. RACE CONDITION INDICATORS ──
        if method == "POST" and status == 200:
            race_endpoints = ["/transfer", "/withdraw", "/redeem", "/apply",
                              "/submit", "/claim", "/confirm", "/execute",
                              "/process", "/activate", "/approve"]
            if any(ep in path_lower for ep in race_endpoints):
                _record("information_disclosure", f"Race Condition Target — {netloc}{parsed.path[:40]}", "info",
                        f"State-changing endpoint identified. Test for TOCTOU. URL: {url[:200]}")

        # ── 29. GRAPHQL INTROSPECTION ──
        if "graphql" in path_lower and status == 200:
            if "__schema" in body_lower or "__type" in body_lower:
                if "__schema" in resp_lower or "querytype" in resp_lower:
                    _record("information_disclosure", f"GraphQL Introspection Enabled — {netloc}", "medium",
                            f"Full schema introspection available. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] GraphQL introspection: {url[:120]}")

        # ── 30. WEBSOCKET ISSUES ──
        if "upgrade" in url_lower and "websocket" in url_lower:
            if status in (101, 200):
                _record("information_disclosure", f"WebSocket Endpoint — {netloc}{parsed.path[:40]}", "info",
                        f"WebSocket upgrade accepted. URL: {url[:200]}")

        # ── 31. FILE UPLOAD VULNERABILITIES ──
        if method == "POST" and resp_text and status == 200:
            upload_sigs = [".php", ".jsp", ".asp", ".aspx", ".exe", ".sh", ".py"]
            if any(f"filename=\"{ext}" in body_lower or f"filename='{ext}" in body_lower for ext in ["shell", "cmd", "backdoor"]):
                _record("vulnerability", f"Unrestricted File Upload — {target_base[-60:]}", "critical",
                        f"Potentially dangerous file uploaded. URL: {url[:200]}")
                logger.info(f"[AutoDetect] File upload: {method} {url[:120]}")
            elif any(ext in body_lower for ext in upload_sigs) and "multipart" in (req_body or "").lower()[:200]:
                if "uploaded" in resp_lower or "success" in resp_lower:
                    _record("vulnerability", f"Dangerous File Extension Uploaded — {target_base[-60:]}", "high",
                            f"Server accepted upload with dangerous extension. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] Dangerous upload: {method} {url[:120]}")

        # ── 32. BLIND SQLi TIMING ──
        timing_payloads = [r"sleep\s*\(\s*\d+\s*\)", r"waitfor\s+delay\s+'",
                           r"pg_sleep\s*\(", r"benchmark\s*\(\s*\d+"]
        timing_in_req = any(_re.search(p, url_lower) or _re.search(p, body_lower) for p in timing_payloads)
        if timing_in_req and status == 200:
            _record("vulnerability", f"Blind SQLi (Time-based) — {target_base[-60:]}", "critical",
                    f"Time-based SQLi payload accepted with HTTP {status}. URL: {url[:200]}")
            logger.info(f"[AutoDetect] Blind SQLi timing: {method} {url[:120]}")

        # ── 33. XPATH INJECTION ──
        xpath_patterns = [r"'\s*or\s+'1'\s*=\s*'1", r"'\s*and\s+'1'\s*=\s*'1",
                          r"count\s*\(", r"string-length\s*\(", r"substring\s*\("]
        xpath_in_req = any(_re.search(p, url_lower) or _re.search(p, body_lower) for p in xpath_patterns)
        xpath_error_sigs = ["xpath", "xmlquerylanguage", "expression is not valid",
                            "invalid predicate", "unknown nodetype"]
        xpath_in_resp = any(sig in resp_lower for sig in xpath_error_sigs)
        if xpath_in_req and xpath_in_resp:
            _record("vulnerability", f"XPath Injection — {target_base[-60:]}", "high",
                    f"XPath error in response to injection payload. URL: {url[:200]}")
            logger.info(f"[AutoDetect] XPath injection: {method} {url[:120]}")

        # ── 34. EMAIL INJECTION ──
        email_patterns = [r"%0[aA]cc:", r"%0[aA]bcc:", r"%0[dD]%0[aA]subject:",
                          r"\r\ncc:", r"\r\nbcc:", r"\ncc:", r"\nbcc:"]
        email_in_req = any(_re.search(p, url_lower) or _re.search(p, body_lower) for p in email_patterns)
        if email_in_req and status == 200:
            if "mail" in path_lower or "contact" in path_lower or "email" in body_lower:
                _record("vulnerability", f"Email Header Injection — {target_base[-60:]}", "high",
                        f"Email injection payload accepted. URL: {url[:200]}")
                logger.info(f"[AutoDetect] Email injection: {method} {url[:120]}")

        # ── 35. INSECURE COOKIE FLAGS ──
        if resp_text and status == 200:
            cookie_match = _re.findall(r'set-cookie:\s*([^\n]+)', resp_lower)
            for cookie_line in cookie_match:
                missing = []
                if "secure" not in cookie_line:
                    missing.append("Secure")
                if "httponly" not in cookie_line:
                    missing.append("HttpOnly")
                if "samesite" not in cookie_line:
                    missing.append("SameSite")
                if len(missing) >= 2:
                    cookie_name = cookie_line.split("=")[0].strip()
                    _record("misconfiguration", f"Insecure Cookie '{cookie_name[:20]}' — {netloc}", "medium",
                            f"Cookie missing flags: {', '.join(missing)}. URL: {url[:200]}",
                            f"Set-Cookie: {cookie_line[:200]}")
                    logger.info(f"[AutoDetect] Insecure cookie: {cookie_name[:20]} on {netloc}")
                    break

        # ── 36. BACKUP / SOURCE CODE FILES ──
        backup_exts = {".bak": "Backup", ".old": "Old file", ".orig": "Original file",
                       ".save": "Save file", ".swp": "Vim swap", ".swo": "Vim swap",
                       "~": "Backup tilde", ".tmp": "Temp file", ".dist": "Dist file",
                       ".sample": "Sample file", ".example": "Example file",
                       ".copy": "Copy file", ".tar.gz": "Archive", ".zip": "Archive",
                       ".sql": "SQL dump", ".log": "Log file", ".conf": "Config file"}
        if status == 200 and len(resp_text) > 50:
            for ext, label in backup_exts.items():
                if path_lower.endswith(ext):
                    _record("information_disclosure", f"{label} Exposed — {netloc}{parsed.path[-40:]}", "medium",
                            f"{label} file accessible at {parsed.path}. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] Backup file: {parsed.path} on {netloc}")
                    break

        # ── 37. API KEY / SECRET IN URL ──
        if resp_text:
            secret_url_patterns = [
                r'[?&](?:api[_-]?key|apikey|token|secret|password|passwd|pwd|auth)=([^&]{8,})',
            ]
            for p in secret_url_patterns:
                m = _re.search(p, url_lower)
                if m:
                    _record("information_disclosure", f"Secret in URL Parameter — {netloc}", "high",
                            f"Sensitive parameter in URL query string. URL: {url[:200]}",
                            f"Parameter value partially: {m.group(1)[:20]}...")
                    logger.info(f"[AutoDetect] Secret in URL: {url[:120]}")
                    break

        # ── 38. HTTP REQUEST SMUGGLING INDICATORS ──
        if method == "POST" and resp_text:
            smuggle_patterns = ["transfer-encoding: chunked", "content-length:"]
            if any(p in body_lower for p in smuggle_patterns):
                if "400 bad request" in resp_lower or "invalid request" in resp_lower:
                    _record("vulnerability", f"HTTP Smuggling Indicator — {netloc}", "high",
                            f"Unusual response to smuggling payload. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] HTTP smuggling indicator: {url[:120]}")

        # ── 39. CACHE POISONING INDICATORS ──
        if resp_text and status == 200:
            cache_headers = ["x-cache: hit", "cf-cache-status: hit", "age:"]
            if any(h in resp_lower for h in cache_headers):
                evil_in_req = any(e in url_lower or e in body_lower for e in ["evil.com", "attacker.com"])
                if evil_in_req and any(e in resp_lower for e in ["evil.com", "attacker.com"]):
                    _record("vulnerability", f"Web Cache Poisoning — {netloc}", "high",
                            f"Injected value cached and reflected. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] Cache poisoning: {url[:120]}")

        # ── 40. NEGATIVE VALUE / BUSINESS LOGIC ──
        if method == "POST" and status == 200:
            neg_patterns = [r'"(?:price|amount|quantity|total|cost|count)":\s*-\d',
                            r'(?:price|amount|quantity|total|cost|count)=-\d']
            if any(_re.search(p, body_lower) for p in neg_patterns):
                if "success" in resp_lower or "order" in resp_lower or "created" in resp_lower:
                    _record("vulnerability", f"Business Logic — Negative Value — {netloc}", "high",
                            f"Negative value accepted in transaction. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] Negative value: {method} {url[:120]}")

        # ── 41. AUTHENTICATION BYPASS INDICATORS ──
        auth_bypass_paths = ["/admin", "/api/admin", "/rest/admin", "/dashboard",
                             "/management", "/internal", "/panel"]
        if status == 200 and len(resp_text) > 100:
            if any(bp in path_lower for bp in auth_bypass_paths):
                auth_indicators = ["admin", "dashboard", "management", "configuration",
                                   "users", "settings", "panel"]
                if sum(1 for ai in auth_indicators if ai in resp_lower) >= 2:
                    _record("vulnerability", f"Admin Access Without Auth — {netloc}{parsed.path[:30]}", "critical",
                            f"Admin endpoint accessible. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] Auth bypass: {url[:120]}")

        # ── 42. EXPOSED SOURCE MAP FILES ──
        if status == 200 and (path_lower.endswith(".map") or path_lower.endswith(".js.map")):
            if "sources" in resp_lower and "mappings" in resp_lower:
                _record("information_disclosure", f"Source Map Exposed — {netloc}{parsed.path[-40:]}", "medium",
                        f"JavaScript source map accessible. URL: {url[:200]}")
                logger.info(f"[AutoDetect] Source map: {parsed.path} on {netloc}")

        # ── 43. EXPOSED ERROR PAGES WITH STACK TRACES ──
        if status >= 400 and resp_text:
            error_detail_sigs = [
                (r"traceback \(most recent call", "Python traceback", "medium"),
                (r"at\s+\w+\.\w+\.java:\d+", "Java stack trace", "medium"),
                (r"microsoft\.aspnet", "ASP.NET error", "medium"),
                (r"<b>warning</b>.*<b>", "PHP warning", "low"),
                (r"<b>fatal error</b>", "PHP fatal error", "medium"),
                (r"syntaxerror:", "JavaScript error", "low"),
                (r"referenceerror:", "JavaScript error", "low"),
                (r"typeerror:", "JavaScript error", "low"),
                (r"unhandledpromiserejection", "Node.js error", "medium"),
            ]
            for pattern, label, sev in error_detail_sigs:
                if _re.search(pattern, resp_lower):
                    _record("information_disclosure", f"{label} in Error Page — {netloc}", sev,
                            f"{label} exposed in HTTP {status} error response. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] Error detail ({label}): {url[:120]}")
                    break

        # ── 44. EXPOSED DATABASE CONTENT ──
        if status == 200 and resp_text:
            db_content_sigs = ["create table", "insert into", "drop table", "alter table",
                               "select * from", "grant all", "mysqldump"]
            if any(sig in resp_lower for sig in db_content_sigs):
                if path_lower.endswith((".sql", ".dump", ".bak", ".db")):
                    _record("information_disclosure", f"Database Dump Exposed — {netloc}", "critical",
                            f"Database content accessible at {parsed.path}. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] DB dump: {parsed.path} on {netloc}")

        # ── 45. CONTENT INJECTION / HTML INJECTION ──
        html_inject_payloads = [r"<h1>", r"<div\s", r"<p>", r"<form\s", r"<input\s"]
        html_in_req = any(_re.search(p, url_lower) or _re.search(p, body_lower) for p in html_inject_payloads)
        if html_in_req and status == 200:
            for p in html_inject_payloads:
                if _re.search(p, resp_lower) and not xss_in_req:
                    _record("vulnerability", f"HTML Injection — {target_base[-60:]}", "medium",
                            f"HTML tags reflected in response. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] HTML injection: {method} {url[:120]}")
                    break

        # ── 46. EXPOSED METRICS / MONITORING ──
        if status == 200 and resp_text:
            metrics_sigs = ["# help ", "# type ", "process_cpu_seconds_total",
                            "go_goroutines", "http_requests_total", "node_cpu_seconds_total"]
            if any(sig in resp_lower for sig in metrics_sigs):
                _record("information_disclosure", f"Prometheus Metrics Exposed — {netloc}", "medium",
                        f"Application metrics at {parsed.path}. URL: {url[:200]}")
                logger.info(f"[AutoDetect] Prometheus metrics: {parsed.path} on {netloc}")

        # ── 47. CORS WITH CREDENTIALS ──
        if resp_text and status == 200:
            has_allow_creds = "access-control-allow-credentials: true" in resp_lower
            origin_reflected = False
            if "origin" in resp_lower:
                for evil in ["evil.com", "attacker.com", "null"]:
                    if evil in body_lower or evil in url_lower:
                        if evil in resp_lower or "access-control-allow-origin: null" in resp_lower:
                            origin_reflected = True
                            break
            if has_allow_creds and origin_reflected:
                _record("vulnerability", f"CORS with Credentials — {netloc}", "high",
                        f"CORS allows credentials with reflected/null origin. URL: {url[:200]}")
                logger.info(f"[AutoDetect] CORS credentials: {url[:120]}")

        # ── 48. EXPOSED ADMIN PANELS / SCORE-BOARD ──
        admin_paths = {
            "/admin": ("Admin panel accessible", "high"),
            "/administration": ("Admin panel accessible", "high"),
            "/admin/config": ("Admin config accessible", "high"),
            "/admin/dashboard": ("Admin dashboard accessible", "high"),
            "/panel": ("Control panel accessible", "high"),
            "/manage": ("Management interface accessible", "high"),
            "/console": ("Console accessible", "high"),
            "/internal": ("Internal endpoint accessible", "high"),
            "/api/users": ("Users API exposed", "high"),
            "/api/admin": ("Admin API exposed", "high"),
            "/debug": ("Debug endpoint accessible", "high"),
            "/status": ("Status endpoint accessible", "low"),
            "/metrics": ("Metrics endpoint accessible", "medium"),
            "/health": ("Health check accessible", "low"),
            "/env": ("Environment info exposed", "high"),
            "/config": ("Config endpoint accessible", "high"),
        }
        if status == 200 and len(resp_text) > 50:
            for admin_path, (title, sev) in admin_paths.items():
                if path_lower.rstrip("/") == admin_path or path_lower.startswith(admin_path + "/"):
                    _record("information_disclosure", f"{title} — {netloc}", sev,
                            f"Accessible at {parsed.path}. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] Admin/API path: {parsed.path} on {netloc}")
                    break

        # ── 49. HTTP SECURITY RESPONSE HEADERS ANALYSIS ──
        if status == 200 and resp_text and len(resp_text) > 200:
            if "access-control-allow-origin: *" in resp_lower:
                _record("misconfiguration", f"Wildcard CORS — {netloc}", "medium",
                        f"Access-Control-Allow-Origin: * on {parsed.path}. URL: {url[:200]}")
                logger.info(f"[AutoDetect] Wildcard CORS: {url[:120]}")

        # ── 50. CHATBOT / AI COMMAND INJECTION ──
        if method == "POST" and status == 200:
            chat_endpoints = ["/api/chat", "/rest/chatbot", "/api/chatbot", "/chat"]
            if any(ep in path_lower for ep in chat_endpoints):
                if "function" in resp_lower or "command" in resp_lower or "execute" in resp_lower or "system" in resp_lower:
                    _record("vulnerability", f"Chatbot Command Injection — {netloc}", "medium",
                            f"Chatbot returned function/command data. URL: {url[:200]}")
                    logger.info(f"[AutoDetect] Chatbot injection: {url[:120]}")

    _TOOL_CONFIRM_PATTERNS = (
        ("sqlmap", ("sqlmap:", "sqlmap confirmed", "parameter 'q' is vulnerable",
                    "parameter is vulnerable", "boolean-based blind", "union query",
                    "time-based blind", "error-based")),
        ("nuclei", ("nuclei", "[critical]", "[high]", "[medium]", "template matched")),
        ("nikto", ("nikto:", "+ osvdb", "+ /")),
        ("dalfox", ("dalfox", "[poc]", "[vuln]")),
        ("wpscan", ("wpscan", "[!] title:")),
        ("ffuf", ("ffuf ::",)),
        ("hydra", ("hydra", "login:", "password:")),
        ("burp", ("burp",)),
    )

    def _infer_tool_and_confirmation(self, finding: Dict[str, Any]) -> tuple:
        """Look at evidence/details/title to attribute the tool that produced a
        finding, and decide whether the tool's own output implies a confirmed
        vulnerability. Returns (tool_name, is_confirmed)."""
        blob = " ".join([
            str(finding.get("evidence", "")),
            str(finding.get("details", "")),
            str(finding.get("title", "")),
        ]).lower()
        for tool, patterns in self._TOOL_CONFIRM_PATTERNS:
            for p in patterns:
                if p in blob:
                    return tool, True
        return "", False

    def _record_finding(self, args: Dict[str, Any]) -> str:
        finding = {
            "type": args.get("type", "information"),
            "title": args.get("title", ""),
            "severity": args.get("severity", "info"),
            "details": args.get("details", ""),
            "evidence": args.get("evidence", ""),
            "target": args.get("target", self.ctx.target),
            "next_steps": args.get("next_steps", ""),
            "source": "agentic_executor",
        }
        tool, confirmed_by_tool = self._infer_tool_and_confirmation(finding)
        if tool:
            finding["tool"] = tool
        if confirmed_by_tool:
            finding["confirmed"] = True
        self.result.findings.append(finding)
        # Post-finding reflection: for HIGH/CRITICAL confirmed findings, queue a
        # reflection turn asking the LLM "what does this UNLOCK?" and execute
        # 3-5 follow-up probes. Bounded per phase to avoid runaway.
        sev = (finding.get("severity") or "info").upper()
        if sev in ("HIGH", "CRITICAL") and confirmed_by_tool:
            if not hasattr(self, "_pending_reflections"):
                self._pending_reflections = []
            if len(self._pending_reflections) < 3:  # cap per phase
                self._pending_reflections.append(finding)
        # Auto-extract as a skill so future scans can reuse the exact probe.
        try:
            if sev in ("HIGH", "CRITICAL") and confirmed_by_tool and \
               finding.get("tool") == "custom_probe":
                from core.intel.skill_library import save_skill
                current = getattr(self.ctx, "technologies", {}) or {}
                tags = sorted({t for vs in current.values()
                                for t in (vs if isinstance(vs, list) else [vs])
                                if isinstance(t, str)})[:10]
                save_skill(
                    name=(finding.get("title","")[:60]),
                    description=finding.get("details","")[:400],
                    method="POST" if "post" in (finding.get("details","") or "").lower() else "GET",
                    url_template=finding.get("target") or self.ctx.target,
                    expected_signature=(finding.get("evidence","") or "")[:120],
                    tech_shape={"tags": tags},
                    scan_id=self.scan_id or "",
                )
        except Exception:
            pass
        logger.info(f"[AgenticExecutor] Finding: [{finding['severity']}] {finding['title']}"
                    f" | target={finding.get('target', '')} | details={finding.get('details', '')}"
                    f"{(' | evidence=' + finding.get('evidence', '')) if finding.get('evidence') else ''}"
                    f"{(' | tool=' + tool) if tool else ''}")

        ftype = finding.get("type", "").lower().strip()
        if hasattr(self.ctx, "add_vulnerability") and (
            ftype in self._VULN_TYPES or "vuln" in ftype or "inject" in ftype
            or (finding.get("severity") or "").upper() in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        ):
            self.ctx.add_vulnerability({
                "title": finding["title"],
                "type": ftype.upper(),
                "severity": (finding.get("severity") or "info").upper(),
                "details": finding.get("details", ""),
                "evidence": finding.get("evidence", ""),
                "proof": finding.get("evidence", ""),
                "target": finding.get("target", self.ctx.target),
                "location": finding.get("target", self.ctx.target),
                "tool": tool,
                "status": "CONFIRMED" if confirmed_by_tool else "UNCONFIRMED",
                "source": "agentic_executor",
                "source_agent": "agentic_executor",
                "confirmed": bool(confirmed_by_tool),
            })

        if finding["type"] == "subdomain":
            sub = finding.get("target", "") or finding.get("title", "")
            if sub and sub not in self.result.subdomains:
                self.result.subdomains.append(sub)

        if finding["type"] == "endpoint":
            ep = finding.get("target", "") or finding.get("title", "")
            if ep:
                self.result.raw_endpoints.append(ep)

        return f"Finding recorded: [{finding['severity']}] {finding['title']}. Continue investigating."

    def _filter_endpoints(self, args: Dict[str, Any]) -> str:
        endpoints = args.get("endpoints", [])
        keep_patterns = args.get("keep_patterns", [])

        import re

        static_extensions = {
            '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp', '.mp4',
            '.mp3', '.pdf', '.zip', '.tar', '.gz',
        }

        filtered = []
        removed = []
        for ep in endpoints:
            ep_lower = ep.lower().split('?')[0]

            is_static = any(ep_lower.endswith(ext) for ext in static_extensions)

            if is_static:
                force_keep = any(p in ep for p in keep_patterns)
                if not force_keep:
                    removed.append(ep)
                    continue

            filtered.append(ep)

        return (
            f"Filtered {len(endpoints)} → {len(filtered)} actionable endpoints "
            f"(removed {len(removed)} static assets).\n\n"
            f"Actionable endpoints:\n" +
            "\n".join(f"  - {ep}" for ep in filtered[:50]) +
            (f"\n  ... and {len(filtered) - 50} more" if len(filtered) > 50 else "")
        )

    _VULN_TYPES = frozenset({
        "vulnerability", "misconfiguration", "sqli", "sql_injection",
        "xss", "cross_site_scripting", "rce", "command_injection",
        "ssrf", "lfi", "rfi", "xxe", "ssti", "idor", "csrf",
        "open_redirect", "path_traversal", "file_upload",
        "auth_bypass", "broken_access", "privilege_escalation",
        "information_disclosure", "sensitive_data", "default_credentials",
        "cors_misconfiguration", "clickjacking", "header_injection",
        "deserialization", "weak_crypto", "session_fixation",
        "missing_header", "missing_security_header", "missing_cors",
        "nikto_finding", "nuclei_match", "nuclei_finding",
        "cross_origin_data_theft", "cors_wildcard",
        "tls_weakness", "ssl_issue", "certificate_issue",
        "directory_listing", "exposed_panel", "exposed_admin",
        "server_info_disclosure", "version_disclosure",
        "insecure_cookie", "missing_httponly", "missing_secure_flag",
        "subdomain_takeover", "dns_misconfiguration",
        "http_method_allowed", "verb_tampering",
        "jwt_weakness", "jwt_none_algorithm",
        "graphql_introspection", "api_exposure",
        "backup_file", "source_code_exposure",
        "race_condition", "business_logic",
        "nosql_injection", "ldap_injection", "xpath_injection",
        "crlf_injection", "http_smuggling",
        "prototype_pollution", "mass_assignment",
        "email_injection", "sms_injection",
        "weak_password", "brute_force",
        "cache_poisoning", "host_header_injection",
    })

    def _ingest_to_shared_context(self):
        """Push all findings back into shared context."""
        for finding in self.result.findings:
            ftype = finding.get("type", "").lower().strip()

            if ftype in self._VULN_TYPES or "vuln" in ftype or "inject" in ftype:
                _tool = finding.get("tool", "")
                _confirmed = bool(finding.get("confirmed"))
                self.ctx.add_vulnerability({
                    "title": finding["title"],
                    "type": ftype.upper(),
                    "severity": (finding.get("severity") or "info").upper(),
                    "details": finding.get("details", ""),
                    "evidence": finding.get("evidence", ""),
                    "proof": finding.get("evidence", ""),
                    "target": finding.get("target", self.ctx.target),
                    "location": finding.get("target", self.ctx.target),
                    "tool": _tool,
                    "status": "CONFIRMED" if _confirmed else "UNCONFIRMED",
                    "source": "agentic_executor",
                    "source_agent": "agentic_executor",
                    "confirmed": _confirmed,
                })

            elif ftype == "subdomain":
                sub = finding.get("target", "") or finding.get("title", "")
                if sub:
                    self.ctx.add_subdomains([sub], source="agentic_executor")

            elif ftype == "endpoint":
                ep = finding.get("target", "") or finding.get("title", "")
                if ep:
                    self.ctx.add_endpoints([ep], source="agentic_executor")

            elif ftype == "technology":
                tech = finding.get("title", "")
                target = finding.get("target", self.ctx.target)
                if tech:
                    self.ctx.add_technologies(target, [tech])

            elif ftype == "port":
                port_raw = finding.get("title", "")
                try:
                    port_num = int(str(port_raw).split("/")[0])
                except (ValueError, TypeError):
                    port_num = 0
                if port_num > 0:
                    port_info = {
                        "port": port_num,
                        "state": "open",
                        "service": finding.get("details", ""),
                        "target": finding.get("target", self.ctx.target),
                    }
                    self.ctx.add_ports([port_info])

            elif ftype == "credential":
                self.ctx.harvested_creds.append({
                    "title": finding["title"],
                    "details": finding.get("details", ""),
                    "target": finding.get("target", ""),
                })

            else:
                # Everything else — includes findings with ftype == "info",
                # "note", "recon", "" that used to be dropped. Preserve them
                # as INFO-severity vulns so the UI can show fingerprint /
                # negative-result / API-surface notes the LLM emitted.
                sev = (finding.get("severity") or "info").upper()
                if sev not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
                    sev = "INFO"
                _tool2 = finding.get("tool", "")
                _conf2 = bool(finding.get("confirmed"))
                if True:
                    self.ctx.add_vulnerability({
                        "title": finding["title"],
                        "type": (ftype or "info").upper(),
                        "severity": sev,
                        "details": finding.get("details", ""),
                        "evidence": finding.get("evidence", ""),
                        "proof": finding.get("evidence", ""),
                        "target": finding.get("target", self.ctx.target),
                        "location": finding.get("target", self.ctx.target),
                        "tool": _tool2,
                        "status": "CONFIRMED" if _conf2 else "UNCONFIRMED",
                        "source": "agentic_executor",
                        "source_agent": "agentic_executor",
                        "confirmed": _conf2,
                    })

        self._route_osint_findings()

        logger.info(
            f"[AgenticExecutor] Ingested {len(self.result.findings)} findings into shared context"
        )

    def _route_osint_findings(self):
        """When the phase is OSINT (or the finding is OSINT-shaped), mirror findings
        into the OSINT ctx fields that `_build_osint_context()` reads. Otherwise
        every OSINT finding lands only in result.findings and the OSINT summary
        panels stay at zero."""
        import re as _re

        phase_l = (getattr(self, "_phase", "") or "").lower()
        is_osint_phase = "osint" in phase_l

        osint_type_keywords = (
            "osint", "employee", "leak", "breach", "credential",
            "github", "cloud_bucket", "s3", "bucket", "domain_intel",
            "whois", "dns_intel", "threat", "identity",
        )

        email_re = _re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        gh_re = _re.compile(r'github\.com/([A-Za-z0-9_.-]+)', _re.IGNORECASE)
        breach_re = _re.compile(r'(\d+)\s+(?:total\s+)?(?:compromised|leaked|breached|infected)', _re.IGNORECASE)
        bucket_re = _re.compile(r'([a-z0-9.\-]+\.s3[.\-][a-z0-9\-]*\.amazonaws\.com|s3://[a-z0-9.\-]+|storage\.googleapis\.com/[a-z0-9.\-]+)', _re.IGNORECASE)

        def _get_list(name):
            cur = None
            if hasattr(self.ctx, name):
                cur = getattr(self.ctx, name, None)
            if cur is None and hasattr(self.ctx, "get"):
                try:
                    cur = self.ctx.get(name, None)
                except Exception:
                    cur = None
            return list(cur) if isinstance(cur, list) else []

        def _set_list(name, value):
            if hasattr(self.ctx, "update"):
                try:
                    self.ctx.update(name, value)
                    return
                except Exception:
                    pass
            try:
                setattr(self.ctx, name, value)
            except Exception:
                pass

        emps = _get_list("discovered_employees")
        emp_emails = {(e.get("email") or "").lower() for e in emps if isinstance(e, dict)}
        gh_profiles = _get_list("github_profiles")
        gh_names = {(g.get("username") or "") for g in gh_profiles if isinstance(g, dict)}
        leaks = _get_list("leaked_credentials")
        buckets = _get_list("cloud_buckets")
        bucket_names = {(b.get("name") or "") for b in buckets if isinstance(b, dict)}
        osint_findings = _get_list("osint_findings")

        touched = {"emp": False, "gh": False, "leak": False, "bucket": False, "osint": False}

        for finding in self.result.findings:
            ftype = (finding.get("type") or "").lower()
            title = finding.get("title") or ""
            details = finding.get("details") or ""
            evidence = finding.get("evidence") or ""
            blob = f"{title}\n{details}\n{evidence}"

            is_osint_finding = is_osint_phase or any(k in ftype for k in osint_type_keywords) \
                or "osint" in title.lower() or "leak" in title.lower() or "breach" in title.lower()

            if not is_osint_finding:
                continue

            osint_findings.append({
                "type": ftype or "osint",
                "title": title,
                "severity": finding.get("severity", "info"),
                "details": details,
                "evidence": evidence,
                "target": finding.get("target", getattr(self.ctx, "target", "")),
                "source": "agentic_executor",
            })
            touched["osint"] = True

            for m in email_re.finditer(blob):
                email = m.group(0).lower()
                if email.endswith((".png", ".jpg", ".gif", ".svg")):
                    continue
                if email in emp_emails:
                    continue
                name_part = email.split("@")[0].replace(".", " ").replace("_", " ").replace("-", " ")
                emps.append({"email": email, "name": name_part.title(), "source": "agentic_executor"})
                emp_emails.add(email)
                touched["emp"] = True

            for m in gh_re.finditer(blob):
                user = m.group(1)
                if user.lower() in ("orgs", "search", "settings", "login"):
                    continue
                if user in gh_names:
                    continue
                gh_profiles.append({"username": user, "source": "agentic_executor"})
                gh_names.add(user)
                touched["gh"] = True

            bm = breach_re.search(blob)
            if bm:
                try:
                    count = int(bm.group(1))
                    leaks.append({
                        "type": "breach_indicator",
                        "count": count,
                        "source": finding.get("target", "") or "agentic_executor",
                        "title": title,
                        "details": details[:500],
                    })
                    touched["leak"] = True
                except ValueError:
                    pass

            for m in bucket_re.finditer(blob):
                name = m.group(1)
                if name in bucket_names:
                    continue
                buckets.append({"name": name, "source": "agentic_executor", "title": title})
                bucket_names.add(name)
                touched["bucket"] = True

        if touched["emp"]:
            _set_list("discovered_employees", emps)
        if touched["gh"]:
            _set_list("github_profiles", gh_profiles)
        if touched["leak"]:
            _set_list("leaked_credentials", leaks)
        if touched["bucket"]:
            _set_list("cloud_buckets", buckets)
        if touched["osint"]:
            _set_list("osint_findings", osint_findings)
