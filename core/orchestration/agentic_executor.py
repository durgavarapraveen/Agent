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
PENTESTING_TOOLS = [
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
  - Example: if target is "preview.owasp-juice.shop", do NOT scan "owasp-juice.shop" or "juice.shop"
  - Example: if target is "staging.api.example.com", do NOT scan "api.example.com" or "example.com"
  - Every tool invocation MUST target {authorized_domain} or {authorized_target} exactly
  - If a tool requires a domain, use {authorized_domain} — never strip subdomains
- Record ALL findings with analyze_results — even "info" severity
- When you've exhausted what you can do, stop. Don't repeat tools pointlessly.
- If you discover a new attack surface (subdomain, API), investigate it before moving on.
- If a tool fails with "No tools available", do NOT retry the same tool. Use http_request as a fallback for manual testing.
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
        "fierce": 60, "amass": 90, "theharvester": 60,
        "nmap": 120, "masscan": 60, "nikto": 120,
        "sqlmap": 180, "nuclei": 120, "wpscan": 120,
        "ffuf": 90, "gobuster": 90, "feroxbuster": 90,
        "dirb": 90, "dirsearch": 90, "hydra": 120,
    }

    def __init__(self, llm_harness, tool_invocation_engine, shared_context, auth_context):
        self.llm = llm_harness
        self.tool_engine = tool_invocation_engine
        self.ctx = shared_context
        self.auth_context = auth_context
        self.result = AgenticResult()
        self._available_tools = None

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
        self._available_tools = self._probe_tool_availability()
        available_tools_str = ", ".join(sorted(self._available_tools)) if self._available_tools else "none (use http_request for all testing)"

        context_summary = json.dumps(self.ctx.get_full_summary(max_chars=4000), default=str)

        known_subdomains = ", ".join(self.ctx.subdomains[:20]) if self.ctx.subdomains else "none discovered yet"
        known_endpoints = str(len(self.ctx.endpoints)) + " endpoints"
        known_vulns = str(len(self.ctx.vulnerabilities)) + " vulnerabilities"
        known_techs = json.dumps(self.ctx.technologies, default=str) if self.ctx.technologies else "unknown"

        user_message = (
            f"## Objective\n{objective}\n\n"
            f"## Phase\n{phase}\n\n"
            f"## Target\n{self.ctx.target}\n\n"
            f"## Current Knowledge\n"
            f"- Subdomains: {known_subdomains}\n"
            f"- Endpoints: {known_endpoints}\n"
            f"- Vulnerabilities: {known_vulns}\n"
            f"- Technologies: {known_techs}\n\n"
        )
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

        logger.info(f"[AgenticExecutor] Starting: objective='{objective[:80]}' phase={phase} max_rounds={max_rounds}")

        response = await self.llm.generate_with_tools(
            messages=messages,
            tools=PENTESTING_TOOLS,
            tool_executor=self._execute_tool_call,
            max_rounds=max_rounds,
            max_tokens=4096,
        )

        self.result.total_cost = response.cost_usd
        self.result.summary = response.content or ""

        logger.info(
            f"[AgenticExecutor] Completed: steps={self.result.steps_taken} "
            f"tools={self.result.tools_used} findings={len(self.result.findings)} "
            f"cost=${self.result.total_cost:.4f}"
        )

        self._ingest_to_shared_context()
        return self.result

    async def _execute_tool_call(self, fn_name: str, fn_args: Dict[str, Any]) -> str:
        """
        Bridge between LLM tool calls and actual tool execution.
        Returns the result as a string the LLM can read.
        """
        self.result.steps_taken += 1

        if fn_name == "run_tool":
            return await self._run_security_tool(fn_args)
        elif fn_name == "http_request":
            return await self._run_http_request(fn_args)
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
        params["timeout"] = self.TOOL_TIMEOUTS.get(tool_id, 60)

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
                stdout_trimmed = str(result.stdout)[:8000]
                output_parts.append(f"\n--- STDOUT ({len(str(result.stdout))} bytes) ---\n{stdout_trimmed}")

            if result.stderr:
                stderr_trimmed = str(result.stderr)[:2000]
                output_parts.append(f"\n--- STDERR ---\n{stderr_trimmed}")

            if result.data:
                data_str = json.dumps(result.data, default=str)[:3000]
                output_parts.append(f"\n--- Parsed Data ---\n{data_str}")

            return "\n".join(output_parts)

        except Exception as e:
            error_msg = f"[ERROR] Tool execution crashed: {e}"
            self.result.errors_encountered.append(f"{tool_id}: {e}")
            logger.error(f"[AgenticExecutor] {error_msg}")
            return error_msg

    async def _run_http_request(self, args: Dict[str, Any]) -> str:
        method = args.get("method", "GET")
        url = args.get("url", "")
        headers = args.get("headers", {})
        body = args.get("body", "")
        follow = args.get("follow_redirects", True)

        self.result.tools_used.append(f"http_{method}")
        logger.info(f"[AgenticExecutor] HTTP {method} {url}")

        try:
            import httpx as httpx_lib
            async with httpx_lib.AsyncClient(follow_redirects=follow, timeout=30, verify=False) as client:
                resp = await client.request(method, url, headers=headers, content=body if body else None)

                output_parts = [
                    f"HTTP {resp.status_code} {resp.reason_phrase}",
                    f"URL: {resp.url}",
                    "\n--- Response Headers ---",
                ]
                for k, v in resp.headers.items():
                    output_parts.append(f"{k}: {v}")

                body_text = resp.text[:5000] if resp.text else "(empty body)"
                output_parts.append(f"\n--- Response Body ({len(resp.text)} bytes) ---\n{body_text}")

                return "\n".join(output_parts)

        except Exception as e:
            return f"[ERROR] HTTP request failed: {e}"

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
        self.result.findings.append(finding)
        logger.info(f"[AgenticExecutor] Finding: [{finding['severity']}] {finding['title']}"
                    f" | target={finding.get('target', '')} | details={finding.get('details', '')[:200]}"
                    f"{(' | evidence=' + finding.get('evidence', '')[:150]) if finding.get('evidence') else ''}")

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

    def _ingest_to_shared_context(self):
        """Push all findings back into shared context."""
        for finding in self.result.findings:
            ftype = finding.get("type", "")

            if ftype == "vulnerability" or ftype == "misconfiguration":
                self.ctx.add_vulnerability({
                    "title": finding["title"],
                    "type": ftype.upper(),
                    "severity": finding.get("severity", "info"),
                    "details": finding.get("details", ""),
                    "evidence": finding.get("evidence", ""),
                    "target": finding.get("target", self.ctx.target),
                    "source": "agentic_executor",
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
                port_info = {
                    "port": finding.get("title", ""),
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

        logger.info(
            f"[AgenticExecutor] Ingested {len(self.result.findings)} findings into shared context"
        )
