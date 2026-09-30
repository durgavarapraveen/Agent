from __future__ import annotations

from pathlib import Path
from typing import Optional


class PromptBuildingMixin:
    """Assemble LLM context/prompt strings and load phase prompt templates.

    Extracted from CentralBrain; reads shared self attrs (self.ctx) and calls
    self._summarize_context via MRO.
    """

    def _load_phase_prompt(self, phase: str) -> Optional[str]:
        prompt_map = {
            "recon": "core/prompts/brain/brain_recon.txt",
            "analyze": "core/prompts/brain/brain_analyze.txt",
            "exploit": "core/prompts/brain/brain_exploit.txt",
        }
        path = prompt_map.get(phase)
        if path and Path(path).exists():
            return Path(path).read_text(encoding="utf-8")
        return None

    def _summarize_context(self) -> str:

        lines = []
        
        # Target
        lines.append(f"Target: {self.ctx.target}")
        
        # Subdomains
        subs = self.ctx.get_subdomains()
        if subs:
            lines.append(f"Discovered subdomains: {len(subs)} ({', '.join(subs[:3])})")
        else:
            lines.append("Subdomains: None discovered yet")
        
        # Ports
        ports_data = self.ctx.data.get("ports", {})
        if ports_data:
            all_ports = []
            for _host, port_list in ports_data.items():
                all_ports.extend(port_list)
            lines.append(f"Open ports found: {len(set(all_ports))} ({', '.join(map(str, sorted(set(all_ports))[:5]))})")
        else:
            lines.append("Open ports: None scanned yet")
        
        # Technologies
        techs_by_host = self.ctx.data.get("technologies", {})
        if techs_by_host:
            all_techs = []
            for _host, tech_list in techs_by_host.items():
                all_techs.extend(tech_list)
            if all_techs:
                lines.append(f"Technologies identified: {', '.join(set(all_techs)[:3])}")
        
        # Endpoints
        endpoints = self.ctx.get_endpoints()
        if endpoints:
            lines.append(f"Web endpoints discovered: {len(endpoints)} ({', '.join(endpoints[:3])})")
        
        # Vulnerabilities
        vulns = self.ctx.data.get("vulnerabilities", [])
        if vulns:
            lines.append(f"Vulnerabilities found: {len(vulns)}")
            for vuln in vulns[:2]:
                severity = vuln.get("severity", "UNKNOWN")
                title = vuln.get("title", "Unknown")
                lines.append(f"  - {title} ({severity})")
        else:
            lines.append("Vulnerabilities: None identified yet")
        
        return "\n".join(lines)

    def _build_agent_context(self, keys: list) -> str:
        
        if not keys:
            return f"Target: {self.ctx.target}\nObjective: Complete assigned task"
        
        lines = []
        for key in keys:
            if key == "target":
                lines.append(f"Target: {self.ctx.target}")
            elif key == "subdomains":
                subs = self.ctx.get_subdomains()
                if subs:
                    lines.append(f"Subdomains ({len(subs)}): {', '.join(subs[:5])}")
            elif key == "ports":
                ports_data = self.ctx.data.get("ports", {})
                if ports_data:
                    lines.append(f"Open ports: {list(ports_data.keys())}")
            elif key == "technologies":
                techs = self.ctx.get_technologies(self.ctx.target)
                if techs:
                    lines.append(f"Technologies: {', '.join(techs[:3])}")
            elif key == "endpoints":
                eps = self.ctx.get_endpoints()
                if eps:
                    lines.append(f"Endpoints ({len(eps)}): {eps[:3]}")
            elif key == "vulnerabilities":
                vulns = self.ctx.data.get("vulnerabilities", [])
                if vulns:
                    lines.append(f"Known vulns ({len(vulns)}): {[v.get('title', '?') for v in vulns[:2]]}")
        
        return "\n".join(lines) if lines else f"Target: {self.ctx.target}"

    def _build_brain_prompt(self, phase: str, iteration: int) -> str:
        
        context = self._summarize_context()
        
        prompt = f"""You are an AUTONOMOUS PENTESTING ORCHESTRATION BRAIN.

⚠️  CRITICAL: You are Claude, an LLM. You orchestrate agents that execute tools.
You do NOT execute tools yourself. You DECIDE what agents should do.

Target: {self.ctx.target}
Phase: {phase.upper()} (Iteration {iteration})

CURRENT STATE:
{context}

WHAT AGENTS NEED (examples):

For Subdomain Discovery:
  objective: "Find all subdomains of target domain"
  tools: ["amass", "subfinder", "dig", "whois"]

For Port Scanning:
  objective: "Scan for open ports and services"
  tools: ["nmap", "masscan"]

For Tech Stack Detection:
  objective: "Identify web server, frameworks, CMS"
  tools: ["httpx", "whatweb", "wafw00f"]

For Directory Discovery:
  objective: "Find hidden directories and files"
  tools: ["gobuster", "feroxbuster", "ffuf"]

For JavaScript Analysis:
  objective: "Extract endpoints and secrets from JS"
  tools: ["curl", "strings"]

For Vulnerability Scanning:
  objective: "Scan for CVEs and known vulnerabilities"
  tools: ["nuclei", "nessus"]

YOUR ROLE:
1. Look at current state
2. Identify what's missing
3. Decide which tools would help
4. Spawn agent with objective + tools
5. Agent executes tools, you don't

PHASE RULES:
RECON: Discover targets (subdomains, ports, tech, endpoints)
ANALYZE: Find vulnerabilities
EXPLOIT: Execute vulnerabilities
REPORT: Compile findings

RESPONSE: JSON only (no other text)

Single agent:
{{
  "thinking": "why this helps fill the gap",
  "action": "spawn_agent",
  "agent_spec": {{
    "objective": "specific goal for agent",
    "tools": ["tool1", "tool2", "tool3"],
    "context_keys": ["target", "existing_data"],
    "max_steps": 8
  }}
}}

Phase complete:
{{
  "thinking": "why we have enough information",
  "action": "phase_complete"
}}

CRITICAL RULES:
✓ You orchestrate. Agents execute.
✓ Give agents both objective AND tools
✓ Only spawn agents that address gaps
✓ JSON only response"""
        
        return prompt
