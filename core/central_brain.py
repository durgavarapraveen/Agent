"""
CentralBrain - LLM decides everything.
No hardcoded planner. No fixed agent types.
Reads shared context, decides what to do, spawns agents, loops.
"""

import json
import logging
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from agents.llm_client import LLMClient, TaskTier
from agents.authorization import AuthorizationManager
from core.shared_context import SharedContext
from core.tool_registry import ToolRegistry
from core.agent_spawner import AgentSpawner
from core.token_optimizer import TokenOptimizer

logger = logging.getLogger(__name__)

BRAIN_SYSTEM = """You are an autonomous penetration testing brain.
You control a team of agents. You decide what to scan, test, exploit, and chain.

WORKFLOW:
1. RECON: Discover attack surface (subdomains, ports, tech, endpoints)
2. ANALYZE: Identify vulnerabilities from recon data
3. PLAN: Map attack chains and create exploitation plan
4. EXECUTE: Run approved exploits — chain results into follow-up attacks
5. REPORT: Generate findings report

RULES:
- Be thorough in recon before exploitation
- Each agent gets ONLY the data it needs (you pick context_keys)
- Don't repeat scans already done

CHAINING RULE (CRITICAL):
After each exploit succeeds, ask: "What did this unlock?"
  - SQLi found creds → spawn auth_bypass agent with those creds
  - Admin access gained → spawn upload/RCE agent on admin panel
  - LFI reads config → spawn SQLi agent with DB creds from config
  - RCE achieved → spawn privesc agent
  - SSRF hits metadata → spawn agent to use cloud keys
Document the chain: SQLi → auth_bypass → upload → RCE → privesc

PARALLEL RULE:
Spawn MULTIPLE agents when tasks are INDEPENDENT:
  - Recon: subdomains + ports + SSL = independent → spawn_agents
  - After SQLi: test admin panel + dump more data = independent → spawn_agents
  - Exploiting different endpoints = independent → spawn_agents
Spawn SINGLE agent when tasks DEPEND on previous result.

RESPONSE FORMAT (strict JSON):

Single agent (sequential):
{
  "thinking": "analysis and reasoning",
  "action": "spawn_agent",
  "agent_spec": {
    "objective": "what to do",
    "tools": ["tool1", "tool2"],
    "context_keys": ["target", "subdomains"],
    "vuln_type": "xss",
    "max_steps": 10
  }
}

Multiple agents (parallel):
{
  "thinking": "these tasks are independent because...",
  "action": "spawn_agents",
  "agent_specs": [
    {"objective": "task 1", "tools": [...], "context_keys": [...], "max_steps": 8},
    {"objective": "task 2", "tools": [...], "context_keys": [...], "max_steps": 8}
  ]
}

Phase transitions:
{"action": "phase_complete"}
{"action": "done"}"""


class CentralBrain:
    """The autonomous pentesting orchestrator. LLM drives everything."""

    def __init__(self, target: str, scope: Dict = None):
        self.llm = LLMClient.get()
        self.ctx = SharedContext(target, scope)
        self.tools = ToolRegistry()
        self.spawner = AgentSpawner(self.tools, self.ctx)
        self.auth = AuthorizationManager()
        self.start_time = datetime.now()
        self.max_agents_per_phase = 15
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
        self.failed_tools = set()  # NEW: Brain-level tool failure tracking
        self.consecutive_agent_failures = 0  # NEW: Track failure streak
        self.max_consecutive_failures = 3

    async def run(self, auth_document: str = ""):
        """Main entry point. Runs full pentest autonomously."""

        logger.info("=" * 60)
        logger.info("AUTONOMOUS PENTESTING BRAIN")
        logger.info("=" * 60)
        logger.info(f"Target: {self.ctx.target}")
        logger.info("=" * 60)

        # Phase 0: Parse authorization
        if auth_document:
            await self._parse_authorization(auth_document)
            
        logger.info("\nValidating tools...")
        await self.tools.validate_tools()

        # Phase 1: Deep recon
        logger.info("\n>>> PHASE 1: DEEP RECONNAISSANCE")
        await self._run_phase("recon")

        # Phase 2: Vulnerability analysis
        logger.info("\n>>> PHASE 2: VULNERABILITY ANALYSIS")
        await self._run_phase("analyze")

        # Phase 3: Exploit planning (human approval)
        logger.info("\n>>> PHASE 3: EXPLOIT PLANNING")
        plan = await self._generate_exploit_plan()

        if plan and plan.get("exploits"):
            approved = await self._human_approval(plan)
            if approved:
                # Phase 4: Exploitation
                logger.info("\n>>> PHASE 4: AUTONOMOUS EXPLOITATION")
                await self._run_phase("exploit")

        # Phase 5: Report
        logger.info("\n>>> PHASE 5: REPORT GENERATION")
        await self._generate_report()

        duration = (datetime.now() - self.start_time).total_seconds()
        logger.info(f"\nCompleted in {duration:.0f}s")
        logger.info(f"Agents spawned: {len(self.ctx.agents_spawned)}")
        logger.info(f"Vulnerabilities: {len(self.ctx.vulnerabilities)}")
        logger.info(f"Exploits executed: {len(self.ctx.exploit_results)}")

    async def _parse_authorization(self, auth_doc: str):
        """LLM parses authorization document to extract scope"""
        logger.info("Parsing authorization document...")
        self.ctx.log_brain("Parsing authorization document", "parse_auth")

        result = await self.llm.generate_json(
            f"Parse this authorization document and extract:\n"
            f"- domains: list of authorized domains\n"
            f"- max_tier: POC, SHALLOW, or DEEP\n"
            f"- restrictions: any restrictions mentioned\n"
            f"- valid_until: expiration date if mentioned\n\n"
            f"Document:\n{auth_doc[:3000]}\n\n"
            f"Return JSON: {{\"domains\": [...], \"max_tier\": \"...\", "
            f"\"restrictions\": [...], \"valid_until\": \"...\"}}",
            tier=TaskTier.SMALL,
        )

        if result and result.get("domains"):
            self.ctx.scope = result
            AuthorizationManager.create_scope_file(
                domains=result["domains"],
                max_tier=result.get("max_tier", "POC"),
            )
            logger.info(f"Scope: {result['domains']}, tier: {result.get('max_tier')}")

    async def _run_phase(self, phase: str):
        """LLM-driven loop with smart failure handling"""
        agents_this_phase = 0
        self.consecutive_agent_failures = 0
 
        phase_prompt = self._load_phase_prompt(phase)
 
        while agents_this_phase < self.max_agents_per_phase:
            summary = self.ctx.get_full_summary(max_chars=5000)
 
            # ✓ NEW: Tell LLM which tools failed
            failed_tools_warning = ""
            if self.failed_tools:
                failed_tools_warning = (
                    f"\n⚠ WARNING: These tools are not available (don't use them):\n"
                    f"  {', '.join(sorted(self.failed_tools))}\n"
                    f"Use only available tools.\n"
                )
 
            chain_context = ""
            if phase == "exploit" and self.ctx.exploit_results:
                chain_context = "\nEXPLOIT CHAIN SO FAR:\n"
                for er in self.ctx.exploit_results:
                    chain_context += (
                        f"  - {er.get('type','?')}: "
                        f"{'SUCCESS' if er.get('success') else 'FAILED'}\n"
                    )
 
            prompt = (
                f"PHASE: {phase}\n"
                f"TARGET: {self.ctx.target}\n"
                f"{failed_tools_warning}"  # NEW: Warn about failed tools
                f"\nDATA:\n{summary}\n"
                f"{chain_context}\n"
                f"Available tools: {self.tools.list_tools()}\n"
                f"Agents spawned: {agents_this_phase}/{self.max_agents_per_phase}\n"
                f"What should I do next?"
            )
 
            decision = await self.llm.generate_json(prompt, system=phase_prompt or BRAIN_SYSTEM)
 
            if not decision:
                self.consecutive_agent_failures += 1
                logger.warning(f"Brain returned empty (failure streak: {self.consecutive_agent_failures})")
                
                if self.consecutive_agent_failures > self.max_consecutive_failures:
                    logger.error(f"Too many failures ({self.consecutive_agent_failures}), ending {phase}")
                    break
                continue
 
            self.consecutive_agent_failures = 0
 
            action = decision.get("action", "phase_complete")
 
            if action in ("phase_complete", "done"):
                logger.info(f"✓ Phase '{phase}' complete")
                break
 
            # Spawn and execute agents
            if action == "spawn_agents":
                specs = decision.get("agent_specs", [])
                specs = [s for s in specs if s.get("objective")]
                if not specs:
                    continue
 
                agents = [self.spawner.spawn(s) for s in specs]
                results = await asyncio.gather(*[a.execute() for a in agents], return_exceptions=True)
 
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        logger.error(f"Agent {i} crashed: {result}")
                        self.consecutive_agent_failures += 1
                    elif result.get("status") == "failed":
                        logger.warning(f"Agent {i} failed: {result.get('reason')}")
                        self.consecutive_agent_failures += 1
                    else:
                        self.consecutive_agent_failures = 0
                        logger.info(f"✓ Agent {i} succeeded")
                    
                    # ✓ NEW: Learn from agent failures
                    if hasattr(agents[i], 'failed_tools'):
                        for failed_tool in agents[i].failed_tools:
                            self.failed_tools.add(failed_tool)
                            logger.warning(f"Brain learned: '{failed_tool}' is not available")
                    
                    agents_this_phase += 1
 
            elif action == "spawn_agent":
                spec = decision.get("agent_spec", {})
                if not spec.get("objective"):
                    continue
 
                agent = self.spawner.spawn(spec)
                result = await agent.execute()
                agents_this_phase += 1
 
                if result.get("status") == "failed":
                    self.consecutive_agent_failures += 1
                    logger.warning(f"Agent failed: {result.get('reason')}")
                else:
                    self.consecutive_agent_failures = 0
                
                # ✓ NEW: Learn from agent failures
                if hasattr(agent, 'failed_tools'):
                    for failed_tool in agent.failed_tools:
                        self.failed_tools.add(failed_tool)
                        logger.warning(f"Brain learned: '{failed_tool}' is not available")
    
    def _load_phase_prompt(self, phase: str) -> Optional[str]:
        """Load phase-specific prompt from file if available"""
        prompt_map = {
            "recon": "prompts/brain_recon.txt",
            "analyze": "prompts/brain_analyze.txt",
            "exploit": "prompts/brain_exploit.txt",
        }
        path = prompt_map.get(phase)
        if path and Path(path).exists():
            return Path(path).read_text(encoding="utf-8")
        return None

    async def _generate_exploit_plan(self) -> Optional[Dict]:
        """LLM generates complete exploitation plan from vulnerabilities"""
        if not self.ctx.vulnerabilities:
            logger.info("No vulnerabilities found. Skipping exploitation.")
            return None

        summary = self.ctx.get_full_summary(max_chars=6000)

        plan = await self.llm.generate_json(
            f"Based on these vulnerability findings, create an exploitation plan.\n\n"
            f"DATA:\n{summary}\n\n"
            f"For each vulnerability, describe:\n"
            f"- How to exploit it (specific steps)\n"
            f"- What payload to use\n"
            f"- What proof to collect\n"
            f"- If it chains with other vulns\n"
            f"- Risk level of exploitation\n\n"
            f"Return JSON:\n"
            f"{{\n"
            f'  "risk_assessment": "overall risk level",\n'
            f'  "exploits": [\n'
            f'    {{\n'
            f'      "vuln_id": "VULN-001",\n'
            f'      "title": "...",\n'
            f'      "method": "...",\n'
            f'      "payload": "...",\n'
            f'      "proof": "what to capture",\n'
            f'      "chains_to": ["VULN-002"],\n'
            f'      "risk": "low|medium|high",\n'
            f'      "tools": ["tool1"]\n'
            f"    }}\n"
            f"  ],\n"
            f'  "attack_chains": [\n'
            f'    {{"chain": ["VULN-001", "VULN-003"], "impact": "..."}}\n'
            f"  ]\n"
            f"}}",
            tier=TaskTier.LARGE,
            max_tokens=3000,
        )

        if plan:
            self.ctx.exploit_plan = plan
            self.ctx.attack_chains = plan.get("attack_chains", [])

        return plan

    async def _human_approval(self, plan: Dict) -> bool:
        """Display plan and get human approval"""
        print("\n" + "=" * 60)
        print("EXPLOITATION PLAN - REQUIRES APPROVAL")
        print("=" * 60)
        print(f"\nTarget: {self.ctx.target}")
        print(f"Risk: {plan.get('risk_assessment', 'Unknown')}")
        print(f"\nVulnerabilities to exploit ({len(plan.get('exploits', []))}):\n")

        for i, exp in enumerate(plan.get("exploits", []), 1):
            print(f"  [{i}] [{exp.get('risk','?').upper()}] {exp.get('title', 'Unknown')}")
            print(f"      Method: {exp.get('method', '')[:80]}")
            print(f"      Proof: {exp.get('proof', '')[:80]}")
            if exp.get("chains_to"):
                print(f"      Chains to: {exp['chains_to']}")
            print()

        if plan.get("attack_chains"):
            print("Attack Chains:")
            for chain in plan["attack_chains"]:
                print(f"  {' -> '.join(chain.get('chain', []))}: {chain.get('impact', '')}")
            print()

        print("=" * 60)

        try:
            response = input("Approve this plan? [YES/NO/MODIFY]: ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            response = "NO"

        if response == "YES":
            logger.info("Plan APPROVED by human")
            self.ctx.log_brain("Human approved exploitation plan", "plan_approved")
            return True
        elif response == "MODIFY":
            modifications = input("Describe modifications: ").strip()
            self.ctx.log_brain(f"Human requested modifications: {modifications}", "plan_modified")
            # TODO: Re-generate plan with modifications
            return False
        else:
            logger.info("Plan REJECTED by human")
            self.ctx.log_brain("Human rejected exploitation plan", "plan_rejected")
            return False

    def _summarize_context(self) -> str:
        """Summarize current reconnaissance state"""
        
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
            for host, port_list in ports_data.items():
                all_ports.extend(port_list)
            lines.append(f"Open ports found: {len(set(all_ports))} ({', '.join(map(str, sorted(set(all_ports))[:5]))})")
        else:
            lines.append("Open ports: None scanned yet")
        
        # Technologies
        techs_by_host = self.ctx.data.get("technologies", {})
        if techs_by_host:
            all_techs = []
            for host, tech_list in techs_by_host.items():
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
        """Build agent context from shared context keys"""
        
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

    async def _spawn_and_run_agent(self, spec: Dict):
        """Spawn single agent and run it"""
        from core.dynamic_agent import DynamicAgent
        
        objective = spec.get("objective", "")
        tools = spec.get("tools", [])
        context_keys = spec.get("context_keys", [])
        max_steps = spec.get("max_steps", 10)
        
        logger.info(f"  Spawning agent: {objective}")
        
        # Build agent context from shared context
        agent_context = self._build_agent_context(context_keys)
        
        # Spawn agent
        agent_id = f"AGENT-{len(self.spawner.agents) + 1:03d}"
        
        agent = DynamicAgent(
            agent_id=agent_id,
            objective=objective,
            tool_registry=self.tools,
            shared_context=self.ctx,
            agent_context=agent_context,
            allowed_tools=tools,
            max_steps=max_steps
        )
        
        # Run agent
        logger.info(f"  Running {agent_id}...")
        result = await agent.execute()
        
        # Handle result
        if result.get("status") == "success":
            logger.info(f"  ✓ {agent_id} succeeded")
            self.ctx.add_event(f"{agent_id}: Success", result.get("results", {}))
        else:
            logger.warning(f"  ✗ {agent_id} failed: {result.get('reason', 'unknown')}")
            self.ctx.add_event(f"{agent_id}: Failed", result)

    async def _spawn_multiple_agents(self, specs: list):
        """Spawn multiple agents and run in parallel"""
        from core.dynamic_agent import DynamicAgent
        
        logger.info(f"  Spawning {len(specs)} agents in parallel...")
        
        agents = []
        for i, spec in enumerate(specs):
            objective = spec.get("objective", "")
            tools = spec.get("tools", [])
            context_keys = spec.get("context_keys", [])
            max_steps = spec.get("max_steps", 8)
            
            # Build context
            agent_context = self._build_agent_context(context_keys)
            
            # Create agent
            agent_id = f"AGENT-{len(agents) + 1:03d}"
            agent = DynamicAgent(
                agent_id=agent_id,
                objective=objective,
                tool_registry=self.tools,
                shared_context=self.ctx,
                agent_context=agent_context,
                allowed_tools=tools,
                max_steps=max_steps
            )
            agents.append(agent)
        
        # Run all in parallel
        logger.info(f"  Running {len(agents)} agents...")
        results = await asyncio.gather(*[agent.execute() for agent in agents])
        
        # Log results
        for agent, result in zip(agents, results):
            if result.get("status") == "success":
                logger.info(f"  ✓ {agent.agent_id} succeeded")
            else:
                logger.warning(f"  ✗ {agent.agent_id} {result.get('reason', 'failed')}")

    def _build_brain_prompt(self, phase: str, iteration: int) -> str:
        """Build brain decision prompt"""
        
        context = self._summarize_context()
        tools_list = self.tools.list_tools()
        
        prompt = f"""You are autonomous pentesting brain.
Target: {self.ctx.target}
Phase: {phase.upper()}

CURRENT STATE:
{context}

AVAILABLE TOOLS:
{tools_list}

PHASE OBJECTIVES:
recon: Discover subdomains, ports, technologies, endpoints
analyze: Identify vulnerabilities from recon data
plan: Map attack chains and prioritize targets
exploit: Execute exploits and chain results
report: Compile findings into report

{phase.upper()} STRATEGY (Iteration {iteration}):
- Identify what's still needed
- Spawn agents to fill gaps
- When phase is done, respond phase_complete

RESPONSE FORMAT:
Single agent:
{{
  "thinking": "why this action",
  "action": "spawn_agent",
  "agent_spec": {{
    "objective": "what to do",
    "tools": ["tool1", "tool2"],
    "context_keys": ["target", "subdomains"],
    "max_steps": 10
  }}
}}

Multiple agents:
{{
  "thinking": "these are independent",
  "action": "spawn_agents",
  "agent_specs": [
    {{"objective": "task1", "tools": [...], "context_keys": [...], "max_steps": 8}},
    {{"objective": "task2", "tools": [...], "context_keys": [...], "max_steps": 8}}
  ]
}}

Phase done:
{{
  "action": "phase_complete"
}}"""
        
        return prompt

    async def _generate_report(self):
        """LLM generates final report"""
        summary = self.ctx.get_full_summary(max_chars=8000)

        # Generate executive summary via LLM
        exec_summary = await self.llm.generate(
            f"Write a professional executive summary for this penetration test.\n\n"
            f"DATA:\n{summary}\n\n"
            f"Include: overall risk, key findings, attack chains, recommendations.\n"
            f"Be concise (3 paragraphs max).",
            tier=TaskTier.LARGE,
            max_tokens=1000,
        )

        # Build report
        report = {
            "metadata": {
                "title": f"Penetration Test Report - {self.ctx.target}",
                "target": self.ctx.target,
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
                "agents_used": len(self.ctx.agents_spawned),
            },
            "executive_summary": exec_summary,
            "scope": self.ctx.scope,
            "vulnerabilities": self.ctx.vulnerabilities,
            "attack_chains": self.ctx.attack_chains,
            "exploit_results": self.ctx.exploit_results,
            "technical_data": {
                "subdomains": self.ctx.subdomains,
                "ips": self.ctx.ips,
                "ports": self.ctx.ports,
                "technologies": self.ctx.technologies,
                "endpoints": self.ctx.endpoints,
                "directories": self.ctx.directories,
                "headers": self.ctx.headers,
                "ssl_info": self.ctx.ssl_info,
                "secrets": self.ctx.secrets,
            },
            "brain_log": self.ctx.brain_log,
            "agents": self.ctx.agents_spawned,
        }

        # Save
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.report_dir / f"pentest_{ts}.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)
        logger.info(f"Report saved: {report_path}")

        # Save shared context as backup
        ctx_path = self.report_dir / f"context_{ts}.json"
        self.ctx.save(str(ctx_path))
        logger.info(f"Context saved: {ctx_path}")