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
        """LLM-driven loop for any phase. Supports single + parallel agents."""
        agents_this_phase = 0

        # Load phase-specific prompt if available
        phase_prompt = self._load_phase_prompt(phase)

        while agents_this_phase < self.max_agents_per_phase:
            summary = self.ctx.get_full_summary(max_chars=5000)

            # Build chain context for exploit phase
            chain_context = ""
            if phase == "exploit" and self.ctx.exploit_results:
                chain_context = "\nEXPLOIT CHAIN SO FAR:\n"
                for er in self.ctx.exploit_results:
                    chain_context += (
                        f"  - {er.get('type','?')}: "
                        f"{'SUCCESS' if er.get('success') else 'FAILED'} "
                        f"({er.get('agent','')})\n"
                    )
                chain_context += (
                    "\nWhat did the last exploit UNLOCK? "
                    "Can you chain further? Spawn parallel agents for "
                    "independent follow-ups.\n"
                )

            prompt = (
                f"CURRENT PHASE: {phase}\n"
                f"TARGET: {self.ctx.target}\n\n"
                f"CURRENT DATA:\n{summary}\n"
                f"{chain_context}\n"
                f"AVAILABLE TOOLS:\n{self.tools.list_tools()}\n\n"
                f"AGENTS SPAWNED THIS PHASE: {agents_this_phase}\n\n"
                f"What should I do next?"
            )

            system = phase_prompt or BRAIN_SYSTEM

            decision = await self.llm.generate_json(
                prompt, system=system,
                tier=TaskTier.LARGE, max_tokens=2500,
            )

            if not decision:
                logger.warning("Brain returned empty, retrying...")
                continue

            thinking = decision.get("thinking", "")
            action = decision.get("action", "phase_complete")

            self.ctx.log_brain(thinking, action)
            logger.info(f"Brain [{phase}]: {thinking[:120]}...")

            # ── Phase complete ──
            if action in ("phase_complete", "done"):
                logger.info(f"Phase '{phase}' complete")
                break

            # ── Spawn MULTIPLE agents (parallel) ──
            if action == "spawn_agents":
                specs = decision.get("agent_specs", [])
                specs = [s for s in specs if s.get("objective")]
                if not specs:
                    continue

                logger.info(f"Spawning {len(specs)} agents in PARALLEL")
                agents = [self.spawner.spawn(s) for s in specs]

                results = await asyncio.gather(
                    *[a.execute() for a in agents],
                    return_exceptions=True
                )

                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        logger.error(f"Agent failed: {result}")
                    else:
                        logger.info(
                            f"Agent result: "
                            f"{result.get('summary', '')[:80]}"
                        )
                    agents_this_phase += 1

            # ── Spawn SINGLE agent (sequential) ──
            elif action == "spawn_agent":
                spec = decision.get("agent_spec", {})
                if not spec.get("objective"):
                    logger.warning("No objective in agent_spec, skipping")
                    continue

                agent = self.spawner.spawn(spec)
                result = await agent.execute()
                agents_this_phase += 1

                logger.info(
                    f"Agent result: {result.get('summary', '')[:100]}"
                )

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