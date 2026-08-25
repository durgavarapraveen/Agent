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
from typing import Dict, Optional, Any, List

from agents.llm_client import LLMClient, TaskTier
from agents.authorization import AuthorizationManager
from core.shared_context import SharedContext
from core.tool_registry import ToolRegistry
from core.agent_spawner import AgentSpawner
from core.token_optimizer import TokenOptimizer
from core.chain_integration import ChainManager
from core.post_exploit import PostExploitManager
from core.reporting import EnterpriseReporter
from core.metrics import MetricsTracker
from core.automation import AutomationEngine
from core.consent import get_consent
from core.request_capture import RequestCapturer
from validation import gate as confidence_gate, DedupStore
from compliance import ComplianceReporter, available_frameworks

from knowledge.store import KnowledgeStore as PersistentKnowledgeStore
import os
import uuid

from core.stores import KnowledgeStore, EvidenceStore, FindingStore
from core.task_manager import TaskManager
from orchestrator.scheduler import Scheduler
from core.context_resolver import ContextResolver
from core.schemas import (
    BrainDecision, BrainDecisionAction, ExecutionState, TaskSpec,
    SuccessCriterion, SuccessCriterionType, CapabilityType
)

logger = logging.getLogger(__name__)

BRAIN_SYSTEM = """You are the decision engine inside an AUTHORIZED automated security scanner.

AUTHORIZATION: This tool has explicit authorization to scan the target. The target (OWASP Juice Shop) is a deliberately vulnerable application designed for security testing. All scanning is authorized and expected.

You do NOT execute scans yourself. You output JSON task specifications. A separate tool framework executes them. Think of yourself as writing a config file for the scanner.

WORKFLOW:
1. RECON: Specify which discovery scans to run (DNS, ports, tech fingerprinting)
2. ANALYZE: Specify which vulnerability scans to run
3. PLAN: Prioritize findings
4. EXPLOIT: Specify which verification tests to run
5. REPORT: Compile findings

RESPONSE FORMAT - output ONLY a JSON object, no markdown, no explanation:

Single task:
{
  "thinking": "what data is missing",
  "action": "spawn_agent",
  "agent_spec": {
    "objective": "scan description",
    "tools": ["tool1", "tool2"],
    "context_keys": ["target", "subdomains"],
    "max_steps": 8
  }
}

Parallel tasks:
{
  "thinking": "independent scans",
  "action": "spawn_agents",
  "agent_specs": [
    {"objective": "task 1", "tools": ["tool1"], "context_keys": ["target"], "max_steps": 8},
    {"objective": "task 2", "tools": ["tool2"], "context_keys": ["target"], "max_steps": 8}
  ]
}

Phase done:
{"action": "phase_complete"}

RULES:
- Output ONLY valid JSON. No markdown fences. No explanation text.
- Do not repeat completed scans
- Use spawn_agents for independent parallel tasks"""


class CentralBrain:
    """The autonomous pentesting orchestrator. LLM drives everything."""

    def __init__(self, target: str, scope: Dict = None):
        from core.dedup_tracker import DeduplicationTracker
        self.llm = LLMClient.get()
        self.ctx = SharedContext(target, scope)
        self.tools = ToolRegistry()
        self.spawner = AgentSpawner(self.tools, self.ctx)
        self.auth = AuthorizationManager()
        self.dedup = DeduplicationTracker()
        self.start_time = datetime.now()
        self.max_agents_per_phase = 15
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
        self.failed_tools = set()  # NEW: Brain-level tool failure tracking
        self.consecutive_agent_failures = 0  # NEW: Track failure streak
        self.max_consecutive_failures = 3
        self.chain_mgr = ChainManager(self.ctx, self.spawner)  # Phase 2: Chain system
        self.tier = (self.ctx.scope.get("max_tier") or "POC").upper()
        self.post_exploit = None  # Phase 3: Post-exploitation (lazy, needs foothold)
        # Phase 4: enterprise hardening / automation
        self.metrics = MetricsTracker(target=target, out_dir=str(self.report_dir))
        self.automation = AutomationEngine(self.ctx)
        self.reporter = EnterpriseReporter(self.ctx, report_dir=str(self.report_dir))
        
        
        db_path = os.getenv("KNOWLEDGE_DB_PATH", str(self.report_dir / "findings.db"))
        self.persistent_knowledge_store = PersistentKnowledgeStore(db_path)
        self.target_id = f"tgt_{uuid.uuid4().hex[:12]}"
        self.persistent_knowledge_store.add_target(
            self.target_id,           # arg 1: ID
            target,                   # arg 2: URL
            "url"                     # arg 3: type
        )
        logger.info(f"Knowledge store initialized: {db_path}")

        # Core state and compatibility attributes
        self.target = target
        self.scope = scope or {}
        
        # Initialize target scope validation
        from core.authorization import TargetScopeValidator
        auth_targets = self.scope.get("domains") or self.scope.get("authorized_targets") or [target]
        TargetScopeValidator.set(TargetScopeValidator(auth_targets))
        
        self.authorized_scope = auth_targets
        self.execution_count = 0
        self.max_iterations = 100

        # Memory stores (for compatibility with OrchestratorV2 and state validation)
        self.knowledge_store = KnowledgeStore()
        self.evidence_store = EvidenceStore()
        self.finding_store = FindingStore()

        # Framework components
        self.task_manager = TaskManager()
        self.scheduler = Scheduler(self.task_manager)
        self.context_resolver = ContextResolver(self.knowledge_store)

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
        await self._persist_recon_findings()

        # Phase 1b: Intercept live HTTP traffic across the site (for exploit replay)
        await self._capture_requests()
        await self._persist_captured_requests()

        # Phase 2: Vulnerability analysis
        logger.info("\n>>> PHASE 2: VULNERABILITY ANALYSIS")
        await self._run_phase("analyze")
        await self._persist_vulnerabilities()

        # Phase 3: Build attack graph and detect chains
        logger.info("\n>>> PHASE 3: ATTACK CHAIN ANALYSIS")
        chain_plan = None
        if self.ctx.vulnerabilities:
            self.chain_mgr.build_graph()
            chains = self.chain_mgr.detect_chains(max_chains=5)
            if chains:
                chain_plan = self.chain_mgr.get_exploitation_plan()
                logger.info(f"Found {len(chains)} attack chains")
                for i, c in enumerate(chains[:3]):
                    logger.info(f"  #{i+1} {c.description} (score={c.score:.3f})")
            else:
                logger.info("No attack chains found, falling back to direct exploitation")
                plan = await self._generate_exploit_plan()
        else:
            logger.info("No vulnerabilities found. Skipping exploitation.")

        if chain_plan and chain_plan.get("top_chains"):
            approved = await self._human_approval(chain_plan)
            if approved:
                # Phase 4: Chain-based exploitation
                logger.info("\n>>> PHASE 4: CHAIN EXPLOITATION")
                result = await self.chain_mgr.llm_select_and_execute()
                if result:
                    logger.info(f"Chain result: {result.status} "
                                f"({result.steps_completed}/{result.steps_total})")
                    if result.final_impact:
                        logger.info(f"Impact: {result.final_impact}")

                    # Try more chains if first succeeded
                    if result.status == "completed":
                        suggestions = self.chain_mgr.suggest_next_exploits()
                        if suggestions:
                            logger.info(f"Follow-up suggestions: {len(suggestions)}")
                            # Run additional exploitation phase for follow-ups
                            await self._run_phase("exploit")
                            await self._persist_exploit_results()
                else:
                    logger.warning("Chain execution failed, falling back to direct exploitation")
                    await self._run_phase("exploit")
                    await self._persist_exploit_results()
        elif self.ctx.vulnerabilities:
            plan = await self._generate_exploit_plan()
            if plan and plan.get("exploits"):
                approved = await self._human_approval(plan)
                if approved:
                    logger.info("\n>>> PHASE 4: DIRECT EXPLOITATION")
                    await self._run_phase("exploit")
                    await self._persist_exploit_results()

        # Phase 6: Post-exploitation (privesc / lateral / persistence / MITRE)
        await self._run_post_exploitation()

        # Phase 5: Report
        logger.info("\n>>> PHASE 5: REPORT GENERATION")
        await self._generate_report()

        duration = (datetime.now() - self.start_time).total_seconds()
        logger.info(f"\nCompleted in {duration:.0f}s")
        logger.info(f"Agents spawned: {len(self.ctx.agents_spawned)}")
        logger.info(f"Vulnerabilities: {len(self.ctx.vulnerabilities)}")
        logger.info(f"Exploits executed: {len(self.ctx.exploit_results)}")

    async def _capture_requests(self):
        """Phase 1b: crawl the site with a headless browser and intercept every
        request (XHR/fetch/API/CORS-preflight), storing them for exploit replay."""
        target = self.ctx.target
        if not str(target).lower().startswith(("http://", "https://")):
            logger.info("[capture] target is not an http(s) URL — skipping capture")
            return
        logger.info("\n>>> PHASE 1b: HTTP REQUEST INTERCEPTION")
        try:
            capturer = RequestCapturer(max_pages=12, max_depth=2)
            result = await asyncio.to_thread(capturer.capture, target)
            if result.error and not result.requests:
                logger.warning(f"[capture] no requests captured: {result.error}")
                return
            capturer.store(result, self.ctx)
            self.metrics.record_event(
                "tool", "request_capture",
                bool(result.requests),
                f"{len(result.pages)} pages, {len(result.requests)} requests")
            logger.info(f"[capture] stored {len(self.ctx.captured_requests)} "
                        f"requests across {len(self.ctx.crawled_pages)} pages")
        except Exception as e:      # noqa: BLE001
            logger.error(f"[capture] request interception failed: {e}")

    async def _run_post_exploitation(self):
        """Phase 6: privesc / lateral movement / persistence / MITRE mapping.

        Runs only when a shell/RCE foothold exists. Active enumeration and
        persistence installation are gated by tier (see PostExploitManager);
        no live command runner is wired by default, so this is analysis +
        planning unless a foothold session is explicitly provided.
        """
        logger.info("\n>>> PHASE 6: POST-EXPLOITATION (privesc / lateral / persistence)")

        if not self.ctx.has_shell_access():
            logger.info("No shell/RCE foothold established — skipping post-exploitation")
            return

        # Runner stays None (plan-only) unless a confirmed foothold session is
        # wired in. Persistence install additionally requires DEEP + authorize.
        runner = None
        authorize_persistence = False  # never auto-install; operator opt-in only

        self.post_exploit = PostExploitManager(
            self.ctx, tier=self.tier,
            runner=runner, authorize_persistence=authorize_persistence,
        )
        try:
            result = await self.post_exploit.run()
            if result.get("status") == "completed":
                pv = result["privesc"]; lat = result["lateral"]
                logger.info(
                    f"Post-exploitation: {pv['count']} privesc paths, "
                    f"{lat['pivots']} pivots, {lat['credentials']} creds, "
                    f"{len(result['persistence']['installed'])} persistence installed "
                    f"(plan-only={self.tier != 'DEEP'}), "
                    f"{result['mitre']['techniques']} ATT&CK techniques"
                )
                rec = pv.get("recommended")
                if rec:
                    logger.info(f"Recommended escalation: {rec.get('technique')} — "
                                f"{rec.get('path','')[:80]}")
        except Exception as e:      # noqa: BLE001
            logger.error(f"Post-exploitation phase failed: {e}")

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
        """LLM-driven loop with agent history, dedup, failed tool filtering, and circuit-breaker."""
        agents_this_phase = 0
        self.consecutive_agent_failures = 0
        agent_history = []  # Track what each agent did
        completed_objectives = set()  # Prevent duplicate tasks

        phase_prompt = self._load_phase_prompt(phase)

        while agents_this_phase < self.max_agents_per_phase:
            summary = self.ctx.get_full_summary(max_chars=800)

            # ── Build failed tools warning ──
            failed_tools_warning = ""
            if self.failed_tools:
                failed_tools_warning = (
                    f"\nUNAVAILABLE TOOLS: {', '.join(sorted(self.failed_tools))}\n"
                )

            # ── Agent history (last 3 only) ──
            history_section = ""
            if agent_history:
                history_section = "\nCOMPLETED AGENTS:\n"
                for h in agent_history[-3:]:
                    status = "✓" if h["success"] else "✗"
                    history_section += f"  {status} {h['agent_id']}: {h['objective'][:50]}\n"

            # ── Build exploit chain context ──
            chain_context = ""
            if phase == "exploit" and self.ctx.exploit_results:
                chain_context = "\nEXPLOIT CHAIN:\n"
                for er in self.ctx.exploit_results[-3:]:
                    chain_context += f"  - {er.get('type','?')}: {'SUCCESS' if er.get('success') else 'FAILED'}\n"

            # ── Context truncation ──
            _MAX_SUMMARY_CHARS = 800
            if len(summary) > _MAX_SUMMARY_CHARS:
                summary = summary[:_MAX_SUMMARY_CHARS] + "..."

            # ── Circuit-breaker hint ──
            circuit_breaker_hint = ""
            if self.consecutive_agent_failures >= 2:
                completed_objectives.clear()
                circuit_breaker_hint = "\n⚠️  REPLAN REQUIRED: Choose a different approach or phase_complete.\n"

            # ── Compact execution context from database ──
            db_context = self._get_db_execution_context()
            comp_tasks = [f"{t[0]}:{t[1]}" for t in db_context.get("completed_tasks", [])[-5:]]
            assets = db_context.get("discovered_assets", {})
            db_summary_lines = []
            if comp_tasks:
                db_summary_lines.append(f"Completed: {', '.join(comp_tasks)}")
            if assets.get("subdomains"):
                db_summary_lines.append(f"Subdomains: {', '.join(assets['subdomains'][:5])}")
            if assets.get("open_ports"):
                db_summary_lines.append(f"Ports: {assets['open_ports']}")
            if assets.get("technologies"):
                db_summary_lines.append(f"Tech: {assets['technologies']}")
            db_context_str = "\n".join(db_summary_lines)

            prompt = (
                f"Authorized security assessment task planner.\n\n"
                f"Phase: {phase.upper()}\n"
                f"Target: {self.ctx.target}\n"
                f"{failed_tools_warning}"
                f"{history_section}"
                f"\n--- DISCOVERED CONTEXT ---\n"
                f"{db_context_str}\n"
                f"\nSummary:\n{summary}\n"
                f"{chain_context}"
                f"{circuit_breaker_hint}"
                f"Tasks completed: {agents_this_phase}/{self.max_agents_per_phase}\n\n"
                f"Based on data above, output JSON for next task. "
                f"If phase complete, output: {{\"action\": \"phase_complete\"}}\n"
                f"Do not repeat completed tasks. Output ONLY valid JSON.\n"
            )
            
            # ── Explicit state transition check for Recon completion ──
            if phase == "recon" and self._is_recon_complete(db_context):
                logger.info("RECON_COMPLETE: All reconnaissance capabilities for discovered targets finished. Advancing to PHASE 2: VULNERABILITY_ASSESSMENT.")
                break

            # ── Log prompt size ──
            logger.info(f"Brain prompt length: {len(prompt)} chars")

            decision = await self.llm.generate_json(prompt, system=phase_prompt or BRAIN_SYSTEM)
            logger.info(f"Brain decision: {json.dumps(decision, indent=2)}")

            if not decision:
                self.consecutive_agent_failures += 1
                logger.warning(f"Brain returned empty (failure streak: {self.consecutive_agent_failures})")
                
                # Deterministic fallback decision tree when LLM returns empty responses
                if self.consecutive_agent_failures >= 2:
                    logger.warning(f"[CentralBrain] Brain returned empty. Inject deterministic fallback task: http_request on discovered endpoints from reconnaissance phase. Log all responses.")
                    
                    # 1. Base URL
                    base_url = self.ctx.target.rstrip("/")
                    if not base_url.startswith(("http://", "https://")):
                        base_url = f"https://{base_url}"

                    # 2. Extract first discovered endpoint
                    discovered_endpoints = getattr(self.ctx, "endpoints", []) or []
                    first_ep = ""
                    if discovered_endpoints:
                        raw_ep = discovered_endpoints[0]
                        first_ep = raw_ep if isinstance(raw_ep, str) else raw_ep.get("url", "")

                    # 3. Construct full target URL
                    if first_ep.startswith(("http://", "https://")):
                        full_target = first_ep
                    elif first_ep:
                        endpoint_path = "/" + first_ep.lstrip("/")
                        full_target = f"{base_url}{endpoint_path}"
                    else:
                        full_target = base_url

                    # 4. Scope validation
                    from agents.authorization import AuthorizationManager
                    from urllib.parse import urlparse
                    parsed_host = urlparse(full_target).hostname or full_target.split("/")[0].split(":")[0]
                    scope_pass = AuthorizationManager.is_authorized(parsed_host)
                    scope_str = "pass" if scope_pass else "fail"

                    logger.info(f"FALLBACK_TARGET_CONSTRUCTED: target={full_target} scope_check={scope_str}")

                    if not scope_pass:
                        logger.warning(f"FALLBACK_TARGET_OUT_OF_SCOPE: '{full_target}' failed authorization scope check. Skipping fallback.")
                        self.consecutive_agent_failures = 0
                        break

                    fallback_task = TaskSpec(
                        objective=f"HTTP request probe and security header verification for {full_target}",
                        capability=CapabilityType.HTTP_ANALYSIS,
                        inputs={"target": full_target, "url": full_target, "tools": ["http_request"]}
                    )
                    try:
                        if hasattr(self, "scheduler") and hasattr(self.scheduler, "schedule_tasks"):
                            self.scheduler.schedule_tasks([fallback_task])
                        else:
                            agent = self.spawner.spawn({
                                "objective": fallback_task.objective,
                                "capability": fallback_task.capability.value,
                                "target": full_target,
                                "tools": ["http_request"]
                            })
                            if agent and hasattr(agent, "run"):
                                await agent.run()
                        self.consecutive_agent_failures = 0
                    except Exception as ex:
                        logger.error(f"Fallback HTTP probe execution failed: {ex}")
                        break
                continue

            # ── Canonical Planner Response Normalization ──
            from core.normalizer import PlannerResponseNormalizer
            from core.schemas import BrainDecisionAction, TaskStatus
            
            try:
                canonical_decision = PlannerResponseNormalizer.normalize(decision)
            except Exception as e:
                self.consecutive_agent_failures += 1
                logger.error(f"Planner decision normalization failed: {e}")
                continue

            self.consecutive_agent_failures = 0
            action = canonical_decision.action

            if action == BrainDecisionAction.COMPLETE:
                logger.info(f"✓ Phase '{phase}' complete")
                break

            # ── Schedule & Spawn Tasks Managed by TaskManager ──
            if action in (BrainDecisionAction.SPAWN_AGENTS, BrainDecisionAction.SPAWN_TASKS):
                task_specs = canonical_decision.tasks
                # Validate upstream proof before spawning auth / downstream exploit tasks
                validated_specs = []
                for spec in task_specs:
                    cap_val = spec.capability.value.lower()
                    obj_val = spec.objective.lower()
                    
                    if cap_val == "authentication_testing" or "auth" in obj_val or "login" in obj_val:
                        creds = getattr(self.ctx, "harvested_creds", []) or getattr(self.ctx, "extracted_credentials", [])
                        if not creds:
                            logger.warning(f"[WARN] NO_EXTRACTED_CREDENTIALS: cannot spawn auth_agent without creds for objective='{spec.objective[:50]}'. Retrying data extraction.")
                            # Substitute with data extraction task
                            spec.capability = CapabilityType.VULNERABILITY_SCANNING
                            spec.objective = f"Extract data and credentials from discovered endpoints for {self.ctx.target}"
                        else:
                            sample = creds[0].get("username") or creds[0].get("secret") or "user"
                            logger.info(f"CREDENTIALS_AVAILABLE: count={len(creds)}, sample_user='{sample}'")
                            
                    elif cap_val in ("rce", "idor", "privilege_escalation") or "rce" in obj_val or "idor" in obj_val:
                        token = getattr(self.ctx, "auth_token", None)
                        if not token and not getattr(self.ctx, "vulnerabilities", []):
                            logger.warning(f"[WARN] NO_UPSTREAM_PROOF: skipping downstream exploit '{spec.objective[:50]}' until auth or upstream vulnerability confirmed")
                            continue
                            
                    validated_specs.append(spec)

                task_specs = validated_specs
                if not task_specs:
                    logger.warning("All proposed tasks filtered out due to missing upstream proof/credentials")
                    self.consecutive_agent_failures += 1
                    continue

                # ── Schedule tasks into DAG Scheduler ──
                try:
                    self.scheduler.schedule_tasks(task_specs)
                except Exception as e:
                    logger.error(f"[CentralBrain] Scheduling failed: {e}")
                    self.consecutive_agent_failures += 1
                    continue

                # ── Execute tasks stage-by-stage respecting dependencies ──
                while True:
                    runnable_tasks = self.scheduler.get_next_runnable_tasks()
                    if not runnable_tasks:
                        break

                    spawn_specs = []
                    for task in runnable_tasks:
                        self.task_manager.start_task(task.spec.task_id)
                        s_dict = {
                            "objective": task.spec.objective,
                            "capability": task.spec.capability.value,
                            "target": task.spec.inputs.get("target", self.ctx.target),
                            "tools": task.spec.inputs.get("tools", []),
                            "max_steps": task.spec.max_steps,
                            "task_id": task.spec.task_id
                        }
                        spawn_specs.append((task, s_dict))

                    valid_specs_and_agents = []
                    for task, s_dict in spawn_specs:
                        agent_inst = self.spawner.spawn(s_dict)
                        if agent_inst is None:
                            logger.info(f"TASK_SKIPPED_OR_DEDUPLICATED: task_id={task.spec.task_id} objective='{task.spec.objective[:50]}'")
                            self.task_manager.complete_task(task.spec.task_id, {"status": "skipped", "reason": "Deduplicated or skipped by spawner"})
                        else:
                            valid_specs_and_agents.append((task, s_dict, agent_inst))

                    if not valid_specs_and_agents:
                        logger.info("[Scheduler] No new valid/non-duplicate agents to execute in this stage.")
                        continue

                    spawn_specs = [(t, s) for t, s, a in valid_specs_and_agents]
                    agents = [a for t, s, a in valid_specs_and_agents]
                    logger.info(f"[Scheduler] Executing {len(agents)} READY tasks in parallel stage")

                    max_task_duration = float(getattr(getattr(self, "config", None), "max_task_duration", 300.0) or 300.0)

                    async def _run_agent_with_timeout(agent_inst):
                        try:
                            return await asyncio.wait_for(agent_inst.execute(), timeout=max_task_duration)
                        except (asyncio.TimeoutError, TimeoutError):
                            agent_id_str = getattr(agent_inst, 'agent_id', 'AGENT')
                            logger.warning(f"TASK_TIMEOUT: agent_id={agent_id_str} duration={max_task_duration}s, killing process")
                            return {"status": "timeout", "reason": f"Task exceeded max duration ({max_task_duration}s)"}

                    results = await asyncio.gather(*[_run_agent_with_timeout(a) for a in agents], return_exceptions=True)

                    for i, result in enumerate(results):
                        task, s_dict = spawn_specs[i]
                        agent = agents[i]
                        obj = task.spec.objective
                        completed_objectives.add(obj.lower().strip())
                        
                        entry = {
                            "agent_id": getattr(agent, 'agent_id', f'AGENT-{agents_this_phase+1}'),
                            "objective": obj,
                            "success": False,
                            "findings": "",
                            "failed_tools": [],
                        }
                        
                        if isinstance(result, dict) and result.get("status") == "timeout":
                            logger.warning(f"TASK_TIMEOUT: task_id={task.spec.task_id} duration={max_task_duration}s, status=TIMEOUT")
                            self.task_manager.timeout_task(task.spec.task_id)
                            self.consecutive_agent_failures += 1
                            entry["findings"] = result.get("reason", "Task exceeded max duration")
                        elif isinstance(result, Exception):
                            logger.error(f"Task {task.spec.task_id} crashed: {result}")
                            self.task_manager.fail_task(task.spec.task_id, str(result))
                            self.consecutive_agent_failures += 1
                            entry["findings"] = f"Crashed: {result}"
                        elif isinstance(result, dict) and result.get("status") == "failed":
                            logger.warning(f"Task {task.spec.task_id} failed: {result.get('reason')}")
                            self.task_manager.fail_task(task.spec.task_id, result.get("reason", "failed"))
                            self.consecutive_agent_failures += 1
                            entry["findings"] = f"Failed: {result.get('reason')}"
                        else:
                            self.consecutive_agent_failures = 0
                            entry["success"] = True
                            entry["findings"] = str(result.get("results", "") if isinstance(result, dict) else result)[:200]
                            self.task_manager.complete_task(task.spec.task_id, result if isinstance(result, dict) else {})
                            logger.info(f"✓ Task {task.spec.task_id} SUCCEEDED")

                        # Track metrics
                        self.metrics.record_event("agent", entry["agent_id"],
                                                  entry["success"], entry["findings"])

                    # Aggregate wave results into shared context and persistent database
                    self._aggregate_wave_results(agents, results)

                    # Process dependencies to unlock newly ready tasks
                    self.scheduler.process_dependencies()
                    agent_history.append(entry)
                    agents_this_phase += len(runnable_tasks)

            # ── Spawn SINGLE agent ──
            elif action == "spawn_agent":
                spec = decision.get("agent_spec", {})
                obj = spec.get("objective", "")
                if not obj:
                    continue
                
                # Check duplicate
                if obj.lower().strip() in completed_objectives:
                    logger.info(f"Skipping duplicate objective: {obj[:60]}")
                    self.consecutive_agent_failures += 1
                    continue
                
                # Strip failed tools
                spec["tools"] = [t for t in spec.get("tools", []) if t not in self.failed_tools]
                if not spec["tools"]:
                    logger.warning(f"Skipping agent - all tools unavailable: {obj[:60]}")
                    self.consecutive_agent_failures += 1
                    continue

                agent = self.spawner.spawn(spec)
                result = await agent.execute()
                agents_this_phase += 1
                completed_objectives.add(obj.lower().strip())

                entry = {
                    "agent_id": getattr(agent, 'agent_id', f'AGENT-{agents_this_phase}'),
                    "objective": obj,
                    "success": False,
                    "findings": "",
                    "failed_tools": [],
                }

                if result.get("status") == "failed":
                    self.consecutive_agent_failures += 1
                    logger.warning(f"Agent failed: {result.get('reason')}")
                    entry["findings"] = f"Failed: {result.get('reason')}"
                else:
                    self.consecutive_agent_failures = 0
                    entry["success"] = True
                    entry["findings"] = str(result.get("results", ""))[:200]
                
                # Learn failed tools
                if hasattr(agent, 'failed_tools'):
                    entry["failed_tools"] = list(agent.failed_tools)
                    for failed_tool in agent.failed_tools:
                        self.failed_tools.add(failed_tool)
                        logger.warning(f"Brain learned: '{failed_tool}' is unavailable")

                self.metrics.record_event("agent", entry["agent_id"],
                                          entry["success"], entry["findings"])
                agent_history.append(entry)

        # ── End of phase: update metrics + evaluate automation rules ──
        self.metrics.incr("vuln_total", 0)  # ensure counter exists
        self.metrics.counters["vuln_total"] = len(self.ctx.vulnerabilities)
        try:
            self.metrics.write_dashboard()
            self.metrics.write_json()
        except Exception as e:      # noqa: BLE001
            logger.debug(f"[Metrics] dashboard write failed: {e}")
        for act in self.automation.evaluate():
            logger.info(f"Automation recommends: {act['action']} ({act['rule']})")
    
    async def _persist_recon_findings(self):
        """Save recon discoveries to knowledge store."""
        try:
            logger.info("Persisting recon findings...")
            
            # ── Debug: Log what's actually in the context ──
            logger.debug(f"subdomains: {getattr(self.ctx, 'subdomains', [])}")
            logger.debug(f"ips: {getattr(self.ctx, 'ips', [])}")
            logger.debug(f"ports keys: {getattr(self.ctx, 'ports', {}).keys()}")
            logger.debug(f"ports data: {getattr(self.ctx, 'ports', {})}")
            
            # ── Subdomains ──
            if hasattr(self.ctx, 'subdomains') and self.ctx.subdomains:
                for subdomain in self.ctx.subdomains:
                    self.persistent_knowledge_store.add_asset(
                        self.target_id, "subdomain", subdomain, 
                        metadata=json.dumps({"discovered_at": datetime.now().isoformat()})
                    )
                logger.info(f"  ✓ Persisted {len(self.ctx.subdomains)} subdomains")
            
            # ── IPs ──
            if hasattr(self.ctx, 'ips') and self.ctx.ips:
                for ip in self.ctx.ips:
                    self.persistent_knowledge_store.add_asset(
                        self.target_id, "ip", ip,
                        metadata=json.dumps({"discovered_at": datetime.now().isoformat()})
                    )
                logger.info(f"  ✓ Persisted {len(self.ctx.ips)} IPs")
            
            # ── Ports - FIXED ──
            if hasattr(self.ctx, 'ports') and self.ctx.ports:
                for host, port_list in self.ctx.ports.items():
                    host_asset_id = self.persistent_knowledge_store.add_asset(
                        self.target_id, "host", host,
                        metadata=json.dumps({"discovered_at": datetime.now().isoformat()})
                    )
                    
                    for port_item in port_list:
                        # Handle both dict and int formats
                        if isinstance(port_item, dict):
                            port_num = port_item.get("port", "unknown")
                            service = port_item.get("service", "unknown")
                            version = port_item.get("version", "")
                        else:
                            port_num = str(port_item)
                            service = "unknown"
                            version = ""
                        
                        # Add technology with port info
                        self.persistent_knowledge_store.add_technology(
                            host_asset_id, 
                            f"{service}:{port_num}", 
                            version,
                            source="port_scan"
                        )
                logger.info(f"  ✓ Persisted ports for {len(self.ctx.ports)} hosts")
            
            # ── Technologies ──
            if hasattr(self.ctx, 'technologies') and self.ctx.technologies:
                for host, techs in self.ctx.technologies.items():
                    host_asset_id = self.persistent_knowledge_store.add_asset(
                        self.target_id, "host", host
                    )
                    for tech in techs:
                        if isinstance(tech, dict):
                            name = tech.get("name", "")
                            version = tech.get("version", "")
                        else:
                            name = str(tech)
                            version = ""
                        if name:
                            self.persistent_knowledge_store.add_technology(
                                host_asset_id, name, version,
                                source="web_fingerprint"
                            )
                logger.info(f"  ✓ Persisted technologies for {len(self.ctx.technologies)} hosts")
            
            # ── Endpoints ──
            if hasattr(self.ctx, 'endpoints') and self.ctx.endpoints:
                for endpoint in self.ctx.endpoints:
                    if isinstance(endpoint, dict):
                        path = endpoint.get("url", "")
                        method = endpoint.get("method", "GET")
                        status = endpoint.get("status", 0)
                        params = endpoint.get("params", [])
                    elif isinstance(endpoint, str):
                        path = endpoint
                        method = "GET"
                        status = 0
                        params = []
                    else:
                        continue
                    
                    if path:
                        self.persistent_knowledge_store.add_endpoint(
                            target_id=self.target_id,
                            path=path,
                            http_method=method,
                            status_code=status,
                            metadata=json.dumps({
                                "params": params,
                                "discovered_at": datetime.now().isoformat()
                            })
                        )
                logger.info(f"  ✓ Persisted {len(self.ctx.endpoints)} endpoints")
            
            # ── Summary ──
            logger.info(f"Persisted: {len(getattr(self.ctx, 'subdomains', []))} subdomains, "
                        f"{len(getattr(self.ctx, 'ips', []))} IPs, "
                        f"{len(getattr(self.ctx, 'ports', {}))} hosts with ports, "
                        f"{len(getattr(self.ctx, 'endpoints', []))} endpoints")
                        
        except Exception as e:
            logger.error(f"Failed to persist recon findings: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    async def _persist_captured_requests(self):
        """Save captured HTTP requests to disk for replay."""
        try:
            if not self.ctx.captured_requests:
                logger.debug("No captured requests to persist")
                return
            
            logger.info("Persisting captured HTTP requests...")
            request_file = self.report_dir / f"captured_requests_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(request_file, 'w') as f:
                json.dump({
                    "target": self.ctx.target,
                    "captured_at": datetime.now().isoformat(),
                    "pages": self.ctx.crawled_pages,
                    "requests": self.ctx.captured_requests,
                }, f, indent=2)
            logger.info(f"Saved {len(self.ctx.captured_requests)} requests to {request_file}")
        except Exception as e:
            logger.error(f"Failed to persist captured requests: {e}")

    async def _persist_vulnerabilities(self):
        """Save vulnerability findings to knowledge store."""
        try:
            if not self.ctx.vulnerabilities:
                logger.debug("No vulnerabilities to persist")
                return
            
            logger.info("Persisting vulnerability findings...")
            for vuln in self.ctx.vulnerabilities:
                finding_id = self.persistent_knowledge_store.add_finding(
                    target_id=self.target_id,
                    title=vuln.get("title", "Unknown"),
                    description=vuln.get("details", ""),
                    severity=vuln.get("severity", "MEDIUM"),
                    category=vuln.get("type", ""),
                    cwe=vuln.get("cwe", ""),
                    cve=vuln.get("cve", ""),
                    affected_asset=vuln.get("location", ""),
                    evidence=json.dumps(vuln.get("proof", {})),
                    source_agent_id=vuln.get("source_agent", ""),
                )
                # Add evidence
                for evidence_item in vuln.get("evidence", []):
                    if isinstance(evidence_item, dict):
                        self.persistent_knowledge_store.add_evidence(
                            finding_id,
                            evidence_type=evidence_item.get("type", "screenshot"),
                            content=evidence_item.get("content", ""),
                            tool_name=evidence_item.get("tool", "")
                        )
            
            logger.info(f"Persisted {len(self.ctx.vulnerabilities)} vulnerabilities")
        except Exception as e:
            logger.error(f"Failed to persist vulnerabilities: {e}")

    async def _persist_exploit_results(self):
        """Save exploitation results to knowledge store."""
        try:
            if not self.ctx.exploit_results:
                logger.debug("No exploit results to persist")
                return
            
            logger.info("Persisting exploit results...")
            for result in self.ctx.exploit_results:
                self.persistent_knowledge_store.add_exploit_result(
                    target_id=self.target_id,
                    vuln_id=result.get("vuln_id", ""),
                    exploit_id=result.get("exploit_id", ""),
                    payload=result.get("payload", ""),
                    success=result.get("success", False),
                    proof=result.get("proof", ""),
                    severity=result.get("severity", "MEDIUM"),
                    executed_at=result.get("timestamp", datetime.now().isoformat()),
                )
            
            logger.info(f"Persisted {len(self.ctx.exploit_results)} exploitation results")
        except Exception as e:
            logger.error(f"Failed to persist exploit results: {e}")

    async def _persist_post_exploit_findings(self):
        """Save post-exploitation findings (privesc, lateral, persistence, MITRE)."""
        try:
            findings = []
            
            # Privesc findings
            for priv in self.ctx.privesc_findings:
                self.persistent_knowledge_store.add_post_exploit_finding(
                    target_id=self.target_id,
                    type="privesc",
                    host=priv.get("host", ""),
                    technique=priv.get("technique", ""),
                    detail=priv.get("detail", ""),
                    severity=priv.get("severity", "MEDIUM"),
                    metadata=json.dumps(priv)
                )
                findings.append(priv)
            
            # Lateral movement
            if self.ctx.lateral_plan:
                for pivot in self.ctx.lateral_plan.get("pivots", []):
                    self.persistent_knowledge_store.add_post_exploit_finding(
                        target_id=self.target_id,
                        type="lateral_movement",
                        host=pivot.get("source_host", ""),
                        technique=pivot.get("technique", ""),
                        detail=f"Move to {pivot.get('target_host', '')}",
                        metadata=json.dumps(pivot)
                    )
                    findings.append(pivot)
            
            # Persistence mechanisms
            for persist in self.ctx.persistence_plan:
                self.persistent_knowledge_store.add_post_exploit_finding(
                    target_id=self.target_id,
                    type="persistence",
                    technique=persist.get("mechanism", ""),
                    detail=persist.get("artifact", ""),
                    metadata=json.dumps(persist)
                )
                findings.append(persist)
            
            logger.info(f"Persisted {len(findings)} post-exploitation findings")
        except Exception as e:
            logger.error(f"Failed to persist post-exploit findings: {e}")


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

        summary = self.ctx.get_full_summary(max_chars=2000)

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
            max_tokens=6000,
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
            import os, sys
            if os.environ.get("AUTO_APPROVE") == "1" or not sys.stdin.isatty():
                response = "YES"
            else:
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

    def _active_frameworks(self):
        """Compliance frameworks selected via --frameworks (defaults to all)."""
        try:
            from core.config import get_config
            fw = get_config().config.get("COMPLIANCE_FRAMEWORKS")
            if fw:
                return fw
        except Exception:       # noqa: BLE001
            pass
        return available_frameworks()

    def _validate_findings(self, ts: str):
        """Confidence-gate + cross-scan dedup the findings.

        Returns dict: reported (high/med confidence, non-suppressed),
        needs_review (low confidence), dedup summary.
        """
        # Work on shallow copies so we don't mutate the canonical vuln list.
        findings = [dict(v) for v in self.ctx.vulnerabilities]

        # 1. Confidence gate — LOW confidence -> needs_review (not main report).
        gated = confidence_gate(findings)
        reported, needs_review = gated["report"], gated["needs_review"]

        # 2. Cross-scan dedup — suppress recurring-unchanged, flag new/resolved.
        try:
            dedup = DedupStore()
            dd = dedup.process_scan(reported, scan_id=ts)
            reported = dd["report"]
            dedup_summary = {"suppressed_recurring": dd["suppressed"],
                             "resolved": len(dd["resolved"]),
                             "reported": len(reported)}
        except Exception as e:      # noqa: BLE001
            logger.warning(f"[report] dedup failed: {e}")
            dedup_summary = {"suppressed_recurring": 0, "resolved": 0,
                             "reported": len(reported), "error": str(e)}

        logger.info(f"[report] findings: {len(reported)} reported, "
                    f"{len(needs_review)} need review, "
                    f"{dedup_summary['suppressed_recurring']} recurring suppressed")
        return {"reported": reported, "needs_review": needs_review,
                "dedup": dedup_summary}

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
            max_tokens=4096,
        )

        # ── Finding validation + compliance mapping (production-grade layer) ──
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        validated = self._validate_findings(ts)
        frameworks = self._active_frameworks()
        try:
            compliance_summary = ComplianceReporter(frameworks).build(
                self.ctx.vulnerabilities)
        except Exception as e:      # noqa: BLE001
            logger.warning(f"[report] compliance mapping failed: {e}")
            compliance_summary = {"active_frameworks": frameworks, "error": str(e)}

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
            "vulnerabilities": validated["reported"],
            "vulnerabilities_all": self.ctx.vulnerabilities,
            "needs_review": validated["needs_review"],
            "dedup": validated["dedup"],
            "compliance": compliance_summary,
            "attack_chains": self.ctx.attack_chains,
            "exploit_results": self.ctx.exploit_results,
            "post_exploitation": (
                self.post_exploit.to_dict() if self.post_exploit else {
                    "privesc_findings": self.ctx.privesc_findings,
                    "harvested_creds": self.ctx.harvested_creds,
                    "lateral_plan": self.ctx.lateral_plan,
                    "persistence_plan": self.ctx.persistence_plan,
                    "mitre_mappings": self.ctx.mitre_mappings,
                }
            ),
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
                "crawled_pages": self.ctx.crawled_pages,
                "captured_requests": self.ctx.captured_requests,
            },
            "automation": self.automation.to_dict(),
            "exploit_consent": get_consent().summary(),
            "remediation": self.automation.remediation_report(),
            "metrics": self.metrics.snapshot(),
            "scheduled_scan": AutomationEngine.schedule_config(self.ctx.target),
            "brain_log": self.ctx.brain_log,
            "agents": self.ctx.agents_spawned,
        }

        # Save  (ts computed above, shared with the validation/dedup scan_id)
        report_path = self.report_dir / f"pentest_{ts}.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)
        logger.info(f"Report saved: {report_path}")

        # Enterprise HTML/PDF report + final dashboard
        try:
            self.reporter.active_frameworks = frameworks
            paths = self.reporter.generate(executive_summary=exec_summary,
                                           stem=f"pentest_{ts}")
            logger.info(f"Enterprise report: {paths.get('html')}"
                        + (f" | {paths['pdf']}" if paths.get("pdf") else ""))
            self.metrics.write_dashboard()
        except Exception as e:      # noqa: BLE001
            logger.error(f"Enterprise report generation failed: {e}")

        # Save shared context as backup
        ctx_path = self.report_dir / f"context_{ts}.json"
        self.ctx.save(str(ctx_path))
        logger.info(f"Context saved: {ctx_path}")

    def plan_reconnaissance(self, state: ExecutionState) -> BrainDecision:
        """
        Reason about reconnaissance tasks.
        Returns structured decision, not task objects.
        """
        
        # What do we already know?
        hosts_known = len(self.knowledge_store.get_by_type("host"))
        ports_known = len(self.knowledge_store.get_by_type("port"))
        services_known = len(self.knowledge_store.get_by_type("service"))
        
        # What should we investigate?
        tasks = []
        
        # Stage 1: DNS if no hosts known
        if hosts_known == 0:
            tasks.append(TaskSpec(
                objective=f"Enumerate DNS records for {self.target}",
                capability=CapabilityType.DNS_ENUMERATION,
                inputs={"domain": self.target},
                context_requirements=["hosts"],
                success_criteria=[
                    SuccessCriterion(
                        criterion_type=SuccessCriterionType.KNOWLEDGE_EXISTS,
                        entity_type="host"
                    )
                ],
                timeout_seconds=300,
                max_steps=5,
            ))
        
        # Stage 2: Port scan discovered hosts
        elif hosts_known > 0 and ports_known == 0:
            tasks.append(TaskSpec(
                objective="Scan discovered hosts for open ports",
                capability=CapabilityType.PORT_SCANNING,
                inputs={"targets": [h["host"] for h in self.context_resolver.resolve_hosts(self.authorized_scope)]},
                context_requirements=["hosts"],
                success_criteria=[
                    SuccessCriterion(
                        criterion_type=SuccessCriterionType.KNOWLEDGE_EXISTS,
                        entity_type="port"
                    )
                ],
                timeout_seconds=600,
                max_steps=8,
            ))
        
        # Stage 3: Technology fingerprinting
        elif ports_known > 0 and services_known == 0:
            tasks.append(TaskSpec(
                objective="Fingerprint technologies on discovered services",
                capability=CapabilityType.TECHNOLOGY_FINGERPRINTING,
                inputs={"ports": self.context_resolver.resolve_ports()},
                context_requirements=["ports"],
                success_criteria=[
                    SuccessCriterion(
                        criterion_type=SuccessCriterionType.KNOWLEDGE_EXISTS,
                        entity_type="technology"
                    )
                ],
                timeout_seconds=300,
                max_steps=8,
            ))
        
        else:
            # Recon complete
            return BrainDecision(
                action=BrainDecisionAction.COMPLETE,
                thought="Reconnaissance phase complete - hosts, ports, technologies discovered",
                reason="Sufficient reconnaissance data collected"
            )
        
        if tasks:
            return BrainDecision(
                action=BrainDecisionAction.SPAWN_AGENTS,
                thought=f"Spawning {len(tasks)} reconnaissance task(s)",
                tasks=tasks,
            )
        
        return BrainDecision(
            action=BrainDecisionAction.WAIT,
            thought="Waiting for reconnaissance tasks to complete",
            wait_seconds=5,
        )

    def make_decision(self, state: ExecutionState) -> BrainDecision:
        """
        Central decision point.
        Analyzes execution state, decides next action.
        """
        
        # Safety check
        if self.execution_count >= self.max_iterations:
            logger.warning("[Brain] Max iterations reached, completing")
            return BrainDecision(
                action=BrainDecisionAction.COMPLETE,
                reason="Max execution iterations reached"
            )
        
        self.execution_count += 1
        
        # Check if all objectives completed
        completed_count = len(state.tasks_completed)
        failed_count = len(state.tasks_failed)
        blocked_count = len(state.tasks_blocked)
        running_count = len(state.tasks_running)
        
        logger.info(f"[Brain] Iteration {self.execution_count}: "
                    f"completed={completed_count}, running={running_count}, "
                    f"failed={failed_count}, blocked={blocked_count}")
        
        # Check for blocking issues
        if blocked_count > 0 and running_count == 0 and completed_count == 0:
            return BrainDecision(
                action=BrainDecisionAction.BLOCKED,
                reason="Tasks blocked and no progress being made"
            )
        
        # Phase-based decision
        phase = self._determine_phase(state)
        
        if phase == "recon":
            return self.plan_reconnaissance(state)
        elif phase == "analysis":
            return self.plan_analysis(state)
        else:
            return BrainDecision(
                action=BrainDecisionAction.COMPLETE,
                reason="No more phases to execute"
            )

    def plan_analysis(self, state: ExecutionState) -> BrainDecision:
        """Plan vulnerability analysis phase"""
        # This would implement deeper analysis logic
        return BrainDecision(
            action=BrainDecisionAction.COMPLETE,
            reason="Analysis planning not yet implemented"
        )

    def _determine_phase(self, state: ExecutionState) -> str:
        """Determine current phase of execution"""
        hosts_known = len(self.knowledge_store.get_by_type("host"))
        ports_known = len(self.knowledge_store.get_by_type("port"))
        services_known = len(self.knowledge_store.get_by_type("service"))
        
        if hosts_known == 0:
            return "recon"
        elif ports_known == 0:
            return "recon"
        elif services_known == 0:
            return "recon"
        else:
            return "analysis"

    def get_execution_state(self) -> ExecutionState:
        """
        Build structured state for Brain decision-making.
        Not raw logs or context, structured facts.
        """
        # Separate tasks by status
        all_tasks = self.task_manager.get_all_tasks()
        completed = [t.spec for t in all_tasks if t.status.value == "COMPLETED"]
        running = [t.spec for t in all_tasks if t.status.value == "RUNNING"]
        failed = [t.spec.task_id for t in all_tasks if t.status.value == "FAILED"]
        blocked = [t.spec.task_id for t in all_tasks if t.status.value == "BLOCKED"]
        
        return ExecutionState(
            target=self.target,
            scope=self.scope,
            tasks_completed=completed,
            tasks_running=running,
            tasks_failed=failed,
            tasks_blocked=blocked,
            task_dependency_graph=self.task_manager.get_dependency_graph(),
            knowledge_summary=self.knowledge_store.summarize(),
            evidence_summary=self.evidence_store.to_dict(),
            findings=self.finding_store.get_all(),
            available_capabilities=[
                CapabilityType.DNS_ENUMERATION,
                CapabilityType.PORT_SCANNING,
                CapabilityType.TLS_ANALYSIS,
                CapabilityType.TECHNOLOGY_FINGERPRINTING,
                CapabilityType.HTTP_ANALYSIS,
            ],
            objectives=self.scope.get("objectives", []),
        )

    def to_dict(self) -> Dict:
        """Serialize brain state"""
        return {
            "execution_count": self.execution_count,
            "target": self.target,
            "scope": self.scope,
            "knowledge": self.knowledge_store.to_dict(),
            "evidence": self.evidence_store.to_dict(),
            "findings": self.finding_store.to_dict(),
            "tasks": self.task_manager.to_dict(),
            "start_time": self.start_time.isoformat(),
        }

    def _get_db_execution_context(self) -> Dict[str, Any]:
        """Pull active execution context and discovered assets from findings.db and TaskManager."""
        completed_tasks = []
        for task in self.task_manager.get_all_tasks():
            if task.status.value in ("COMPLETED", "FAILED", "RUNNING"):
                target = task.spec.inputs.get("target") or task.spec.inputs.get("url") or task.spec.inputs.get("domain") or self.target
                tools = task.spec.inputs.get("tools", [])
                summary_finding = ""
                if task.result and isinstance(task.result, dict):
                    summary_finding = str(task.result.get("results") or task.result.get("reason") or "")[:150]
                completed_tasks.append([
                    task.spec.capability.value,
                    target,
                    ",".join(tools) if tools else "default",
                    task.status.value,
                    summary_finding
                ])

        # Pull discovered assets from persistent knowledge store or shared context
        subdomains = list(getattr(self.ctx, "subdomains", []))
        ips = list(getattr(self.ctx, "ips", []))
        ports = dict(getattr(self.ctx, "ports", {}))
        technologies = dict(getattr(self.ctx, "technologies", {}))

        return {
            "completed_tasks": completed_tasks[-10:],
            "discovered_assets": {
                "subdomains": subdomains[:10],
                "ips": ips[:10],
                "open_ports": ports,
                "technologies": technologies
            }
        }

    def _is_recon_complete(self, db_context: Dict[str, Any]) -> bool:
        """Check if essential reconnaissance capabilities for discovered targets have finished."""
        completed = db_context.get("completed_tasks", [])
        if not completed:
            return False

        # Gather target domains/subdomains tested for recon
        recon_caps = {"dns_enumeration", "port_scanning", "technology_fingerprinting", "tls_analysis"}
        executed_recon = {f"{item[0]}:{item[1]}" for item in completed if item[0] in recon_caps and item[3] == "COMPLETED"}

        # Targets requiring recon
        subdomains = db_context.get("discovered_assets", {}).get("subdomains", [])
        targets = set([self.target] + subdomains)

        # Check if port scanning & tech fingerprinting ran for primary target and subdomains
        required_pairs = {f"port_scanning:{t}" for t in targets}
        return required_pairs.issubset(executed_recon)

    def _aggregate_wave_results(self, agents: List[Any], results: List[Any]) -> None:
        """Aggregate findings and discovered assets from executed agent wave into shared context and database."""
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                continue
            
            res_data = result if isinstance(result, dict) else {}
            
            # 1. Aggregate discovered ports
            discovered_ports = res_data.get("open_ports") or res_data.get("ports") or []
            if isinstance(discovered_ports, list):
                for port in discovered_ports:
                    if isinstance(port, (int, str)):
                        self.ctx.ports[str(port)] = "open"
                    elif isinstance(port, dict):
                        p_num = str(port.get("port", ""))
                        if p_num:
                            self.ctx.ports[p_num] = port.get("service", "open")

            # 2. Aggregate discovered endpoints
            endpoints = res_data.get("endpoints") or res_data.get("discovered_endpoints") or []
            if isinstance(endpoints, list):
                for ep in endpoints:
                    if isinstance(ep, str) and ep not in self.ctx.endpoints:
                        self.ctx.endpoints.append(ep)

            # 3. Aggregate discovered subdomains
            subdomains = res_data.get("subdomains") or []
            if isinstance(subdomains, list):
                for sub in subdomains:
                    if isinstance(sub, str) and sub not in self.ctx.subdomains:
                        self.ctx.subdomains.append(sub)

            # 4. Aggregate technologies
            techs = res_data.get("technologies") or {}
            if isinstance(techs, dict):
                self.ctx.technologies.update(techs)

            # 5. Persist to KnowledgeStore if available
            if hasattr(self, "store") and self.store:
                try:
                    for port, service in self.ctx.ports.items():
                        self.store.add_asset(
                            asset_type="port",
                            value=f"{self.ctx.target}:{port}",
                            metadata={"service": service}
                        )
                    for ep in self.ctx.endpoints:
                        self.store.add_endpoint(
                            target_id=self.ctx.target,
                            url=ep,
                            method="GET"
                        )
                except Exception as e:
                    logger.warning(f"Failed to persist wave aggregation to knowledge store: {e}")