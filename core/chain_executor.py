"""
Chain Executor
Executes attack chains step by step, verifies success, handles failures,
and falls back to alternative chains.
"""

import logging
import asyncio
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

from core.chain_detector import ChainDetector, ScoredChain
from core.vuln_graph import VulnGraph
from core.relationship_db import RelationshipDB
from core.shared_context import SharedContext
from core.agent_spawner import AgentSpawner
from agents.llm_client import LLMClient, TaskTier

logger = logging.getLogger(__name__)


@dataclass
class StepResult:
    """Result of executing one step in a chain"""
    vuln_id: str
    vuln_type: str
    success: bool
    proof: str = ""
    data_extracted: Dict = field(default_factory=dict)
    error: str = ""
    agent_id: str = ""
    duration_sec: float = 0.0


@dataclass
class ChainResult:
    """Result of executing an entire chain"""
    chain_id: str
    status: str           # completed, partial, failed
    steps_completed: int
    steps_total: int
    results: List[StepResult] = field(default_factory=list)
    final_impact: str = ""
    alternative_used: Optional[str] = None
    started_at: str = ""
    finished_at: str = ""


CHAIN_STEP_SYSTEM = """You are a security verification agent executing one step of an authorized attack chain.

Your task: exploit a specific vulnerability and extract proof/data that enables the next step.

RULES:
- Execute the specific exploit described in your objective
- Collect proof of exploitation (screenshots, data, tokens)
- Extract any data needed for the NEXT step in the chain
- Report success/failure honestly
- Output ONLY valid JSON

RESPONSE when done:
{
  "action": "done",
  "results": {
    "success": true/false,
    "proof": "description of what was achieved",
    "data_extracted": {"credentials": [...], "tokens": [...], "files": [...]},
    "next_step_input": {"key": "value to pass to next step"}
  }
}"""


class ChainExecutor:
    """Executes attack chains with verification and fallback"""

    def __init__(self, graph: VulnGraph, detector: ChainDetector,
                 rel_db: RelationshipDB, ctx: SharedContext,
                 spawner: AgentSpawner):
        self.graph = graph
        self.detector = detector
        self.rel_db = rel_db
        self.ctx = ctx
        self.spawner = spawner
        self.llm = LLMClient.get()
        self.execution_history: List[ChainResult] = []
        self.max_retries_per_step = 2
        self.max_alternative_chains = 3

    async def execute_chain(self, chain: ScoredChain) -> ChainResult:
        """Execute a chain step by step with verification"""
        logger.info(f"[ChainExec] Starting chain {chain.chain_id}: {chain.description}")
        chain.status = "executing"

        result = ChainResult(
            chain_id=chain.chain_id,
            status="executing",
            steps_completed=0,
            steps_total=len(chain.steps),
            started_at=datetime.now().isoformat(),
        )

        prev_step_data: Dict = {}  # Data passed from previous step

        for i, step in enumerate(chain.steps):
            vuln_id = step.get("vuln_id", "")
            vuln_type = step.get("vuln_type", step.get("type", ""))
            location = step.get("location", "")

            logger.info(f"[ChainExec] Step {i+1}/{len(chain.steps)}: "
                         f"{vuln_type} @ {location}")

            # Build step objective
            edge_desc = ""
            if i < len(chain.edges):
                edge = chain.edges[i]
                edge_desc = f"Relationship: {edge.get('relationship', '')} "
                edge_desc += f"(expected success: {edge.get('success_rate', 0):.0%})"

            objective = self._build_step_objective(
                step_num=i+1,
                total_steps=len(chain.steps),
                vuln_type=vuln_type,
                location=location,
                edge_desc=edge_desc,
                prev_data=prev_step_data,
                next_step=chain.steps[i+1] if i+1 < len(chain.steps) else None,
            )

            # Execute step with retry
            step_result = await self._execute_step(
                vuln_id=vuln_id,
                vuln_type=vuln_type,
                objective=objective,
                location=location,
            )

            result.results.append(step_result)

            if step_result.success:
                result.steps_completed += 1
                prev_step_data = step_result.data_extracted

                # Mark node as exploited in graph
                if vuln_id in self.graph.nodes:
                    self.graph.nodes[vuln_id].exploited = True

                # Store in shared context
                self.ctx.exploit_results.append({
                    "vuln_id": vuln_id,
                    "type": vuln_type,
                    "success": True,
                    "proof": step_result.proof,
                    "chain_id": chain.chain_id,
                    "step": i+1,
                })

                logger.info(f"[ChainExec] ✓ Step {i+1} succeeded: {step_result.proof[:80]}")
            else:
                logger.warning(f"[ChainExec] ✗ Step {i+1} failed: {step_result.error}")

                # Store failure
                self.ctx.exploit_results.append({
                    "vuln_id": vuln_id,
                    "type": vuln_type,
                    "success": False,
                    "error": step_result.error,
                    "chain_id": chain.chain_id,
                    "step": i+1,
                })

                # Try alternative chain
                result.status = "partial"
                break

        # Final status
        if result.steps_completed == result.steps_total:
            result.status = "completed"
            chain.status = "completed"
            result.final_impact = self._assess_impact(result)
            logger.info(f"[ChainExec] ✓ Chain {chain.chain_id} COMPLETED: {result.final_impact}")
        else:
            chain.status = "failed"
            result.status = "partial" if result.steps_completed > 0 else "failed"
            logger.warning(f"[ChainExec] Chain {chain.chain_id} ended at step "
                           f"{result.steps_completed}/{result.steps_total}")

        result.finished_at = datetime.now().isoformat()
        self.execution_history.append(result)
        return result

    async def execute_best_chain(self) -> Optional[ChainResult]:
        """Execute the top-scored chain, fall back to alternatives on failure"""
        chains = self.detector.get_top_chains(self.max_alternative_chains + 1)
        if not chains:
            logger.warning("[ChainExec] No chains available to execute")
            return None

        for i, chain in enumerate(chains):
            if chain.chain_id in [r.chain_id for r in self.execution_history]:
                continue  # Skip already-attempted chains

            logger.info(f"[ChainExec] Attempting chain #{i+1}: {chain.description} "
                         f"(score={chain.score:.3f})")
            result = await self.execute_chain(chain)

            if result.status == "completed":
                return result

            # Chain failed, try alternatives
            logger.info(f"[ChainExec] Chain failed, trying alternative...")
            alternatives = self.detector.get_alternatives(chain.chain_id)
            for alt in alternatives[:self.max_alternative_chains]:
                if alt.chain_id in [r.chain_id for r in self.execution_history]:
                    continue
                logger.info(f"[ChainExec] Alternative: {alt.description} (score={alt.score:.3f})")
                alt_result = await self.execute_chain(alt)
                alt_result.alternative_used = chain.chain_id
                if alt_result.status == "completed":
                    return alt_result

        logger.warning("[ChainExec] All chains exhausted")
        return None

    async def _execute_step(self, vuln_id: str, vuln_type: str,
                            objective: str, location: str) -> StepResult:
        """Execute a single chain step via agent spawner"""
        start = datetime.now()

        # Map vuln types to tools
        tools = self._tools_for_vuln(vuln_type)

        spec = {
            "objective": objective,
            "tools": tools,
            "context_keys": ["target", "endpoints", "vulnerabilities", "exploit_results"],
            "max_steps": 8,
            "vuln_type": vuln_type,
        }

        try:
            agent = self.spawner.spawn(spec)
            result = await agent.execute()
            duration = (datetime.now() - start).total_seconds()

            if result.get("status") == "failed":
                return StepResult(
                    vuln_id=vuln_id, vuln_type=vuln_type, success=False,
                    error=result.get("reason", "Agent failed"),
                    agent_id=getattr(agent, 'agent_id', ''),
                    duration_sec=duration,
                )

            # Extract results
            results_data = result.get("results", result)
            return StepResult(
                vuln_id=vuln_id,
                vuln_type=vuln_type,
                success=results_data.get("success", True),
                proof=results_data.get("proof", results_data.get("summary", "")),
                data_extracted=results_data.get("data_extracted",
                               results_data.get("data", {})),
                agent_id=getattr(agent, 'agent_id', ''),
                duration_sec=duration,
            )

        except Exception as e:
            duration = (datetime.now() - start).total_seconds()
            logger.error(f"[ChainExec] Step exception: {e}")
            return StepResult(
                vuln_id=vuln_id, vuln_type=vuln_type, success=False,
                error=str(e), duration_sec=duration,
            )

    def _build_step_objective(self, step_num: int, total_steps: int,
                               vuln_type: str, location: str,
                               edge_desc: str, prev_data: Dict,
                               next_step: Optional[Dict]) -> str:
        """Build a clear objective for the step agent"""
        parts = [
            f"CHAIN STEP {step_num}/{total_steps}: Exploit {vuln_type} at {location}",
        ]

        if edge_desc:
            parts.append(f"  {edge_desc}")

        if prev_data:
            parts.append(f"  Data from previous step: {str(prev_data)[:200]}")

        if next_step:
            parts.append(
                f"  NEXT STEP NEEDS: Extract data for {next_step.get('type', 'unknown')} "
                f"at {next_step.get('location', 'unknown')}"
            )

        parts.append(f"  Collect proof of exploitation and any data for next step.")
        return "\n".join(parts)

    def _tools_for_vuln(self, vuln_type: str) -> List[str]:
        """Map vuln type to relevant tools"""
        tool_map = {
            "sqli":          ["sqlmap", "http_request", "curl"],
            "xss":           ["http_request", "curl", "browser"],
            "lfi":           ["http_request", "curl"],
            "rce":           ["http_request", "curl", "ncat"],
            "ssrf":          ["http_request", "curl"],
            "auth_bypass":   ["http_request", "curl", "hydra"],
            "idor":          ["http_request", "curl"],
            "file_upload":   ["http_request", "curl"],
            "ssti":          ["http_request", "curl"],
            "xxe":           ["http_request", "curl"],
            "csrf":          ["http_request", "curl", "browser"],
            "credentials":   ["http_request", "curl", "hydra"],
            "admin_access":  ["http_request", "curl", "browser"],
            "weak_config":   ["http_request", "curl", "nikto"],
            "cors_misconfig":["http_request", "curl"],
        }
        return tool_map.get(vuln_type, ["http_request", "curl"])

    def _assess_impact(self, result: ChainResult) -> str:
        """Generate impact assessment from chain results"""
        if not result.results:
            return "No impact"

        types_exploited = [r.vuln_type for r in result.results if r.success]
        proofs = [r.proof for r in result.results if r.success and r.proof]

        if "rce" in types_exploited:
            return f"CRITICAL: Remote code execution achieved via {' → '.join(types_exploited)}"
        elif "admin_access" in types_exploited:
            return f"HIGH: Admin access achieved via {' → '.join(types_exploited)}"
        elif "credentials" in types_exploited:
            return f"HIGH: Credentials extracted via {' → '.join(types_exploited)}"
        elif "data_leak" in types_exploited:
            return f"MEDIUM: Data leaked via {' → '.join(types_exploited)}"
        else:
            return f"Chain completed: {' → '.join(types_exploited)}"

    def summary_for_llm(self) -> str:
        """Compact summary for LLM"""
        if not self.execution_history:
            return "No chains executed yet."

        lines = ["CHAIN EXECUTION HISTORY:"]
        for r in self.execution_history:
            status_icon = "✓" if r.status == "completed" else "✗"
            lines.append(
                f"  {status_icon} {r.chain_id}: {r.status} "
                f"({r.steps_completed}/{r.steps_total} steps)"
            )
            if r.final_impact:
                lines.append(f"    Impact: {r.final_impact}")
            for sr in r.results:
                si = "✓" if sr.success else "✗"
                lines.append(f"    {si} {sr.vuln_type}: {sr.proof[:60] or sr.error[:60]}")

        return "\n".join(lines)