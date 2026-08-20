"""
Chain Integration
Hooks the vulnerability graph, chain detector, and chain executor
into CentralBrain's workflow. Auto-suggests and executes best chains.
"""

import logging
from typing import Dict, List, Optional

from core.vuln_graph import VulnGraph
from core.relationship_db import RelationshipDB
from core.chain_detector import ChainDetector, ScoredChain
from core.chain_executor import ChainExecutor, ChainResult
from core.shared_context import SharedContext
from core.agent_spawner import AgentSpawner
from agents.llm_client import LLMClient, TaskTier

logger = logging.getLogger(__name__)


class ChainManager:
    """
    Manages the full chain lifecycle:
    1. Build vuln graph from discovered vulns
    2. Detect and score chains
    3. Let LLM pick or auto-pick best chain
    4. Execute chain with fallback
    5. Report results back to brain
    """

    def __init__(self, ctx: SharedContext, spawner: AgentSpawner):
        self.ctx = ctx
        self.spawner = spawner
        self.llm = LLMClient.get()
        self.rel_db = RelationshipDB()
        self.graph: Optional[VulnGraph] = None
        self.detector: Optional[ChainDetector] = None
        self.executor: Optional[ChainExecutor] = None

    def build_graph(self) -> VulnGraph:
        """Build vulnerability graph from current shared context"""
        self.graph = VulnGraph()
        self.graph.build_from_context(self.ctx.vulnerabilities, self.rel_db)

        self.detector = ChainDetector(self.graph, self.rel_db)
        self.executor = ChainExecutor(
            self.graph, self.detector, self.rel_db,
            self.ctx, self.spawner
        )

        logger.info(f"[ChainMgr] Graph built: {len(self.graph.nodes)} vulns, "
                     f"{len(self.graph.edges)} edges")
        return self.graph

    def detect_chains(self, max_chains: int = 5) -> List[ScoredChain]:
        """Detect and score attack chains"""
        if not self.graph:
            self.build_graph()
        chains = self.detector.detect_chains(max_chains=max_chains)
        logger.info(f"[ChainMgr] Detected {len(chains)} chains")
        return chains

    async def auto_execute(self) -> Optional[ChainResult]:
        """Auto-select and execute the best chain"""
        if not self.detector:
            self.detect_chains()
        if not self.executor:
            logger.error("[ChainMgr] Executor not initialized")
            return None
        return await self.executor.execute_best_chain()

    async def llm_select_and_execute(self) -> Optional[ChainResult]:
        """Let LLM choose which chain to execute from top candidates"""
        if not self.detector:
            self.detect_chains()

        chains = self.detector.get_top_chains(5)
        if not chains:
            logger.warning("[ChainMgr] No chains to select from")
            return None

        # Ask LLM to pick
        chain_summary = self.detector.summary_for_llm()
        graph_summary = self.graph.summary_for_llm()

        prompt = f"""You are selecting an attack chain to execute.

{graph_summary}

{chain_summary}

CONTEXT:
Target: {self.ctx.target}
Previous exploits: {len(self.ctx.exploit_results)}

Pick the best chain to execute. Consider:
- Highest score = best success_rate × impact / complexity
- Prefer chains with confirmed vulnerabilities
- Avoid chains that overlap with already-exploited vulns
- Shorter chains are more reliable

Respond with JSON:
{{
  "selected_chain_id": "CHAIN-001",
  "reasoning": "why this chain",
  "expected_outcome": "what we expect to achieve"
}}"""

        decision = await self.llm.generate_json(prompt, tier=TaskTier.LARGE)

        if not decision:
            logger.warning("[ChainMgr] LLM returned no selection, using top chain")
            return await self.executor.execute_chain(chains[0])

        selected_id = decision.get("selected_chain_id", "")
        logger.info(f"[ChainMgr] LLM selected: {selected_id} — "
                     f"{decision.get('reasoning', '')[:80]}")

        # Find selected chain
        selected = None
        for c in chains:
            if c.chain_id == selected_id:
                selected = c
                break

        if not selected:
            logger.warning(f"[ChainMgr] Selected chain {selected_id} not found, using top")
            selected = chains[0]

        return await self.executor.execute_chain(selected)

    def get_brain_context(self) -> str:
        """Get chain context for brain prompt"""
        parts = []

        if self.graph and self.graph.nodes:
            parts.append(self.graph.summary_for_llm(max_chars=1000))

        if self.detector and self.detector.scored_chains:
            parts.append(self.detector.summary_for_llm(max_chains=3))

        if self.executor and self.executor.execution_history:
            parts.append(self.executor.summary_for_llm())

        return "\n".join(parts) if parts else ""

    def suggest_next_exploits(self) -> List[Dict]:
        """Based on what's been exploited, suggest what to try next"""
        if not self.graph:
            return []

        suggestions = []
        for nid, node in self.graph.nodes.items():
            if node.exploited:
                # What can we reach from this exploited node?
                next_steps = self.rel_db.suggest_next_steps(node.vuln_type)
                for ns in next_steps:
                    suggestions.append({
                        "from_vuln": nid,
                        "from_type": node.vuln_type,
                        "target_type": ns["target"],
                        "relationship": ns["relationship"],
                        "success_rate": ns["success_rate"],
                        "description": ns["description"],
                    })

        suggestions.sort(key=lambda s: s["success_rate"], reverse=True)
        return suggestions[:10]

    def get_exploitation_plan(self) -> Dict:
        """Generate a complete exploitation plan for the brain"""
        if not self.detector:
            self.detect_chains()

        chains = self.detector.get_top_chains(5)
        suggestions = self.suggest_next_exploits()

        return {
            "graph_stats": {
                "vulnerabilities": len(self.graph.nodes) if self.graph else 0,
                "relationships": len(self.graph.edges) if self.graph else 0,
                "chains_found": len(chains),
            },
            "top_chains": [
                {
                    "id": c.chain_id,
                    "description": c.description,
                    "score": c.score,
                    "success_rate": c.success_rate,
                    "steps": len(c.steps),
                } for c in chains
            ],
            "next_exploit_suggestions": suggestions[:5],
            "execution_history": [
                {
                    "chain": r.chain_id,
                    "status": r.status,
                    "steps": f"{r.steps_completed}/{r.steps_total}",
                    "impact": r.final_impact,
                } for r in (self.executor.execution_history if self.executor else [])
            ],
        }

    def to_dict(self) -> Dict:
        """Full serialization for reporting"""
        return {
            "graph": self.graph.to_dict() if self.graph else {},
            "chains": self.detector.to_dict() if self.detector else {},
            "executions": [
                {
                    "chain_id": r.chain_id,
                    "status": r.status,
                    "steps_completed": r.steps_completed,
                    "steps_total": r.steps_total,
                    "impact": r.final_impact,
                    "started": r.started_at,
                    "finished": r.finished_at,
                    "results": [
                        {
                            "vuln_id": sr.vuln_id,
                            "type": sr.vuln_type,
                            "success": sr.success,
                            "proof": sr.proof,
                            "error": sr.error,
                            "duration": sr.duration_sec,
                        } for sr in r.results
                    ],
                } for r in (self.executor.execution_history if self.executor else [])
            ],
        }