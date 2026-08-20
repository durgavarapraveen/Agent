"""
Chain Detector
Scores attack chains, finds top paths, suggests alternatives when primary fails.
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from core.vuln_graph import VulnGraph, AttackPath, VulnNode
from core.relationship_db import RelationshipDB

logger = logging.getLogger(__name__)


@dataclass
class ScoredChain:
    """A scored and annotated attack chain"""
    chain_id: str
    steps: List[Dict]       # [{vuln_id, type, location, severity}]
    edges: List[Dict]       # [{from, to, relationship, success_rate}]
    score: float = 0.0
    success_rate: float = 0.0
    max_impact: float = 0.0
    complexity: int = 0
    description: str = ""
    status: str = "pending"  # pending, executing, completed, failed
    alternative_ids: List[str] = field(default_factory=list)


class ChainDetector:
    """Finds, scores, and manages attack chains"""

    def __init__(self, graph: VulnGraph, rel_db: RelationshipDB):
        self.graph = graph
        self.rel_db = rel_db
        self.scored_chains: List[ScoredChain] = []
        self.failed_chains: List[str] = []

    def detect_chains(self, max_chains: int = 10) -> List[ScoredChain]:
        """Find and score all attack chains, return top N"""
        raw_paths = self.graph.find_all_paths(max_depth=6)

        scored = []
        for path in raw_paths:
            sc = self._score_chain(path)
            if sc and sc.score > 0:
                scored.append(sc)

        # Deduplicate similar chains (same start+end, keep highest score)
        scored = self._deduplicate(scored)

        # Sort by score
        scored.sort(key=lambda c: c.score, reverse=True)

        # Find alternatives for each chain
        for i, chain in enumerate(scored[:max_chains]):
            chain.alternative_ids = [
                c.chain_id for c in scored[i+1:i+4]
                if c.steps[-1] == chain.steps[-1]  # Same goal
            ]

        self.scored_chains = scored[:max_chains]
        logger.info(f"[ChainDetector] Detected {len(self.scored_chains)} chains "
                     f"(top score: {self.scored_chains[0].score:.3f})" if self.scored_chains else "")
        return self.scored_chains

    def get_top_chains(self, n: int = 5) -> List[ScoredChain]:
        """Return top N scored chains"""
        if not self.scored_chains:
            self.detect_chains()
        return self.scored_chains[:n]

    def get_alternatives(self, failed_chain_id: str) -> List[ScoredChain]:
        """When a chain fails, get alternatives with same end goal"""
        self.failed_chains.append(failed_chain_id)

        # Find the failed chain
        failed = None
        for c in self.scored_chains:
            if c.chain_id == failed_chain_id:
                failed = c
                break

        if not failed:
            return []

        # Find chains with same end goal that haven't failed
        goal_type = failed.steps[-1].get("type", "") if failed.steps else ""
        alternatives = [
            c for c in self.scored_chains
            if c.chain_id not in self.failed_chains
            and c.chain_id != failed_chain_id
            and c.steps  # has steps
            and (c.steps[-1].get("type", "") == goal_type  # same goal
                 or c.score > 0.1)  # or decent score
        ]

        alternatives.sort(key=lambda c: c.score, reverse=True)
        logger.info(f"[ChainDetector] {len(alternatives)} alternatives for failed {failed_chain_id}")
        return alternatives[:5]

    def _score_chain(self, path: AttackPath) -> Optional[ScoredChain]:
        """Score an attack path: (success_rate × impact) / complexity"""
        if len(path.steps) < 2:
            return None

        # Build step details
        steps = []
        for nid in path.steps:
            node = self.graph.nodes.get(nid)
            if not node:
                continue
            steps.append({
                "vuln_id": nid,
                "type": node.vuln_type,
                "location": node.location,
                "severity": node.severity,
            })

        # Build edge details
        edges = []
        for edge in path.edges:
            edges.append({
                "from": edge.source,
                "to": edge.target,
                "relationship": edge.relationship,
                "success_rate": edge.success_rate,
            })

        # Calculate scores
        success_rate = path.total_success_rate
        max_impact = path.total_impact
        complexity = max(len(steps), 1)

        # Bonus for confirmed vulns
        confirmed_bonus = sum(
            0.1 for nid in path.steps
            if self.graph.nodes.get(nid, VulnNode("","","","")).confirmed
        )

        # Penalty for already-exploited vulns (already done)
        exploited_penalty = sum(
            0.2 for nid in path.steps
            if self.graph.nodes.get(nid, VulnNode("","","","")).exploited
        )

        score = ((success_rate * max_impact) / complexity) + confirmed_bonus - exploited_penalty
        score = max(score, 0.0)

        # Build description
        chain_desc = " → ".join(s["type"] for s in steps)

        return ScoredChain(
            chain_id=path.chain_id,
            steps=steps,
            edges=edges,
            score=score,
            success_rate=success_rate,
            max_impact=max_impact,
            complexity=complexity,
            description=chain_desc,
        )

    def _deduplicate(self, chains: List[ScoredChain]) -> List[ScoredChain]:
        """Remove duplicate chains (same start→end, keep highest score)"""
        seen = {}
        unique = []
        for c in sorted(chains, key=lambda x: -x.score):
            if not c.steps:
                continue
            key = (c.steps[0].get("vuln_id", ""), c.steps[-1].get("vuln_id", ""))
            if key not in seen:
                seen[key] = True
                unique.append(c)
        return unique

    def summary_for_llm(self, max_chains: int = 5) -> str:
        """Compact summary for LLM context"""
        if not self.scored_chains:
            return "No attack chains detected."

        lines = [f"TOP {min(max_chains, len(self.scored_chains))} ATTACK CHAINS:"]
        for i, c in enumerate(self.scored_chains[:max_chains]):
            lines.append(
                f"  #{i+1} [{c.chain_id}] {c.description} "
                f"(score={c.score:.3f}, success={c.success_rate:.0%}, "
                f"impact={c.max_impact:.1f}, steps={c.complexity})"
            )
            if c.alternative_ids:
                lines.append(f"       Alternatives: {', '.join(c.alternative_ids)}")

        if self.failed_chains:
            lines.append(f"  FAILED: {', '.join(self.failed_chains)}")

        return "\n".join(lines)

    def to_dict(self) -> Dict:
        """Serialize for storage"""
        return {
            "chains": [{
                "chain_id": c.chain_id,
                "steps": c.steps,
                "edges": c.edges,
                "score": c.score,
                "success_rate": c.success_rate,
                "max_impact": c.max_impact,
                "complexity": c.complexity,
                "description": c.description,
                "status": c.status,
                "alternatives": c.alternative_ids,
            } for c in self.scored_chains],
            "failed": self.failed_chains,
        }