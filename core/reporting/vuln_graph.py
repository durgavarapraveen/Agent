"""
Vulnerability Graph Builder
Builds a directed graph of discovered vulnerabilities and finds all attack paths.
Nodes = vulnerabilities, Edges = "leads to" relationships.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class VulnNode:
    """A vulnerability in the attack graph"""
    id: str
    vuln_type: str          # sqli, xss, lfi, rce, auth_bypass, etc.
    location: str           # URL/endpoint where it exists
    severity: str           # critical, high, medium, low
    details: Dict = field(default_factory=dict)
    confirmed: bool = False
    exploited: bool = False
    unlocks: List[str] = field(default_factory=list)  # What this vuln can lead to

    @property
    def impact_score(self) -> float:
        scores = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
        return scores.get(self.severity, 0.3)


@dataclass
class AttackEdge:
    """A relationship between two vulnerabilities"""
    source: str       # source vuln id
    target: str       # target vuln id
    relationship: str # e.g. "credentials_from", "access_to", "escalates_to"
    success_rate: float = 0.5
    description: str = ""


@dataclass
class AttackPath:
    """A complete chain of vulnerabilities"""
    chain_id: str
    steps: List[str]           # ordered vuln IDs
    edges: List[AttackEdge]    # edges between steps
    total_impact: float = 0.0
    total_success_rate: float = 0.0
    complexity: int = 0
    score: float = 0.0        # (success_rate * impact) / complexity


class VulnGraph:
    """Directed graph of vulnerabilities and attack relationships"""

    def __init__(self):
        self.nodes: Dict[str, VulnNode] = {}
        self.edges: List[AttackEdge] = []
        self.adjacency: Dict[str, List[AttackEdge]] = defaultdict(list)  # source → edges
        self.reverse_adj: Dict[str, List[AttackEdge]] = defaultdict(list)  # target → edges
        self._path_counter = 0

    def add_vulnerability(self, vuln: Dict) -> VulnNode:
        """Add a vulnerability node from shared context format"""
        vid = vuln.get("id", f"VULN-{len(self.nodes)+1:03d}")
        node = VulnNode(
            id=vid,
            vuln_type=vuln.get("type", vuln.get("vuln_type", "unknown")),
            location=vuln.get("location", vuln.get("url", "")),
            severity=vuln.get("severity", "medium"),
            details=vuln,
            confirmed=vuln.get("confirmed", False),
        )
        self.nodes[vid] = node
        logger.info(f"[VulnGraph] Added node: {vid} ({node.vuln_type} @ {node.location})")
        return node

    def add_edge(self, source_id: str, target_id: str,
                 relationship: str, success_rate: float = 0.5,
                 description: str = "") -> Optional[AttackEdge]:
        """Add a directed edge between two vulnerability nodes"""
        if source_id not in self.nodes or target_id not in self.nodes:
            logger.warning(f"[VulnGraph] Edge skipped: {source_id} → {target_id} (missing node)")
            return None

        edge = AttackEdge(
            source=source_id,
            target=target_id,
            relationship=relationship,
            success_rate=success_rate,
            description=description,
        )
        self.edges.append(edge)
        self.adjacency[source_id].append(edge)
        self.reverse_adj[target_id].append(edge)
        logger.debug(f"[VulnGraph] Edge: {source_id} --[{relationship}]--> {target_id}")
        return edge

    def build_from_context(self, vulnerabilities: List[Dict],
                           relationship_db: Optional["RelationshipDB"] = None):
        """
        Build graph from SharedContext.vulnerabilities list.
        Auto-infer edges using RelationshipDB if provided.
        """
        # Add all vulns as nodes
        for v in vulnerabilities:
            self.add_vulnerability(v)

        # Auto-infer edges from relationship database
        if relationship_db:
            nodes_list = list(self.nodes.values())
            for i, src in enumerate(nodes_list):
                for tgt in nodes_list[i+1:]:
                    rel = relationship_db.get_relationship(src.vuln_type, tgt.vuln_type)
                    if rel:
                        self.add_edge(
                            src.id, tgt.id,
                            relationship=rel["relationship"],
                            success_rate=rel["success_rate"],
                            description=rel.get("description", ""),
                        )
                    # Check reverse direction
                    rev = relationship_db.get_relationship(tgt.vuln_type, src.vuln_type)
                    if rev:
                        self.add_edge(
                            tgt.id, src.id,
                            relationship=rev["relationship"],
                            success_rate=rev["success_rate"],
                            description=rev.get("description", ""),
                        )

        logger.info(f"[VulnGraph] Built graph: {len(self.nodes)} nodes, {len(self.edges)} edges")

    def find_all_paths(self, max_depth: int = 6) -> List[AttackPath]:
        """Find all attack paths using DFS from every entry point"""
        all_paths: List[AttackPath] = []

        # Entry points = nodes with no incoming edges (or all nodes for completeness)
        entry_points = [nid for nid in self.nodes if nid not in self.reverse_adj]
        if not entry_points:
            entry_points = list(self.nodes.keys())

        for start in entry_points:
            visited: Set[str] = set()
            self._dfs_paths(start, visited, [start], [], all_paths, max_depth)

        # Score each path
        for path in all_paths:
            path.score = self._score_path(path)

        # Sort by score descending
        all_paths.sort(key=lambda p: p.score, reverse=True)
        logger.info(f"[VulnGraph] Found {len(all_paths)} attack paths")
        return all_paths

    def _dfs_paths(self, current: str, visited: Set[str],
                   path_nodes: List[str], path_edges: List[AttackEdge],
                   results: List[AttackPath], max_depth: int):
        """DFS to find all paths"""
        if len(path_nodes) > max_depth:
            return

        visited.add(current)

        # If path has at least 2 nodes, record it
        if len(path_nodes) >= 2:
            self._path_counter += 1
            chain = AttackPath(
                chain_id=f"CHAIN-{self._path_counter:03d}",
                steps=list(path_nodes),
                edges=list(path_edges),
                complexity=len(path_nodes),
            )
            results.append(chain)

        # Explore neighbors
        for edge in self.adjacency.get(current, []):
            if edge.target not in visited:
                path_nodes.append(edge.target)
                path_edges.append(edge)
                self._dfs_paths(edge.target, visited, path_nodes, path_edges, results, max_depth)
                path_nodes.pop()
                path_edges.pop()

        visited.discard(current)

    def _score_path(self, path: AttackPath) -> float:
        """Score: (combined_success_rate * max_impact) / complexity"""
        if not path.edges:
            return 0.0

        # Combined success rate (multiply all edge probabilities)
        success = 1.0
        for edge in path.edges:
            success *= edge.success_rate
        path.total_success_rate = success

        # Max impact = highest severity node in path
        max_impact = max(
            self.nodes[nid].impact_score for nid in path.steps if nid in self.nodes
        )
        path.total_impact = max_impact

        # Score
        complexity = max(path.complexity, 1)
        path.score = (success * max_impact) / complexity
        return path.score

    def get_entry_vulns(self) -> List[VulnNode]:
        """Get vulnerabilities that are good entry points (no prerequisites)"""
        entry = []
        for nid, node in self.nodes.items():
            if nid not in self.reverse_adj:
                entry.append(node)
        return entry if entry else list(self.nodes.values())

    def get_terminal_vulns(self) -> List[VulnNode]:
        """Get vulnerabilities that are end goals (no outgoing edges)"""
        terminal = []
        for nid, node in self.nodes.items():
            if nid not in self.adjacency:
                terminal.append(node)
        return terminal

    def to_dict(self) -> Dict:
        """Serialize graph for LLM context or storage"""
        return {
            "nodes": {nid: {
                "type": n.vuln_type,
                "location": n.location,
                "severity": n.severity,
                "confirmed": n.confirmed,
                "exploited": n.exploited,
            } for nid, n in self.nodes.items()},
            "edges": [{
                "from": e.source,
                "to": e.target,
                "relationship": e.relationship,
                "success_rate": e.success_rate,
            } for e in self.edges],
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "entry_points": len(self.get_entry_vulns()),
                "terminal_goals": len(self.get_terminal_vulns()),
            }
        }

    def summary_for_llm(self, max_chars: int = 2000) -> str:
        """Compact summary for LLM context window"""
        lines = [f"VULNERABILITY GRAPH: {len(self.nodes)} vulns, {len(self.edges)} relationships"]
        for nid, n in self.nodes.items():
            status = "EXPLOITED" if n.exploited else ("CONFIRMED" if n.confirmed else "unconfirmed")
            lines.append(f"  [{nid}] {n.vuln_type} @ {n.location} ({n.severity}) [{status}]")
        if self.edges:
            lines.append("ATTACK EDGES:")
            for e in self.edges[:10]:
                lines.append(f"  {e.source} --[{e.relationship} {e.success_rate:.0%}]--> {e.target}")
        text = "\n".join(lines)
        return text[:max_chars]