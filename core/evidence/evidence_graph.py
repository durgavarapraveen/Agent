import logging
import hashlib
import json
import time
from typing import Dict, Any, List
import uuid

from core.observability.correlation import get_context as _get_correlation_context

logger = logging.getLogger(__name__)

class EvidenceNode:
    def __init__(self, node_type: str, data: Dict[str, Any]):
        self.id = uuid.uuid4().hex
        self.node_type = node_type
        self.data = data
        self.timestamp = time.time()
        self.correlation = _get_correlation_context()
        self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        # Cryptographic hashing for provenance/tamper detection
        content = json.dumps({
            "type": self.node_type,
            "data": self.data,
            "timestamp": self.timestamp
        }, sort_keys=True)
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

class EvidenceGraph:
    """
    First-class evidence graph linking requests, responses, identities, destinations, 
    timing, browser state, tools, and experiment metadata.
    """
    def __init__(self):
        self.nodes: Dict[str, EvidenceNode] = {}
        self.edges: List[Dict[str, str]] = []

    def add_node(self, node_type: str, data: Dict[str, Any]) -> str:
        node = EvidenceNode(node_type, data)
        self.nodes[node.id] = node
        return node.id

    def add_edge(self, from_id: str, to_id: str, relation: str):
        if from_id in self.nodes and to_id in self.nodes:
            self.edges.append({
                "from": from_id,
                "to": to_id,
                "relation": relation
            })
        else:
            logger.warning(f"Failed to add edge {from_id} -> {to_id}: Node missing")

    def link_experiment(self, experiment_id: str, request_node: str, response_node: str, identity_node: str):
        """Link an entire experiment execution path."""
        exp_node = self.add_node("experiment", {"experiment_id": experiment_id})
        self.add_edge(exp_node, request_node, "sent_request")
        self.add_edge(request_node, response_node, "received_response")
        self.add_edge(exp_node, identity_node, "executed_as")
        return exp_node

    def verify_integrity(self) -> bool:
        """Verify the cryptographic hashes of all nodes."""
        for node in self.nodes.values():
            if node.hash != node._compute_hash():
                logger.error(f"Integrity check failed for node {node.id}")
                return False
        return True

    def export(self) -> Dict[str, Any]:
        """Export the graph for reporting or external verification."""
        return {
            "nodes": [
                {"id": n.id, "type": n.node_type, "hash": n.hash, "data": n.data} 
                for n in self.nodes.values()
            ],
            "edges": self.edges
        }
