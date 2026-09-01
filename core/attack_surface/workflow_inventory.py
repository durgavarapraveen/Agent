import logging
from typing import List
from core.attack_surface.graph import AttackSurfaceGraph, CanonicalNode, CanonicalWorkflow, NodeType, EdgeType

logger = logging.getLogger(__name__)


class WorkflowInventory:
    """Manages WORKFLOW nodes in the graph."""

    def __init__(self, graph: AttackSurfaceGraph):
        self.graph = graph
        self._workflow_cache = {}

    def ingest_workflow(self, workflow_name: str, request_nodes: List[CanonicalNode]) -> CanonicalNode:
        """
        Creates a WORKFLOW node and links it to REQUEST nodes via CONTAINS.
        """
        cache_key = f"wf::{workflow_name}"
        
        if cache_key in self._workflow_cache:
            wf_node_id = self._workflow_cache[cache_key]
            wf_node = self.graph.nodes[wf_node_id]
        else:
            wf_node = CanonicalWorkflow(
                label=workflow_name,
                steps=len(request_nodes)
            )
            self.graph.add_node(wf_node)
            self._workflow_cache[cache_key] = wf_node.id
            logger.debug(f"Created workflow: {workflow_name}")
            
        # Link WORKFLOW -> CONTAINS -> REQUEST
        for req_node in request_nodes:
            self.graph.add_edge(wf_node.id, req_node.id, EdgeType.CONTAINS)
            
        return wf_node
