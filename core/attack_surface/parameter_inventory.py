import logging
from typing import Dict, Any, List
from core.attack_surface.graph import AttackSurfaceGraph, CanonicalNode, CanonicalParameter, NodeType, EdgeType

logger = logging.getLogger(__name__)


class ParameterInventory:
    """Manages PARAMETER nodes in the graph."""

    def __init__(self, graph: AttackSurfaceGraph):
        self.graph = graph
        self._param_cache = {}

    def ingest_parameters(self, endpoint_node: CanonicalNode, parameters: List[Dict[str, Any]]):
        """
        Creates PARAMETER nodes and links them to the ENDPOINT via ACCEPTS.
        parameters: [{"name": "id", "type": "query"}, {"name": "body", "type": "json"}]
        """
        for param_data in parameters:
            param_name = param_data.get("name")
            param_type = param_data.get("type", "unknown")
            
            cache_key = f"{endpoint_node.id}::p::{param_name}::{param_type}"
            
            if cache_key in self._param_cache:
                continue
                
            param_node = CanonicalParameter(
                label=param_name,
                name=param_name,
                param_type=param_type
            )
            self.graph.add_node(param_node)
            self._param_cache[cache_key] = param_node.id
            
            # ENDPOINT -> ACCEPTS -> PARAMETER
            self.graph.add_edge(endpoint_node.id, param_node.id, EdgeType.ACCEPTS)
            logger.debug(f"Ingested parameter: {param_name} for endpoint {endpoint_node.label}")
