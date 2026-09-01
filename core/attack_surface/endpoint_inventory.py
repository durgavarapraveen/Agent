import logging
from typing import Optional
from core.attack_surface.graph import AttackSurfaceGraph, CanonicalEndpoint, NodeType
from core.attack_surface.route_normalizer import RouteNormalizer

logger = logging.getLogger(__name__)


class EndpointInventory:
    """Manages ENDPOINT nodes in the graph."""

    def __init__(self, graph: AttackSurfaceGraph):
        self.graph = graph
        self.normalizer = RouteNormalizer()
        # Fast lookup mapping: "METHOD {normalized_path}" -> Node ID
        self._endpoint_cache = {}

    def get_or_create_endpoint(self, method: str, path: str) -> CanonicalEndpoint:
        """
        Normalizes the path, checks if the endpoint exists, and creates it if not.
        """
        normalized_path = self.normalizer.normalize(path)
        cache_key = f"{method.upper()} {normalized_path}"
        
        if cache_key in self._endpoint_cache:
            node_id = self._endpoint_cache[cache_key]
            return self.graph.nodes[node_id]
            
        # Create new endpoint node
        node = CanonicalEndpoint(
            label=cache_key,
            method=method.upper(),
            normalized_path=normalized_path,
            raw_paths_seen={path}
        )
        self.graph.add_node(node)
        self._endpoint_cache[cache_key] = node.id
        logger.debug(f"Created new endpoint node: {cache_key}")
        
        return node
        
    def record_raw_path(self, endpoint_node: CanonicalEndpoint, raw_path: str):
        """Records a new raw path variation if it hasn't been seen."""
        endpoint_node.raw_paths_seen.add(raw_path)
