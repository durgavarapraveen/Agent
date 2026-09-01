import logging
from typing import Dict, Any, Optional
from core.attack_surface.graph import AttackSurfaceGraph, CanonicalRequest, NodeType, EdgeType
from core.attack_surface.endpoint_inventory import EndpointInventory

logger = logging.getLogger(__name__)


class RequestInventory:
    """Manages REQUEST nodes in the graph."""

    def __init__(self, graph: AttackSurfaceGraph, endpoint_inventory: EndpointInventory):
        self.graph = graph
        self.endpoint_inventory = endpoint_inventory

    def ingest_request(self, method: str, path: str, source: str, is_api: bool = False, properties: Optional[Dict[str, Any]] = None) -> CanonicalRequest:
        """
        Creates a REQUEST node, links it to its ENDPOINT, and sets its DISCOVERED_BY properties.
        """
        # Ensure endpoint exists
        endpoint_node = self.endpoint_inventory.get_or_create_endpoint(method, path)
        self.endpoint_inventory.record_raw_path(endpoint_node, path)
        
        props = properties or {}
        props.update({
            "method": method.upper(),
            "path": path,
            "source": source,
            "is_api": is_api
        })
        
        # Create request node
        req_node = CanonicalRequest(
            label=f"{method.upper()} {path}",
            method=method.upper(),
            url=path,
            source=source,
            is_api=is_api
        )
        self.graph.add_node(req_node)
        
        # We model that a PAGE CALLS an ENDPOINT, and a REQUEST is just a specific instance, 
        # but to keep it simple, we can link the REQUEST to the ENDPOINT
        # Let's say: ENDPOINT -> ACCEPTS -> REQUEST? 
        # Actually, let's link: REQUEST -> DISCOVERED_BY -> (source)
        # We don't have a SOURCE node type, so we just keep it in properties.
        
        # How does Request relate to Endpoint?
        # Maybe Endpoint -> CONTAINS -> Request? Or Request -> INSTANCE_OF -> Endpoint
        # We'll just define an edge REQUEST -> CALLS -> ENDPOINT to keep it connected.
        self.graph.add_edge(req_node.id, endpoint_node.id, EdgeType.CALLS)
        
        logger.debug(f"Ingested request: {req_node.label} from {source}")
        return req_node
