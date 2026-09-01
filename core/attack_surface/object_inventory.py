import logging
from typing import Dict, Any, List
from core.attack_surface.graph import AttackSurfaceGraph, CanonicalNode, CanonicalObject, NodeType, EdgeType

logger = logging.getLogger(__name__)


class ObjectInventory:
    """Manages OBJECT nodes in the graph."""

    def __init__(self, graph: AttackSurfaceGraph):
        self.graph = graph
        self._object_cache = {}

    def ingest_objects(self, endpoint_node: CanonicalNode, returned_objects: List[Dict[str, Any]]):
        """
        Creates OBJECT nodes and links them to the ENDPOINT via RETURNS.
        returned_objects: [{"object_type": "User", "fields": ["id", "name"]}]
        """
        for obj_data in returned_objects:
            obj_type = obj_data.get("object_type", "unknown")
            
            cache_key = f"obj::{obj_type}"
            
            if cache_key in self._object_cache:
                obj_node_id = self._object_cache[cache_key]
            else:
                obj_node = CanonicalObject(
                    label=obj_type,
                    object_type=obj_type,
                    fields=obj_data.get("fields", [])
                )
                self.graph.add_node(obj_node)
                self._object_cache[cache_key] = obj_node.id
                obj_node_id = obj_node.id
                logger.debug(f"Ingested object: {obj_type}")
            
            # ENDPOINT -> RETURNS -> OBJECT
            self.graph.add_edge(endpoint_node.id, obj_node_id, EdgeType.RETURNS)
