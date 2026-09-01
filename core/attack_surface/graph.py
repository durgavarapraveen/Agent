from enum import Enum
from typing import Dict, List, Set, Any, Optional
import uuid
import logging
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class NodeType(str, Enum):
    HOST = "HOST"
    APPLICATION = "APPLICATION"
    PAGE = "PAGE"
    ENDPOINT = "ENDPOINT"
    REQUEST = "REQUEST"
    PARAMETER = "PARAMETER"
    COOKIE = "COOKIE"
    TOKEN = "TOKEN"
    IDENTITY = "IDENTITY"
    ROLE = "ROLE"
    OBJECT = "OBJECT"
    WORKFLOW = "WORKFLOW"
    RESPONSE = "RESPONSE"
    FILE = "FILE"
    TECHNOLOGY = "TECHNOLOGY"

class EdgeType(str, Enum):
    CALLS = "CALLS"                  # PAGE -> CALLS -> ENDPOINT
    USES = "USES"                    # REQUEST -> USES -> SESSION/COOKIE
    BELONGS_TO = "BELONGS_TO"        # SESSION -> BELONGS_TO -> IDENTITY
    HAS_ROLE = "HAS_ROLE"            # IDENTITY -> HAS_ROLE -> ROLE
    ACCEPTS = "ACCEPTS"              # ENDPOINT -> ACCEPTS -> PARAMETER
    RETURNS = "RETURNS"              # ENDPOINT -> RETURNS -> OBJECT
    DISCOVERED_BY = "DISCOVERED_BY"  # REQUEST -> DISCOVERED_BY -> SOURCE
    CONTAINS = "CONTAINS"            # WORKFLOW -> CONTAINS -> REQUEST

# Canonical Typed Entities
class CanonicalNode(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    node_type: NodeType
    label: str

class CanonicalEndpoint(CanonicalNode):
    node_type: NodeType = NodeType.ENDPOINT
    method: str
    normalized_path: str
    raw_paths_seen: Set[str] = Field(default_factory=set)

class CanonicalRequest(CanonicalNode):
    node_type: NodeType = NodeType.REQUEST
    method: str
    url: str
    source: str
    is_api: bool = False

class CanonicalParameter(CanonicalNode):
    node_type: NodeType = NodeType.PARAMETER
    name: str
    param_type: str  # query, body, header, path
    
class CanonicalObject(CanonicalNode):
    node_type: NodeType = NodeType.OBJECT
    object_type: str
    fields: List[str] = Field(default_factory=list)

class CanonicalIdentity(CanonicalNode):
    node_type: NodeType = NodeType.IDENTITY
    role: str

class CanonicalWorkflow(CanonicalNode):
    node_type: NodeType = NodeType.WORKFLOW
    steps: int


class AttackSurfaceGraph:
    """Central Application Model representing the attack surface."""
    
    def __init__(self):
        self.nodes: Dict[str, CanonicalNode] = {}
        self.edges: Dict[str, Dict[EdgeType, Set[str]]] = {}
        logger.info("ATTACK_SURFACE_GRAPH_BUILT")
        
    def add_node(self, node: CanonicalNode) -> CanonicalNode:
        """Add a node to the graph."""
        self.nodes[node.id] = node
        if node.id not in self.edges:
            self.edges[node.id] = {}
        
        # Log specific models
        if isinstance(node, CanonicalEndpoint):
            logger.info(f"ENDPOINT_MODEL_CREATED: {node.label}")
        elif isinstance(node, CanonicalRequest):
            logger.info(f"REQUEST_MODEL_CREATED: {node.label}")
        elif isinstance(node, CanonicalParameter):
            logger.info(f"PARAMETER_MODEL_CREATED: {node.label}")
            
        return node
        
    def add_edge(self, source_id: str, target_id: str, edge_type: EdgeType):
        """Add a directed edge between two nodes."""
        if source_id not in self.nodes or target_id not in self.nodes:
            logger.warning(f"Attempted to link non-existent nodes: {source_id} -> {target_id}")
            return
            
        if edge_type not in self.edges[source_id]:
            self.edges[source_id][edge_type] = set()
            
        self.edges[source_id][edge_type].add(target_id)
        logger.info(f"GRAPH_RELATIONSHIP_CREATED: {source_id} -> {edge_type.value} -> {target_id}")
        
    def get_nodes_by_type(self, node_type: NodeType) -> List[CanonicalNode]:
        """Fetch all nodes of a specific type."""
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def get_related(self, source_id: str, edge_type: EdgeType) -> List[CanonicalNode]:
        """Get all nodes connected from a source node by a specific edge type."""
        if source_id not in self.edges or edge_type not in self.edges[source_id]:
            return []
        return [self.nodes[tid] for tid in self.edges[source_id][edge_type]]
        
    # Queries required by prompt
    def endpoints_for_identity(self, identity_id: str) -> List[CanonicalEndpoint]:
        # IDENTITY <- BELONGS_TO <- SESSION <- USES <- REQUEST -> CALLS -> ENDPOINT
        # Simplified: We map identities directly if needed, but assuming a direct trace:
        endpoints = set()
        # Find all requests using this identity's token/session
        for node in self.nodes.values():
            if isinstance(node, CanonicalRequest):
                targets = self.edges.get(node.id, {}).get(EdgeType.USES, set())
                # if target is a token that belongs to this identity...
                # (For now, simplified stub returning endpoints if linked directly)
                pass
        return list(endpoints)
        
    def parameters_for_endpoint(self, endpoint_id: str) -> List[CanonicalParameter]:
        return self.get_related(endpoint_id, EdgeType.ACCEPTS)
        
    def requests_for_endpoint(self, endpoint_id: str) -> List[CanonicalRequest]:
        # Find all requests where REQUEST -> CALLS -> ENDPOINT
        requests = []
        for src_id, edges in self.edges.items():
            if endpoint_id in edges.get(EdgeType.CALLS, set()):
                requests.append(self.nodes[src_id])
        return requests
        
    def workflows_for_identity(self, identity_id: str) -> List[CanonicalWorkflow]:
        # Workflows executed by an identity
        return []
        
    def get_apis(self) -> List[CanonicalEndpoint]:
        # Endpoints where associated requests have is_api=True
        api_endpoints_ids = set()
        for node in self.nodes.values():
            if isinstance(node, CanonicalRequest) and node.is_api:
                endpoints = self.get_related(node.id, EdgeType.CALLS)
                for ep in endpoints:
                    api_endpoints_ids.add(ep.id)
        return [self.nodes[eid] for eid in api_endpoints_ids]
        
    def object_identifier_endpoints(self) -> List[CanonicalEndpoint]:
        # Endpoints that have path parameters like {id}, {uuid}
        endpoints = []
        for ep in self.get_nodes_by_type(NodeType.ENDPOINT):
            if "{" in ep.normalized_path and "}" in ep.normalized_path:
                endpoints.append(ep)
        return endpoints

    def count_edges(self) -> int:
        count = 0
        for src, edges in self.edges.items():
            for targets in edges.values():
                count += len(targets)
        return count

    def print_summary(self):
        pages = len(self.get_nodes_by_type(NodeType.PAGE))
        requests = len(self.get_nodes_by_type(NodeType.REQUEST))
        api_requests = len([r for r in self.get_nodes_by_type(NodeType.REQUEST) if getattr(r, 'is_api', False)])
        endpoints = len(self.get_nodes_by_type(NodeType.ENDPOINT))
        parameters = len(self.get_nodes_by_type(NodeType.PARAMETER))
        workflows = len(self.get_nodes_by_type(NodeType.WORKFLOW))
        edges = self.count_edges()
        
        print("ATTACK_SURFACE_GRAPH")
        print(f"pages={pages}")
        print(f"requests={requests}")
        print(f"api_requests={api_requests}")
        print(f"endpoints={endpoints}")
        print(f"parameters={parameters}")
        print(f"workflows={workflows}")
        print(f"graph_edges={edges}")
