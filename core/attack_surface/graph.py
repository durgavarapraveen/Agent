from typing import List, Dict, Set
from core.domain.endpoint import Endpoint
from core.domain.request import CapturedRequest
from core.domain.parameter import Parameter
from core.domain.asset import Workflow, Page, DataObject
from core.attack_surface.request_inventory import RequestInventory
from core.attack_surface.parameter_inventory import ParameterInventory
from core.attack_surface.object_inventory import ObjectInventory
from core.attack_surface.workflow_inventory import WorkflowInventory
import logging

logger = logging.getLogger(__name__)

class AttackSurfaceGraph:
    def __init__(self):
        self.endpoints: Dict[str, Endpoint] = {}
        self.requests = RequestInventory()
        self.parameters = ParameterInventory()
        self.objects = ObjectInventory()
        self.workflows = WorkflowInventory()
        
        # Pages for the PAGE -> CALLS -> ENDPOINT relationships
        self.pages: Dict[str, Page] = {}
        # Tracking edge metrics
        self.edges_count = 0
        
    def add_endpoint(self, endpoint: Endpoint):
        # P3: key by the ONE canonical identity so the graph's endpoint set cannot
        # diverge from AttackSurfaceState, which assigns the same canonical id.
        # Only override a missing or uuid4-style id (keep stable assigned ids).
        try:
            eid = getattr(endpoint, "endpoint_id", "") or ""
            if (not eid) or (len(eid) == 36 and eid.count("-") == 4):
                endpoint.endpoint_id = endpoint.canonical_id()
        except Exception:
            pass
        self.endpoints[endpoint.endpoint_id] = endpoint
        
    def add_request(self, request: CapturedRequest):
        # We need a way to map request to endpoint. 
        # For this prototype, we'll assume the request has `endpoint_id` set, 
        # or we find it by matching path + method.
        # In this simplistic graph builder, we assume endpoint_id is mapped before insertion.
        ep_id = getattr(request, 'endpoint_id', None)
        self.requests.add_captured_request(request, endpoint_id=ep_id)
        if ep_id:
            self.edges_count += 1 # ENDPOINT -> ACCEPTS -> REQUEST (reverse mapping conceptually)
            
        if request.session_id:
            self.edges_count += 1 # REQUEST -> USES -> SESSION
            
        if request.identity_id:
            self.edges_count += 1 # SESSION -> BELONGS_TO -> IDENTITY (implied by request having identity)
            
    def add_parameter(self, endpoint_id: str, param: Parameter):
        self.parameters.add_parameter(endpoint_id, param)
        self.edges_count += 1 # ENDPOINT -> ACCEPTS -> PARAMETER
        
    def add_workflow(self, workflow: Workflow):
        self.workflows.add_workflow(workflow)
        for req_id in workflow.request_ids:
            self.edges_count += 1 # WORKFLOW -> CONTAINS -> REQUEST
            
    def add_page_call(self, page_url: str, endpoint_id: str):
        if page_url not in self.pages:
            self.pages[page_url] = Page(url=page_url)
        # Store the actual page→endpoint edge. Previously only the counter
        # incremented, so `pages_calling_endpoint()` returned nothing useful
        # even when the caller wired up dozens of edges (#145).
        if not hasattr(self, "_page_endpoint_edges"):
            self._page_endpoint_edges: Dict[str, set] = {}
        self._page_endpoint_edges.setdefault(page_url, set()).add(endpoint_id)
        self.edges_count += 1  # PAGE -> CALLS -> ENDPOINT

    def pages_calling_endpoint(self, endpoint_id: str) -> List[str]:
        edges = getattr(self, "_page_endpoint_edges", {}) or {}
        return [page for page, eps in edges.items() if endpoint_id in eps]

    def endpoints_called_by_page(self, page_url: str) -> List[str]:
        edges = getattr(self, "_page_endpoint_edges", {}) or {}
        return list(edges.get(page_url, set()))

    def build_graph(self):
        # Output summary metrics
        ep_list = list(self.endpoints.values())
        req_list = self.requests.get_all_requests()
        wf_list = list(self.workflows.workflows.values())
        param_map = self.parameters.by_type
        total_params = sum(len(plist) for plist in param_map.values())

        api_requests = [r for r in req_list if hasattr(r, 'endpoint_id') and r.endpoint_id]

        # Log-only — the parallel `print()` was noise duplicating what already
        # went to the logger and broke JSON log ingest.
        logger.info(
            "ATTACK_SURFACE_GRAPH_BUILT pages=%d requests=%d api_requests=%d "
            "endpoints=%d parameters=%d workflows=%d graph_edges=%d",
            len(self.pages), len(req_list), len(api_requests),
            len(ep_list), total_params, len(wf_list), self.edges_count,
        )
        
    # --- Queries ---
    def endpoints_for_identity(self, identity_id: str) -> List[Endpoint]:
        matched = []
        for ep in self.endpoints.values():
            for auth in ep.auth_contexts:
                if auth.identity_id == identity_id:
                    matched.append(ep)
                    break
        return matched
        
    def parameters_for_endpoint(self, endpoint_id: str) -> List[Parameter]:
        return self.parameters.get_parameters_for_endpoint(endpoint_id)
        
    def requests_for_endpoint(self, endpoint_id: str) -> List[CapturedRequest]:
        return self.requests.get_requests_for_endpoint(endpoint_id)
        
    def workflows_for_identity(self, identity_id: str) -> List[Workflow]:
        # A workflow is tied to an identity if any of its requests are tied to that identity.
        matched_workflows = []
        for wf in self.workflows.workflows.values():
            tied = False
            for req_id in wf.request_ids:
                req = self.requests.requests.get(req_id)
                if req and req.identity_id == identity_id:
                    tied = True
                    break
            if tied:
                matched_workflows.append(wf)
        return matched_workflows
        
    def api_endpoints(self) -> List[Endpoint]:
        # Assume API endpoints have specific content-types or paths, 
        # or we just return all endpoints if they represent backend calls.
        return list(self.endpoints.values())
        
    def object_identifier_endpoints(self) -> List[Endpoint]:
        # Returns endpoints that contain DataObjects
        matched_eps = []
        for ep_id in self.objects.by_endpoint.keys():
            ep = self.endpoints.get(ep_id)
            if ep:
                matched_eps.append(ep)
        return matched_eps
        
    def endpoints_requiring_auth(self) -> List[Endpoint]:
        matched = []
        for ep in self.endpoints.values():
            if ep.auth_required:
                matched.append(ep)
        return matched
        
    def endpoints_by_parameter_type(self, param_type: str) -> List[Endpoint]:
        matched_ids = set()
        params = self.parameters.by_type.get(param_type, [])
        # We need to map param back to endpoint.
        for ep_id, plist in self.parameters.by_endpoint.items():
            for p in plist:
                if p.parameter_type.value == param_type:
                    matched_ids.add(ep_id)

        return [self.endpoints[eid] for eid in matched_ids if eid in self.endpoints]

    def sync_from_endpoint_inventory(self, inventory) -> int:
        from core.domain.endpoint import Endpoint
        added = 0
        for ep_data in inventory.list_endpoints():
            ep_id = ep_data.get("endpoint_id", "")
            if ep_id not in self.endpoints:
                try:
                    ep = Endpoint(
                        endpoint_id=ep_id,
                        path=ep_data.get("url", ep_data.get("path", "")),
                        method_set=ep_data.get("methods", [ep_data.get("method", "GET")]),
                    )
                    self.endpoints[ep_id] = ep
                    added += 1
                except Exception as e:
                    # Previously silently swallowed. Log the count of malformed
                    # rows and a preview so operators can diagnose data-drift
                    # between inventories rather than losing data invisibly.
                    self._skipped_endpoint_syncs = getattr(
                        self, "_skipped_endpoint_syncs", 0) + 1
                    if self._skipped_endpoint_syncs <= 5:
                        logger.warning(
                            "sync_from_endpoint_inventory: malformed endpoint "
                            "row skipped: %s (ep_id=%r)", e, ep_id,
                        )
        if getattr(self, "_skipped_endpoint_syncs", 0) > 5:
            logger.warning(
                "sync_from_endpoint_inventory: %d total malformed rows skipped "
                "(further messages suppressed)",
                self._skipped_endpoint_syncs,
            )
        return added
