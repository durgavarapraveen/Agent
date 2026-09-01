from typing import List, Dict, Set
from core.domain.endpoint import Endpoint
from core.domain.request import CapturedRequest
from core.domain.parameter import Parameter
from core.domain.asset import Workflow, Page, DataObject
from core.attack_surface.endpoint_inventory import EndpointInventory
from core.attack_surface.request_inventory import RequestInventory
from core.attack_surface.parameter_inventory import ParameterInventory
from core.attack_surface.object_inventory import ObjectInventory
from core.attack_surface.workflow_inventory import WorkflowInventory
import logging

logger = logging.getLogger(__name__)

class AttackSurfaceGraph:
    def __init__(self):
        self.endpoints = EndpointInventory()
        self.requests = RequestInventory()
        self.parameters = ParameterInventory()
        self.objects = ObjectInventory()
        self.workflows = WorkflowInventory()
        
        # Pages for the PAGE -> CALLS -> ENDPOINT relationships
        self.pages: Dict[str, Page] = {}
        # Tracking edge metrics
        self.edges_count = 0
        
    def add_endpoint(self, endpoint: Endpoint):
        self.endpoints.add_endpoint(endpoint)
        
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
        self.edges_count += 1 # PAGE -> CALLS -> ENDPOINT
        
    def build_graph(self):
        # Output summary metrics
        ep_list = self.endpoints.get_endpoints()
        req_list = self.requests.get_all_requests()
        wf_list = list(self.workflows.workflows.values())
        param_map = self.parameters.by_type
        total_params = sum(len(plist) for plist in param_map.values())
        
        api_requests = [r for r in req_list if hasattr(r, 'endpoint_id') and r.endpoint_id]
        
        logger.info(f"ATTACK_SURFACE_GRAPH_BUILT pages={len(self.pages)} requests={len(req_list)} api_requests={len(api_requests)} endpoints={len(ep_list)} parameters={total_params} workflows={len(wf_list)} graph_edges={self.edges_count}")
        print(f"ATTACK_SURFACE_GRAPH_BUILT pages={len(self.pages)} requests={len(req_list)} api_requests={len(api_requests)} endpoints={len(ep_list)} parameters={total_params} workflows={len(wf_list)} graph_edges={self.edges_count}")
        
    # --- Queries ---
    def endpoints_for_identity(self, identity_id: str) -> List[Endpoint]:
        matched = []
        for ep in self.endpoints.get_endpoints():
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
        return self.endpoints.get_endpoints()
        
    def object_identifier_endpoints(self) -> List[Endpoint]:
        # Returns endpoints that contain DataObjects
        matched_eps = []
        for ep_id in self.objects.by_endpoint.keys():
            ep = self.endpoints.endpoints.get(ep_id)
            if ep:
                matched_eps.append(ep)
        return matched_eps
        
    def endpoints_requiring_auth(self) -> List[Endpoint]:
        matched = []
        for ep in self.endpoints.get_endpoints():
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
                    
        return [self.endpoints.endpoints[eid] for eid in matched_ids if eid in self.endpoints.endpoints]
