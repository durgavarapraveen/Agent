from typing import List, Dict
from core.domain.request import CapturedRequest
import logging

logger = logging.getLogger(__name__)

class RequestInventory:
    def __init__(self):
        self.requests: Dict[str, CapturedRequest] = {}
        # Simple indices for fast lookup
        self.by_endpoint: Dict[str, List[str]] = {}
        self.by_identity: Dict[str, List[str]] = {}
        self.by_session: Dict[str, List[str]] = {}
        
    def add_captured_request(self, request: CapturedRequest, endpoint_id: str = None):
        req_id = request.request_id
        self.requests[req_id] = request
        
        if endpoint_id:
            self.by_endpoint.setdefault(endpoint_id, []).append(req_id)
            
        if request.identity_id:
            self.by_identity.setdefault(request.identity_id, []).append(req_id)
            
        if request.session_id:
            self.by_session.setdefault(request.session_id, []).append(req_id)
            
    def get_requests_for_endpoint(self, endpoint_id: str) -> List[CapturedRequest]:
        req_ids = self.by_endpoint.get(endpoint_id, [])
        return [self.requests[rid] for rid in req_ids if rid in self.requests]
        
    def get_requests_by_identity(self, identity_id: str) -> List[CapturedRequest]:
        req_ids = self.by_identity.get(identity_id, [])
        return [self.requests[rid] for rid in req_ids if rid in self.requests]
        
    def get_requests_by_session(self, session_id: str) -> List[CapturedRequest]:
        req_ids = self.by_session.get(session_id, [])
        return [self.requests[rid] for rid in req_ids if rid in self.requests]
        
    def get_all_requests(self) -> List[CapturedRequest]:
        return list(self.requests.values())
