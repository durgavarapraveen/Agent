import re
import uuid
import logging
from typing import List, Dict
from urllib.parse import urlparse
from core.domain.endpoint import Endpoint
from core.domain.request import CapturedRequest
from core.domain.identity import Identity
from core.extraction.parameter_extractor import ParameterExtractor

logger = logging.getLogger(__name__)

class EndpointExtractor:
    def __init__(self):
        self.param_extractor = ParameterExtractor()
        
    def extract(self, requests: List[CapturedRequest]) -> List[Endpoint]:
        endpoints_map: Dict[str, Endpoint] = {}
        
        for req in requests:
            # Normalize path
            parsed = urlparse(req.url)
            path = parsed.path if parsed.path else "/"
            
            # Very basic version collapsing (e.g. /v1/users -> /users)
            path = re.sub(r'/v[0-9]+/', '/', path)
            
            # Collapse numeric IDs to {id}
            path = re.sub(r'/[0-9]+(?:/|$)', '/{id}/', path).rstrip('/')
            if not path:
                path = "/"
                
            sim_key = f"{path}"
            
            if sim_key not in endpoints_map:
                ep = Endpoint(
                    endpoint_id=str(uuid.uuid4()),
                    path=path,
                    url=f"{parsed.scheme}://{parsed.netloc}{path}",
                    method_set=[req.method],
                    discovered_endpoints=0
                )
                endpoints_map[sim_key] = ep
            else:
                ep = endpoints_map[sim_key]
                if req.method not in ep.method_set:
                    ep.method_set.append(req.method)
            
            # Extract params
            params = self.param_extractor.extract_from_request(req)
            existing_param_names = {p.name for p in ep.parameters}
            for p in params:
                if p.name not in existing_param_names:
                    ep.parameters.append(p)
                    existing_param_names.add(p.name)
                    
            # Auth context inference
            if "Authorization" in req.full_headers or "authorization" in req.full_headers:
                ep.auth_required = True
                if req.identity_id and req.identity_id != "anonymous":
                    auth_ctx = Identity(
                        identity_id=req.identity_id,
                        label=req.identity_id,
                        username_reference="extracted"
                    )
                    
                    # Dedupe contexts
                    if not any(a.identity_id == req.identity_id for a in ep.auth_contexts):
                        ep.auth_contexts.append(auth_ctx)
                        
            # Confidence logic
            ep.discovered_endpoints += 1
            ep.confidence = self.calculate_confidence(ep.discovered_endpoints)
            
        return list(endpoints_map.values())
        
    def calculate_confidence(self, observation_count: int) -> float:
        # 1 observation = 0.5, 10+ = 1.0
        return min(1.0, 0.5 + (observation_count * 0.05))
