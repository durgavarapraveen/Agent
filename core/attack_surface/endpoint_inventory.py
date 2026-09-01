import logging
from typing import List, Dict
from core.domain.endpoint import Endpoint

logger = logging.getLogger(__name__)

class EndpointInventory:
    def __init__(self):
        self.endpoints: Dict[str, Endpoint] = {}
        
    def add_endpoint(self, endpoint: Endpoint):
        self.endpoints[endpoint.endpoint_id] = endpoint
        logger.info(f"ENDPOINT_MODEL_CREATED endpoint_id={endpoint.endpoint_id} normalized_path={endpoint.path}")
        print(f"ENDPOINT_MODEL_CREATED endpoint_id={endpoint.endpoint_id} normalized_path={endpoint.path}")
        
    def get_endpoints(self) -> List[Endpoint]:
        return list(self.endpoints.values())
        
    def merge_similar_endpoints(self, threshold: float = 0.9) -> List[Endpoint]:
        """
        Merges endpoints with same method + path pattern + parameters.
        For simplicity in this implementation, we will merge endpoints that have
        exact same path and HTTP methods, combining their parameters.
        """
        merged_map: Dict[str, Endpoint] = {}
        
        for ep in self.endpoints.values():
            # A simplistic similarity key: path + sorted methods
            methods_str = "-".join(sorted(ep.method_set))
            sim_key = f"{methods_str}:{ep.path}"
            
            if sim_key in merged_map:
                existing = merged_map[sim_key]
                # Merge parameters (avoid duplicates by name)
                existing_param_names = {p.name for p in existing.parameters}
                for p in ep.parameters:
                    if p.name not in existing_param_names:
                        existing.parameters.append(p)
                        existing_param_names.add(p.name)
                        
                # Merge auth contexts
                existing_auth_ids = {a.identity_id for a in existing.auth_contexts}
                for a in ep.auth_contexts:
                    if a.identity_id not in existing_auth_ids:
                        existing.auth_contexts.append(a)
                        existing_auth_ids.add(a.identity_id)
                        
                existing.discovered_endpoints += ep.discovered_endpoints
            else:
                merged_map[sim_key] = ep
                
        # Overwrite internal state with merged
        self.endpoints = {ep.endpoint_id: ep for ep in merged_map.values()}
        return self.get_endpoints()
        
    def deduplicate(self) -> List[Endpoint]:
        return self.merge_similar_endpoints(threshold=1.0)
