import json
from typing import Dict, List, Optional, Any
import logging
from core.domain.endpoint import Endpoint
from core.domain.identity import Identity
from core.domain.session import Session
from core.coverage.coverage_state import CoverageStateV2

logger = logging.getLogger(__name__)

class SharedContextV2:
    """
    Central memory and state orchestrator for Pentest V2.
    """
    def __init__(self):
        self.endpoints: Dict[str, Endpoint] = {}
        self.identities: Dict[str, Identity] = {}
        self.sessions: Dict[str, Session] = {}
        self.coverage_state: Optional[CoverageStateV2] = None
        
        self.target_summary = {
            "tech_stack": [],
            "auth_types": []
        }
        self.execution_mode = "safe"
        
    def get_endpoint(self, endpoint_id: str) -> Optional[Endpoint]:
        return self.endpoints.get(endpoint_id)
        
    def get_identity(self, identity_id: str) -> Optional[Identity]:
        return self.identities.get(identity_id)
        
    def get_session(self, session_id: str) -> Optional[Session]:
        return self.sessions.get(session_id)
        
    def get_coverage(self) -> Optional[CoverageStateV2]:
        return self.coverage_state
        
    def get_pending_tests(self) -> List[str]:
        if not self.coverage_state:
            return []
        pending = []
        for test_id, run_state in self.coverage_state.coverage_map.items():
            if run_state.status.value in ["NOT_TESTED", "READY", "INCONCLUSIVE"]:
                pending.append(test_id)
        return pending

    def build_llm_context(self, task: str, params: Dict[str, Any], memory_retriever=None, tool_learning=None) -> Dict[str, Any]:
        """
        Builds a structured prompt context specifically bounded by limits.
        NEVER includes raw logs.
        """
        context = {
            "task": task,
            "target_summary": self.target_summary,
            "execution_mode": self.execution_mode
        }
        
        # Attack surface slice
        if "endpoint_id" in params:
            ep = self.get_endpoint(params["endpoint_id"])
            if ep:
                context["attack_surface_slice"] = {
                    "path": ep.path,
                    "methods": ep.method_set,
                    "parameters": [p.name for p in ep.parameters],
                    "auth_required": ep.auth_required
                }
                
        # Identities context
        context["current_identities"] = [
            {"id": ident.identity_id, "role": ident.role.value, "auth_state": ident.authentication_state.value}
            for ident in self.identities.values()
        ]
        
        # Coverage status
        if self.coverage_state:
            stats = {}
            for t_id, run_state in self.coverage_state.coverage_map.items():
                stats[t_id] = run_state.status.value
            context["coverage_state"] = stats
            
        # Relevant memory and Tools (if engines provided)
        if memory_retriever and "test_id" in params:
            # We will fetch up to 3 relevant experiences to keep context small
            experiences = memory_retriever.retrieve_relevant_experiences(params.get("endpoint_id"), params["test_id"])
            context["relevant_memory"] = [{"strategy": e["strategy_id"], "outcome": e["outcome"]} for e in experiences[:3]]
            
        if tool_learning:
            # Simplified tool capabilities
            context["available_tools"] = [
                {"tool": name, "score": score} for name, score in tool_learning.get_top_tools(params.get("test_id", "all")).items()
            ]
            
        # Log to simulate ContextBuilder size tracking
        context_str = json.dumps(context)
        token_estimate = len(context_str) // 4
        logger.info(f"LLM_CONTEXT_BUILT endpoints={len(self.endpoints)} identities={len(self.identities)} token_estimate={token_estimate}")
        print(f"LLM_CONTEXT_BUILT endpoints={len(self.endpoints)} identities={len(self.identities)} token_estimate={token_estimate}")
        
        return context
