import json
import logging
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional
import re

logger = logging.getLogger(__name__)


class SharedContextV2:
    """Thread-safe shared memory, optimized for LLM Context Generation."""

    def __init__(self, target: str, scope: Dict = None):
        self.target = target
        self.scope = scope or {}
        self.created_at = datetime.now().isoformat()
        self._lock = threading.Lock()
        self.execution_mode = "autonomous"

        # ── Recon data ──
        self.subdomains: List[str] = []
        self.ips: List[str] = []
        self.ports: Dict[str, List[Dict]] = {}
        self.technologies: Dict[str, List[str]] = {}
        self.target_fingerprint: str = ""
        self.endpoints: List[Dict] = []
        self.parameters: List[Dict] = []
        self.identities: List[Dict] = []
        self.sessions: List[Dict] = []
        self.coverage_metrics: Dict = {}
        self.coverage_gaps: List[str] = []
        self.pending_tests: List[Dict] = []
        self.tool_capabilities: Dict = {}
        self.relevant_experiences: List[Dict] = []
        self.captured_requests: List[Dict] = []
        self.observations: List[Dict] = []
        self.vulnerabilities: List[Dict] = []
        self.failed_strategies: List[str] = []
        self.successful_strategies: List[str] = []

    def get_target_profile(self) -> Dict:
        with self._lock:
            return {
                "target": self.target,
                "scope": self.scope,
                "technologies": self.technologies,
                "target_fingerprint": self.target_fingerprint
            }

    def get_attack_surface(self) -> Dict:
        with self._lock:
            return {
                "subdomains": self.subdomains,
                "ips": self.ips,
                "ports": self.ports,
                "endpoints_count": len(self.endpoints)
            }

    def get_endpoint(self, endpoint_id: str) -> Optional[Dict]:
        with self._lock:
            for ep in self.endpoints:
                if ep.get("id") == endpoint_id or ep.get("url") == endpoint_id:
                    return ep
        return None

    def get_request(self, request_id: str) -> Optional[Dict]:
        with self._lock:
            for req in self.captured_requests:
                if req.get("id") == request_id:
                    return req
        return None

    def get_identity(self, identity_id: str) -> Optional[Dict]:
        with self._lock:
            for iden in self.identities:
                if iden.get("id") == identity_id:
                    return iden
        return None

    def get_session(self, session_id: str) -> Optional[Dict]:
        with self._lock:
            for sess in self.sessions:
                if sess.get("id") == session_id:
                    return sess
        return None

    def get_coverage(self) -> Dict:
        with self._lock:
            return {
                "metrics": self.coverage_metrics,
                "gaps": self.coverage_gaps
            }

    def get_pending_tests(self) -> List[Dict]:
        with self._lock:
            return self.pending_tests

    def get_relevant_experiences(self) -> List[Dict]:
        with self._lock:
            return self.relevant_experiences
            
    def get_tool_capabilities(self) -> Dict:
        with self._lock:
            return self.tool_capabilities

    def build_llm_context(self) -> Dict:
        """Constructs the optimized context block to feed to DeepSeek."""
        with self._lock:
            return {
                "target_profile": self.get_target_profile(),
                "attack_surface": self.get_attack_surface(),
                "coverage": self.get_coverage(),
                "pending_tests": self.get_pending_tests(),
                "experiences": self.get_relevant_experiences(),
                "capabilities": self.get_tool_capabilities(),
                "observations": self.observations,
                "vulnerabilities": self.vulnerabilities,
                "execution_mode": self.execution_mode,
                "parameters": self.parameters,
                "failed_strategies": self.failed_strategies,
                "successful_strategies": self.successful_strategies
            }
