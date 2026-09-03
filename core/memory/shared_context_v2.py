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
    def __init__(self, target: str = None, scope: Dict = None):
        # Tracks keys added dynamically via update() (OSINT/recon intelligence) so
        # they can be serialized and shared. Set first so update() can use it.
        self._dynamic_keys: set = set()
        self.target = target
        self.scope = scope or {}
        self.endpoints: Dict[str, Endpoint] = {}
        self.identities: Dict[str, Identity] = {}
        self.sessions: Dict[str, Session] = {}
        self.coverage_state: Optional[CoverageStateV2] = None
        
        # Backward compatibility with V1
        self.subdomains: List[str] = []
        self.ports: List[Dict] = []
        self.agents_spawned: List[str] = []
        self.vulnerabilities: List[Dict] = []
        self.ips: List[str] = []
        self.technologies: Dict[str, Any] = {}
        self.directories: List[str] = []
        self.headers: Dict[str, Any] = {}
        self.ssl_info: Dict[str, Any] = {}
        self.secrets: List[Dict] = []
        self.crawled_pages: List[str] = []
        self.captured_requests: List[Dict] = []
        self.js_files: List[str] = []
        self.brain_log: List[str] = []
        self.exploit_results: List[Dict] = []
        self.exploit_plan: Dict[str, Any] = {}
        self.attack_chains: List[Dict] = []
        self.privesc_findings: List[Dict] = []
        self.harvested_creds: List[Dict] = []
        self.lateral_plan: Dict[str, Any] = {}
        self.persistence_plan: Dict[str, Any] = {}
        self.mitre_mappings: List[Dict] = []
        self.has_shell_access: bool = False
        self.has_run_data_extraction: bool = False

        self.target_summary = {
            "tech_stack": [],
            "auth_types": []
        }
        self.execution_mode = "safe"
        
    def get_full_summary(self, max_chars: int = 0) -> Dict[str, Any]:
        summary = {
            "target": self.target,
            "endpoints_count": len(self.endpoints),
            "subdomains_count": len(self.subdomains),
            "vulnerabilities_count": len(self.vulnerabilities),
            "target_summary": self.target_summary
        }
        if max_chars > 0:
            text = json.dumps(summary)
            if len(text) > max_chars:
                summary.pop("target_summary", None)
        return summary
        
    def log_agent(self, agent_id: str, objective: str = None, status: str = None, result_summary: str = None):
        if agent_id not in self.agents_spawned:
            self.agents_spawned.append(agent_id)
        if objective or status:
            self.brain_log.append(f"[agent] {agent_id}: {objective or ''} -> {status or ''}")

    def log_brain(self, msg: str, event_type: str = "brain"):
        self.brain_log.append(f"[{event_type}] {msg}")

    def add_vulnerability(self, vuln: Dict):
        title = (vuln.get("title") or "").lower()
        vtype = (vuln.get("type") or "").upper()
        location = (vuln.get("location") or vuln.get("target") or "").lower()

        for existing in self.vulnerabilities:
            e_title = (existing.get("title") or "").lower()
            e_type = (existing.get("type") or "").upper()
            e_loc = (existing.get("location") or existing.get("target") or "").lower()
            if e_title == title and e_type == vtype and e_loc == location:
                return

        # Conflict resolution: don't add "Missing X header" if we already know the header is present
        if vtype == "MISSING_HEADER" and "missing" in title:
            header_name = title.replace("missing ", "").replace(" header", "").strip().lower()
            for existing in self.vulnerabilities:
                e_title = (existing.get("title") or "").lower()
                if header_name in e_title and "present" in e_title:
                    return

        self.vulnerabilities.append(vuln)

    def add_subdomains(self, subs: List[str], source: str = None):
        for s in subs:
            if s not in self.subdomains:
                self.subdomains.append(s)

    def get_subdomains(self) -> List[str]:
        return self.subdomains

    def add_endpoints(self, eps: List, source: str = None):
        for ep in eps:
            if isinstance(ep, str):
                eid = ep
            elif isinstance(ep, dict):
                eid = f"{ep.get('method', 'GET')}:{ep.get('url', '')}"
            else:
                eid = getattr(ep, 'endpoint_id', str(ep))
            if eid not in self.endpoints:
                self.endpoints[eid] = ep

    def get_endpoints(self) -> List:
        return list(self.endpoints.values())

    def add_ports(self, host_or_ports, ports: List[Dict] = None, source: str = None):
        if ports is None:
            actual_ports = host_or_ports
        else:
            actual_ports = ports
        for p in actual_ports:
            if isinstance(p, dict) and p not in self.ports:
                self.ports.append(p)
            elif not isinstance(p, dict):
                self.ports.append(p)

    def add_technologies(self, host: str, techs: List[str]):
        if host not in self.technologies:
            self.technologies[host] = []
        for t in techs:
            if t not in self.technologies[host]:
                self.technologies[host].append(t)
        # Auto-register host as subdomain if it belongs to target apex
        if host and hasattr(self, 'target') and self.target:
            apex = self.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
            apex = apex[4:] if apex.startswith("www.") else apex
            h = host.lower()
            if (h == apex or h.endswith("." + apex)) and h not in self.subdomains:
                self.subdomains.append(h)

    def get_technologies(self) -> Dict[str, Any]:
        return self.technologies

    def add_event(self, event: str, data: Any = None):
        self.brain_log.append(f"[event] {event}: {data}")

    def get(self, key: str, default=None):
        return getattr(self, key, default)

    def save(self, path: str):
        data = {
            "target": self.target,
            "scope": self.scope,
            "subdomains": self.subdomains,
            "ports": self.ports,
            "ips": self.ips,
            "vulnerabilities": self.vulnerabilities,
            "technologies": self.technologies,
            "endpoints": [str(e) for e in self.endpoints.keys()],
            "directories": self.directories,
            "headers": self.headers,
            "ssl_info": self.ssl_info,
            "secrets": self.secrets,
            "crawled_pages": self.crawled_pages,
            "captured_requests": self.captured_requests,
            "exploit_results": self.exploit_results,
            "attack_chains": self.attack_chains,
            "agents_spawned": self.agents_spawned,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def update(self, key: str, value: Any):
        # Store EVERY key so recon/OSINT data (employees, GitHub info, leaked creds,
        # cloud buckets, threat correlations, …) is never silently dropped — any agent
        # can then read it via ctx.get(key). Previously novel keys were discarded.
        if key == "target_profile" and isinstance(value, dict) and hasattr(self, "target_summary"):
            self.target_summary.update(value)
        existed = hasattr(self, key)
        setattr(self, key, value)
        if not existed and not key.startswith("_"):
            try:
                self._dynamic_keys.add(key)
            except AttributeError:
                self._dynamic_keys = {key}

    def dynamic_data(self) -> Dict[str, Any]:
        """Return everything added dynamically via update() (OSINT and other recon
        intelligence), so it can be serialized to the report/UI and shared."""
        keys = getattr(self, "_dynamic_keys", set())
        out = {}
        for k in keys:
            try:
                out[k] = getattr(self, k)
            except Exception:
                pass
        return out
        
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

    def get_context_for_agent(self, objective: str, context_keys: list = None) -> Dict[str, Any]:
        context = {"target": self.target, "objective": objective}
        keys = context_keys or []
        for key in keys:
            val = getattr(self, key, None)
            if val is not None:
                if isinstance(val, dict):
                    context[key] = dict(val)
                elif isinstance(val, list):
                    context[key] = list(val)
                else:
                    context[key] = val
        return context

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
