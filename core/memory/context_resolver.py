"""
Context resolver - resolve semantic context requirements.
Agents request context semantically, framework resolves from knowledge store.
"""

import logging
from typing import Dict, List, Any, Optional
from core.stores import KnowledgeStore

logger = logging.getLogger(__name__)


class ContextResolver:
    """Resolve execution context from knowledge store"""
    
    def __init__(self, knowledge_store: KnowledgeStore):
        self.knowledge = knowledge_store
    
    def resolve_hosts(self, authorized_scope: List[str]) -> List[Dict[str, Any]]:
        """Get all known hosts within authorized scope"""
        hosts = self.knowledge.get_by_type("host")
        
        # Filter to authorized scope
        authorized_hosts = [
            h for h in hosts
            if any(self._is_in_scope(h.entity_value, scope) for scope in authorized_scope)
        ]
        
        return [
            {
                "host": h.entity_value,
                "confidence": h.confidence,
                "source": h.source,
                "attributes": h.attributes,
            }
            for h in authorized_hosts
        ]
    
    def resolve_ports(self, host: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get known ports"""
        ports = self.knowledge.get_by_type("port")
        
        if host:
            ports = [p for p in ports if host in str(p.attributes)]
        
        return [
            {
                "port": p.entity_value,
                "service": p.attributes.get("service"),
                "confidence": p.confidence,
                "source": p.source,
            }
            for p in ports
        ]
    
    def resolve_services(self, host: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get identified services"""
        services = self.knowledge.get_by_type("service")
        
        if host:
            services = [s for s in services if host in str(s.attributes)]
        
        return [
            {
                "service": s.entity_value,
                "version": s.version,
                "confidence": s.confidence,
                "source": s.source,
            }
            for s in services
        ]
    
    def resolve_technologies(self, endpoint: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get identified technologies"""
        techs = self.knowledge.get_by_type("technology")
        
        if endpoint:
            techs = [t for t in techs if endpoint in str(t.attributes)]
        
        return [
            {
                "technology": t.entity_value,
                "version": t.version,
                "confidence": t.confidence,
                "source": t.source,
            }
            for t in techs
        ]
    
    def resolve_tls_info(self, endpoint: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get TLS certificate information"""
        certs = self.knowledge.get_by_type("tls_cert")
        
        if endpoint:
            certs = [c for c in certs if endpoint in str(c.entity_value)]
        
        return [
            {
                "endpoint": c.entity_value,
                "cn": c.attributes.get("cn"),
                "confidence": c.confidence,
                "source": c.source,
            }
            for c in certs
        ]
    
    def resolve_endpoints(self) -> List[Dict[str, Any]]:
        """Get known HTTP endpoints"""
        endpoints = self.knowledge.get_by_type("http_endpoint")
        
        return [
            {
                "endpoint": e.entity_value,
                "status_code": e.attributes.get("status_code"),
                "server": e.attributes.get("server"),
                "confidence": e.confidence,
                "source": e.source,
            }
            for e in endpoints
        ]
    
    def resolve_context(self, context_requirements: List[str], 
                       authorized_scope: List[str]) -> Dict[str, Any]:
        """
        Resolve multiple context requirements.
        Called by scheduler to prepare context for agent.
        """
        context = {}
        
        for req in context_requirements:
            if req == "hosts":
                context["hosts"] = self.resolve_hosts(authorized_scope)
            elif req == "ports":
                context["ports"] = self.resolve_ports()
            elif req == "services":
                context["services"] = self.resolve_services()
            elif req == "technologies":
                context["technologies"] = self.resolve_technologies()
            elif req == "tls_info":
                context["tls_info"] = self.resolve_tls_info()
            elif req == "endpoints":
                context["endpoints"] = self.resolve_endpoints()
            elif req == "knowledge_summary":
                context["knowledge_summary"] = self.knowledge.summarize()
            else:
                logger.warning(f"[ContextResolver] Unknown context requirement: {req}")
        
        return context
    
    def _is_in_scope(self, target: str, allowed: str) -> bool:
        """Simple scope matching"""
        if allowed == "*":
            return True
        if target == allowed:
            return True
        if target.endswith("." + allowed):
            return True
        return False
    
    def get_context_summary(self) -> Dict[str, Any]:
        """Summary of available context"""
        return {
            "hosts_known": len(self.knowledge.get_by_type("host")),
            "ports_known": len(self.knowledge.get_by_type("port")),
            "services_known": len(self.knowledge.get_by_type("service")),
            "technologies_known": len(self.knowledge.get_by_type("technology")),
            "endpoints_known": len(self.knowledge.get_by_type("http_endpoint")),
        }