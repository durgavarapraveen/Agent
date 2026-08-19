from typing import List, Optional, Set
from urllib.parse import urlparse
import ipaddress
import logging

from core.exceptions import ScopeViolationException

logger = logging.getLogger(__name__)

class ScopeManager:
    """Manages authorized scope for security operations."""
    
    def __init__(self, allowed_domains: List[str] = None, allowed_ips: List[str] = None,
                 allowed_urls: List[str] = None, allowed_paths: List[str] = None,
                 execution_mode: str = "PASSIVE"):
        self.allowed_domains: Set[str] = self._normalize_domains(allowed_domains or [])
        self.allowed_ips: List[str] = allowed_ips or []
        self.allowed_urls: Set[str] = set(allowed_urls or [])
        self.allowed_paths: Set[str] = set(allowed_paths or [])
        self.execution_mode = execution_mode  # PASSIVE, SAFE_ACTIVE, FULL_AUTHORIZED
        self.dangerous_operations = {
            "delete_file",
            "write_file",
            "execute_command",
            "modify_system",
            "credential_theft",
            "persistence",
            "destroy_data"
        }
    
    def _normalize_domains(self, domains: List[str]) -> Set[str]:
        """Normalize domain patterns."""
        normalized = set()
        for domain in domains:
            domain = domain.lower()
            if domain.startswith("*."):
                normalized.add(domain[2:])  # Store without wildcard
            else:
                normalized.add(domain)
        return normalized
    
    def _is_domain_allowed(self, domain: str) -> bool:
        """Check if a domain is in allowed scope."""
        domain = domain.lower()
        
        for allowed in self.allowed_domains:
            if allowed.startswith("."):
                # Subdomain wildcard
                if domain.endswith(allowed) or domain == allowed[1:]:
                    return True
            elif domain == allowed:
                return True
            elif domain.endswith("." + allowed):
                return True
        
        return False
    
    def _is_ip_allowed(self, ip: str) -> bool:
        """Check if an IP is in allowed scope."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            for allowed_range in self.allowed_ips:
                try:
                    network = ipaddress.ip_network(allowed_range, strict=False)
                    if ip_obj in network:
                        return True
                except:
                    pass
            
            return False
        except:
            return False
    
    def _is_path_allowed(self, path: str) -> bool:
        """Check if a local path is in allowed scope."""
        for allowed_path in self.allowed_paths:
            if path.startswith(allowed_path):
                return True
        return False
    
    def validate_url(self, url: str) -> bool:
        """Validate that a URL is in authorized scope."""
        if url in self.allowed_urls:
            return True
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ":" in domain:
                domain = domain.split(":")[0]
            
            return self._is_domain_allowed(domain)
        except:
            logger.warning(f"Could not parse URL: {url}")
            return False
    
    def validate_ip(self, ip: str) -> bool:
        """Validate that an IP is in authorized scope."""
        return self._is_ip_allowed(ip)
    
    def validate_path(self, path: str) -> bool:
        """Validate that a local path is in authorized scope."""
        return self._is_path_allowed(path)
    
    def validate_tool_execution(self, tool_name: str, target: str) -> bool:
        """Validate tool execution is authorized."""
        # Check if target (URL or path) is in scope
        if target.startswith("http"):
            if not self.validate_url(target):
                raise ScopeViolationException(f"Target URL not in authorized scope: {target}")
        elif target.startswith("/"):
            if not self.validate_path(target):
                raise ScopeViolationException(f"Target path not in authorized scope: {target}")
        
        # Check execution mode restrictions
        if self.execution_mode == "PASSIVE":
            passive_tools = {
                "nmap", "httpx", "whatweb", "nuclei", "dnsenum", "whois",
                "curl", "wget", "dig", "nslookup"
            }
            if tool_name not in passive_tools and not tool_name.startswith("query_"):
                raise ScopeViolationException(
                    f"Tool {tool_name} not allowed in PASSIVE mode. Use SAFE_ACTIVE or FULL_AUTHORIZED."
                )
        
        # Explicitly block dangerous operations
        if tool_name in self.dangerous_operations:
            raise ScopeViolationException(f"Dangerous operation not authorized: {tool_name}")
        
        return True
    
    def can_expand_scope(self, new_domain: str, new_ip: str = None) -> bool:
        """Determine if scope can be expanded (requires user approval)."""
        # The central agent may propose scope expansion
        # But it must be explicitly approved by the user
        logger.info(f"Scope expansion requested: domain={new_domain}, ip={new_ip}")
        return False  # Default: require explicit approval
    
    def get_scope_summary(self) -> dict:
        """Get a summary of current scope."""
        return {
            "allowed_domains": sorted(list(self.allowed_domains)),
            "allowed_ips": self.allowed_ips,
            "allowed_urls": sorted(list(self.allowed_urls)),
            "allowed_paths": sorted(list(self.allowed_paths)),
            "execution_mode": self.execution_mode
        }
