from typing import List, Set
from urllib.parse import urlparse
import ipaddress
import logging

from core.common.exceptions import ScopeViolationException

logger = logging.getLogger(__name__)

class ScopeManager:
    
    def __init__(self, allowed_domains: List[str] = None, allowed_ips: List[str] = None,
                 allowed_urls: List[str] = None, allowed_paths: List[str] = None,
                 execution_mode: str = "PASSIVE"):
        self.allowed_domains: Set[str] = self._normalize_domains(allowed_domains or [])
        self.allowed_ips: List[str] = allowed_ips or []
        self.allowed_urls: Set[str] = set(allowed_urls or [])
        self.allowed_paths: Set[str] = set(allowed_paths or [])
        self.execution_mode = execution_mode
        self.dangerous_operations = {
            "delete_file",
            "write_file",
            "execute_command",
            "modify_system",
            "credential_theft",
            "persistence",
            "destroy_data"
        }
    
    @staticmethod
    def _normalize_host(host: str) -> str:
        h = (host or "").strip().lower().rstrip(".")
        if h.startswith("[") and h.endswith("]"):
            h = h[1:-1]
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            # ASCII-only or malformed; leave as-is (validators below will reject).
            pass
        return h

    def _normalize_domains(self, domains: List[str]) -> Set[str]:
        normalized = set()
        for domain in domains:
            d = self._normalize_host(domain)
            if d.startswith("*."):
                normalized.add(d[2:])  # Store without wildcard
            else:
                normalized.add(d)
        return normalized

    def _is_domain_allowed(self, domain: str) -> bool:
        domain = self._normalize_host(domain)

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
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            # Not a valid IP literal — the caller should have routed this to
            # `_is_domain_allowed`. Log at debug so misrouting is diagnosable
            # but not noisy.
            logger.debug("_is_ip_allowed: %r is not a valid IP literal", ip)
            return False

        for allowed_range in self.allowed_ips:
            try:
                network = ipaddress.ip_network(allowed_range, strict=False)
                if ip_obj in network:
                    return True
            except ValueError as e:
                # A malformed range in configuration is a real bug — log at
                # warning so operators notice. Previously silently swallowed.
                logger.warning("Malformed CIDR in scope config: %r (%s)", allowed_range, e)

        return False
    
    def _is_path_allowed(self, path: str) -> bool:
        for allowed_path in self.allowed_paths:
            if path.startswith(allowed_path):
                return True
        return False
    
    def validate_url(self, url: str) -> bool:
        # Normalize the exact-URL fast path too — else trailing-slash /
        # fragment differences would defeat the shortcut.
        norm_url = url.strip()
        if norm_url in self.allowed_urls:
            return True

        try:
            parsed = urlparse(norm_url)
        except ValueError as e:
            logger.warning("Could not parse URL %r: %s", url, e)
            return False

        host = (parsed.hostname or "").strip()
        if not host:
            logger.debug("URL had no hostname: %r", url)
            return False

        # If the host is an IP literal, route to the IP allowlist. Otherwise
        # normalize and route to the domain allowlist.
        try:
            ipaddress.ip_address(host)
            return self._is_ip_allowed(host)
        except ValueError:
            return self._is_domain_allowed(self._normalize_host(host))
    
    def validate_ip(self, ip: str) -> bool:
        return self._is_ip_allowed(ip)
    
    def validate_path(self, path: str) -> bool:
        return self._is_path_allowed(path)
    
    def validate_tool_execution(self, tool_name: str, target: str) -> bool:
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
    
    def validate_plan(self, target: str, tool_name: str = "") -> str:
        if not target:
            return "PLAN_REJECTED_SCOPE: empty target"

        # Always route through urlparse — prepend a synthetic scheme when the
        # caller gave a bare host so the parser cooperates.
        candidate = target if "://" in target else "http://" + target
        try:
            parsed = urlparse(candidate)
        except ValueError as e:
            return f"PLAN_REJECTED_SCOPE: unparseable target {target!r}: {e}"

        host = (parsed.hostname or "").strip()
        if not host:
            return f"PLAN_REJECTED_SCOPE: no host in {target!r}"

        # Exact-URL allowlist first (only when the caller passed a full URL).
        if "://" in target and target.strip() in self.allowed_urls:
            return ""

        # IP literal → IP allowlist. Hostname → domain allowlist (normalized).
        try:
            ipaddress.ip_address(host)
            allowed = self._is_ip_allowed(host)
        except ValueError:
            allowed = self._is_domain_allowed(self._normalize_host(host))

        if not allowed:
            return f"PLAN_REJECTED_SCOPE: {target} not in authorized scope"
        return ""

    def can_expand_scope(self, new_domain: str, new_ip: str = None) -> bool:
        # The central agent may propose scope expansion
        # But it must be explicitly approved by the user
        logger.info(f"Scope expansion requested: domain={new_domain}, ip={new_ip}")
        return False  # Default: require explicit approval
    
    def get_scope_summary(self) -> dict:
        return {
            "allowed_domains": sorted(list(self.allowed_domains)),
            "allowed_ips": self.allowed_ips,
            "allowed_urls": sorted(list(self.allowed_urls)),
            "allowed_paths": sorted(list(self.allowed_paths)),
            "execution_mode": self.execution_mode
        }
