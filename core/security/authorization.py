"""
Centralized Target Scope Authorization validation layer.
"""

import re
import logging
from typing import List, Optional
from urllib.parse import urlparse
from core.common.exceptions import AuthorizationError

logger = logging.getLogger(__name__)


PASSIVE_OSINT_DOMAINS = frozenset({
    "crt.sh", "api.github.com", "github.com",
    "dns.google", "otx.alienvault.com", "shodan.io", "api.shodan.io",
    "urlscan.io", "web.archive.org", "archive.org",
    "rapiddns.io", "hackertarget.com", "threatcrowd.org",
    "api.certspotter.com", "censys.io", "search.censys.io",
    "securitytrails.com", "api.securitytrails.com",
    "virustotal.com", "www.virustotal.com",
    "api.hunter.io", "hunter.io",
    "haveibeenpwned.com", "api.pwnedpasswords.com",
})


class TargetScopeValidator:
    """Centralized target scope validator singleton"""

    _instance: Optional['TargetScopeValidator'] = None

    @classmethod
    def get(cls) -> 'TargetScopeValidator':
        if cls._instance is None:
            # Fallback default target if validator has not been set yet
            from core.common.config import get_config
            target = get_config().get("TARGET", "example.com")
            cls._instance = cls([target])
        return cls._instance

    @classmethod
    def set(cls, validator: 'TargetScopeValidator') -> None:
        cls._instance = validator

    def __init__(self, authorized_targets: List[str]):
        self.authorized_scope = [
            self._normalize_target(t) for t in authorized_targets if t
        ]
        # IPs that in-scope hosts (authorized domains and their subdomains) resolve
        # to. Populated automatically as ANY in-scope host is validated, so scanning
        # those IPs later is authorized — globally, without per-call-site wiring.
        self._authorized_ips: set = set()
        self._resolved_hosts: set = set()   # hosts we've already resolved (cache)
        logger.info(f"[TargetScopeValidator] Initialized with scope: {self.authorized_scope}")

    def note_resolution(self, host: str, ip: str = None) -> None:
        """
        Record that an in-scope host resolves to an IP, authorizing that IP.
        If the host is in authorized scope (an authorized domain or any of its
        subdomains), every IP it resolves to is added to the authorized set — so a
        follow-up scan of that IP is not blocked. Call this whenever recon resolves
        a host to an address.
        """
        try:
            host_norm = self._normalize_target(host)
            if not host_norm or not self._host_in_scope(host_norm):
                return
            ips = []
            if ip and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip.strip()):
                ips = [ip.strip()]
            else:
                if host_norm in self._resolved_hosts:
                    return  # already resolved this host — cheap cache guard
                self._resolved_hosts.add(host_norm)
                import socket
                try:
                    ips = list({ai[4][0] for ai in socket.getaddrinfo(host_norm, None)})
                except Exception:
                    ips = []
            for got in ips:
                if got not in self._authorized_ips:
                    self._authorized_ips.add(got)
                    logger.info(f"[TargetScopeValidator] Authorized IP {got} (resolved from in-scope host {host_norm})")
        except Exception:
            pass

    def _host_in_scope(self, norm: str) -> bool:
        """True if a (non-IP) hostname matches an authorized domain or subdomain."""
        for allowed in self.authorized_scope:
            allowed_norm = self._normalize_target(allowed)
            if allowed == "*" or norm == allowed_norm:
                return True
            if allowed_norm.startswith("*."):
                allowed_norm = allowed_norm[2:]
            if allowed_norm.startswith("www."):
                allowed_norm = allowed_norm[4:]
            if norm == allowed_norm or norm.endswith("." + allowed_norm):
                return True
        return False

    def _normalize_target(self, target: str) -> str:
        if not target:
            return ""
        target = target.strip()
        # Strip scheme if present
        if "://" in target:
            target = target.split("://", 1)[1]
        # Strip path
        if "/" in target:
            target = target.split("/", 1)[0]
        # Strip port
        if ":" in target:
            target = target.split(":", 1)[0]
        return target.lower()

    def add_target(self, target: str) -> None:
        norm = self._normalize_target(target)
        if norm and norm not in self.authorized_scope:
            self.authorized_scope.append(norm)
            logger.info(f"[TargetScopeValidator] Dynamically added to scope: {norm}")

    def is_authorized(self, target: str) -> bool:
        if not target:
            return False
        norm = self._normalize_target(target)
        if norm in PASSIVE_OSINT_DOMAINS:
            return True
        if any(self._normalize_target(a) == "*" or a == "*" for a in self.authorized_scope):
            return True

        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', norm))

        # Hostname: if it's an authorized domain or any subdomain thereof, authorize
        # it AND opportunistically cache the IPs it resolves to. Because every tool
        # invocation is validated through here, this makes IP-authorization global:
        # once the agent touches an in-scope host, that host's IPs are authorized for
        # any later scan — no per-discovery-site wiring needed.
        if not is_ip:
            if self._host_in_scope(norm):
                self.note_resolution(norm)
                return True
            return False

        # Check if target is an IP address belonging to an in-scope domain.
        if True:
            # 1. Already recorded as an in-scope host's resolved IP.
            if norm in self._authorized_ips:
                return True
            # 2. Resolve every authorized domain (ALL A-records, not just the first)
            #    and authorize the IP if it belongs to one. Cache the result.
            import socket
            for allowed in self.authorized_scope:
                allowed_norm = self._normalize_target(allowed)
                if allowed_norm and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', allowed_norm):
                    domains_to_check = [allowed_norm]
                    if allowed_norm.startswith("www."):
                        domains_to_check.append(allowed_norm[4:])
                    for domain in domains_to_check:
                        try:
                            resolved = {ai[4][0] for ai in socket.getaddrinfo(domain, None)}
                        except Exception:
                            resolved = set()
                        if norm in resolved:
                            self._authorized_ips.add(norm)
                            logger.info(f"[TargetScopeValidator] Authorized resolved IP {norm} for in-scope domain {domain}")
                            return True
        return False

    def validate(self, target: str) -> None:
        """Raises AuthorizationError if target is not in authorized scope"""
        logger.debug(f"[TargetScopeValidator] Validating target: {target}")
        if not self.is_authorized(target):
            logger.error(f"[TargetScopeValidator] AUTHORIZATION_DENIED: '{target}' is out of scope!")
            raise AuthorizationError(
                f"Target '{target}' is not in authorized scope: {self.authorized_scope}"
            )
        logger.info(f"[TargetScopeValidator] AUTHORIZATION_CHECK passed: {target}")

    def extract_and_validate_command(self, command: str) -> None:
        """Parses a raw shell command string and validates any extracted hosts/domains/IPs"""
        if not command:
            return
            
        logger.debug(f"[TargetScopeValidator] Checking targets in command: {command}")
        
        # 1. Extract URLs
        urls = re.findall(r'https?://[a-zA-Z0-9\-\.\:]+', command)
        targets = []
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    targets.append(parsed.netloc)
            except Exception:
                pass
                
        # 2. Extract standalone IPs and domains from tokens
        tokens = command.split()
        for token in tokens:
            token = token.strip("\",';()<>")
            # IP check
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', token):
                targets.append(token)
            # Domain check (has dot, starts/ends with alphanumeric, excludes tools/arguments)
            elif re.match(r'^[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-\.]+$', token):
                # Ignore arguments like -d, output file basenames or tool names
                if token.lower() not in (
                    "httpx", "nmap", "subfinder", "amass", "sslscan", "gobuster", 
                    "feroxbuster", "dirb", "dirsearch", "nikto", "nuclei", "whatweb",
                    "sqlmap", "wpscan", "sslyze", "arjun", "paramspider", "dalfox",
                    "katana", "curl", "theharvester", "example.com"
                ) and not token.startswith("-"):
                    targets.append(token)
                    
        # Validate all extracted targets
        for t in set(targets):
            self.validate(t)

class AuthContext:
    """Authorization context for tool invocations"""
    def __init__(self, allowed_tools: Optional[List[str]] = None, 
                 has_elevated_privilege: bool = False, 
                 target_profile=None):
        self.allowed_tools = allowed_tools or []
        self.has_elevated_privilege = has_elevated_privilege
        self.target_profile = target_profile
        self.validator = TargetScopeValidator.get()

    def can_scan_target(self, target: str) -> bool:
        return self.validator.is_authorized(target)

    def log_denial(self, tool_name: str, target: str, reason: str):
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"AuthContext Denial: tool={tool_name} target={target} reason={reason}")
