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
        logger.info(f"[TargetScopeValidator] Initialized with scope: {self.authorized_scope}")

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
        for allowed in self.authorized_scope:
            if allowed == "*":
                return True
            allowed_norm = self._normalize_target(allowed)
            if norm == allowed_norm:
                return True
            if norm.endswith("." + allowed_norm):
                return True
            if allowed_norm.startswith("*."):
                root = allowed_norm[2:]
                if norm == root or norm.endswith("." + root):
                    return True
            # Handle root/apex conversion (e.g. allowed: www.speshway.com -> match speshway.com or blog.speshway.com)
            if allowed_norm.startswith("www."):
                root = allowed_norm[4:]
                if norm == root or norm.endswith("." + root):
                    return True
            # Handle apex match (e.g. allowed: speshway.com -> match www.speshway.com)
            else:
                if allowed_norm.count(".") >= 1:
                    if norm.endswith("." + allowed_norm):
                        return True
                        
        # Check if target is an IP address resolving from an in-scope domain
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', norm):
            import socket
            for allowed in self.authorized_scope:
                allowed_norm = self._normalize_target(allowed)
                if allowed_norm and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', allowed_norm):
                    try:
                        # Handle www. prefix checks
                        domains_to_check = [allowed_norm]
                        if allowed_norm.startswith("www."):
                            domains_to_check.append(allowed_norm[4:])
                        for domain in domains_to_check:
                            resolved_ip = socket.gethostbyname(domain)
                            if norm == resolved_ip:
                                logger.info(f"[TargetScopeValidator] Dynamically authorized resolved IP {norm} for {domain}")
                                return True
                    except Exception:
                        pass
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
