
import logging
import re
from typing import Dict, List, Optional, Tuple
from core.common.schemas import ErrorInfo, ErrorType

logger = logging.getLogger(__name__)


class PolicyValidator:
    
    # Block patterns - never allow
    BLOCKED_COMMANDS = [
        "apt-get",
        "apt ",
        "pip install",
        "npm install",
        "yum install",
        "pacman",
        "brew install",
        "dnf install",
        "pkg install",
        "rm -rf",
        "mkfs",
        "> /dev/",
    ]
    
    # Environment modification commands
    ENVIRONMENT_MODIFICATION = [
        "export ",
        "setenv",
        "sudo",
        "su ",
    ]
    
    def __init__(self, authorized_scope: List[str]):
        self.authorized_scope = authorized_scope
    
    def validate_scope(self, target: str) -> Tuple[bool, Optional[str]]:
        if not self.authorized_scope:
            # No scope defined - block everything
            return False, "No authorized scope defined"
        
        for allowed in self.authorized_scope:
            if self._is_in_scope(target, allowed):
                return True, None
        
        return False, f"Target {target} not in authorized scope"
    
    def _is_in_scope(self, target: str, allowed: str) -> bool:
        # Simple matching - can be extended for CIDR, wildcards
        if allowed == "*":
            return True
        if target == allowed:
            return True
        if target.endswith("." + allowed):  # Subdomain match
            return True
        return False
    
    def validate_command(self, command: str) -> Tuple[bool, Optional[ErrorInfo]]:
        if not command or not isinstance(command, str):
            return False, ErrorInfo(
                error_type=ErrorType.INVALID_ARGUMENT,
                message="Command must be non-empty string",
                retryable=False
            )
        
        # Check for blocked patterns
        for blocked in self.BLOCKED_COMMANDS:
            if blocked in command:
                return False, ErrorInfo(
                    error_type=ErrorType.POLICY_REJECTION,
                    message=f"Command contains blocked pattern: {blocked}",
                    retryable=False
                )
        
        # Note: environment modification is allowed but logged
        # (not blocked, but monitored)
        
        return True, None
    
    def validate_tool_operation(self, 
                                tool_name: str,
                                capability: str,
                                target: str,
                                command: Optional[str] = None) -> Tuple[bool, Optional[ErrorInfo]]:
        # Check scope
        scope_ok, scope_reason = self.validate_scope(target)
        if not scope_ok:
            return False, ErrorInfo(
                error_type=ErrorType.SCOPE_VIOLATION,
                message=scope_reason,
                retryable=False
            )
        
        # Check command if provided
        if command:
            cmd_ok, cmd_error = self.validate_command(command)
            if not cmd_ok:
                return False, cmd_error
        
        logger.info(f"[PolicyValidator] Approved: {tool_name} on {target}")
        return True, None
    
    def get_authorization_summary(self) -> Dict:
        return {
            "authorized_scope": self.authorized_scope,
            "blocked_patterns": self.BLOCKED_COMMANDS,
        }


class ScopeValidator:
    
    def __init__(self, authorized_scope: List[str]):
        self.authorized_scope = authorized_scope
        self.policy = PolicyValidator(authorized_scope)
    
    def is_authorized(self, target: str) -> bool:
        authorized, _ = self.policy.validate_scope(target)
        return authorized
    
    def get_discovered_targets(self, targets: List[str]) -> List[str]:
        return [t for t in targets if self.is_authorized(t)]
    
    def validate_discovery_result(self, 
                                  discovered_hosts: List[str],
                                  discovered_subdomains: List[str],
                                  discovered_ips: List[str]) -> Dict[str, List[str]]:
        return {
            "hosts": self.get_discovered_targets(discovered_hosts),
            "subdomains": self.get_discovered_targets(discovered_subdomains),
            "ips": self.get_discovered_targets(discovered_ips),
            "all_authorized": list(set(
                self.get_discovered_targets(discovered_hosts) +
                self.get_discovered_targets(discovered_subdomains) +
                self.get_discovered_targets(discovered_ips)
            ))
        }


class CommandPolicyValidator:
    
    # Categories of commands
    READ_ONLY_PATTERNS = [
        "^nmap",
        "^dig",
        "^nslookup",
        "^curl",
        "^wget",
        "^openssl",
        "^whatweb",
        "^nuclei",
        "^cat",
        "^ls",
        "^find",
        "^grep",
    ]
    
    FORBIDDEN_PATTERNS = [
        "apt-get install",
        "pip install",
        "npm install",
        "rm -rf",
        "mkfs",
        "dd ",
    ]
    
    @classmethod
    def classify_command(cls, command: str) -> str:
        for pattern in cls.READ_ONLY_PATTERNS:
            if re.match(pattern, command):
                return "READ_ONLY"
        return "ENVIRONMENT_MODIFICATION"
    
    @classmethod
    def is_allowed(cls, command: str) -> Tuple[bool, Optional[str]]:
        for forbidden in cls.FORBIDDEN_PATTERNS:
            if forbidden in command:
                return False, f"Forbidden pattern: {forbidden}"
        return True, None
