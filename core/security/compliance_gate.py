"""
Compliance Gate Enforcement
Prevents unauthorized exploitation techniques against out-of-scope targets.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

COMPLIANCE_CONFIG = {
    "block_on_failure": True,
    "log_level": "WARNING"
}

@dataclass
class ComplianceCheckResult:
    authorized: bool
    reason: str
    target: str
    technique: str

class ScopeValidator:
    def __init__(self, authorized_targets: List[str], authorized_techniques: List[str] = None):
        self.authorized_targets = [t.lower() for t in authorized_targets]
        self.authorized_techniques = [t.lower() for t in (authorized_techniques or [])]

    def is_target_authorized(self, target: str) -> bool:
        if not target:
            return False
        
        target = target.lower()
        if "://" in target:
            target = target.split("://", 1)[1]
        if "/" in target:
            target = target.split("/", 1)[0]
        if ":" in target:
            target = target.split(":", 1)[0]
            
        for auth_target in self.authorized_targets:
            auth_t = auth_target
            if "://" in auth_t:
                auth_t = auth_t.split("://", 1)[1]
            if "/" in auth_t:
                auth_t = auth_t.split("/", 1)[0]
            if ":" in auth_t:
                auth_t = auth_t.split(":", 1)[0]
                
            if target == auth_t or target.endswith("." + auth_t):
                return True
        return False

    def is_technique_authorized(self, technique: str) -> bool:
        if not self.authorized_techniques:
            return True # Allow all if not specified
        return technique.lower() in self.authorized_techniques

class ComplianceAuditLogger:
    def log_decision(self, result: ComplianceCheckResult):
        timestamp = datetime.now().isoformat()
        decision = "ALLOW" if result.authorized else "DENY"
        msg = f"[COMPLIANCE_AUDIT] {timestamp} - {decision} - Target: {result.target} - Technique: {result.technique} - Reason: {result.reason}"
        if result.authorized:
            logger.info(msg)
        else:
            logger.warning(msg)

class ComplianceGate:
    def __init__(self, scope_validator: ScopeValidator, audit_logger: ComplianceAuditLogger = None, config: Dict = None):
        self.validator = scope_validator
        self.audit = audit_logger or ComplianceAuditLogger()
        self.config = config or COMPLIANCE_CONFIG

    def check_before_exploit(self, target: str, technique: str = "auto") -> ComplianceCheckResult:
        if not self.validator.is_target_authorized(target):
            result = ComplianceCheckResult(
                authorized=False,
                reason=f"Target '{target}' is not in authorized scope.",
                target=target,
                technique=technique
            )
        elif not self.validator.is_technique_authorized(technique):
            result = ComplianceCheckResult(
                authorized=False,
                reason=f"Technique '{technique}' is not authorized.",
                target=target,
                technique=technique
            )
        else:
            result = ComplianceCheckResult(
                authorized=True,
                reason="Target and technique are authorized.",
                target=target,
                technique=technique
            )
            
        self.audit.log_decision(result)
        return result
