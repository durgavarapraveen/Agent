"""
Defensive Security Architecture & Risk Assessment Suite.
Provides internal visibility, network exposure auditing, credential protection checks,
secret scanning, and persistence vector monitoring/defense rule generation.
"""

from core.defensive.network_audit import NetworkAuditor
from core.defensive.credential_hardening import CredentialHardeningAuditor, SecretScanner
from core.defensive.persistence_monitor import PersistenceMonitor
from core.defensive.manager import DefensiveRiskAssessor

__all__ = [
    "NetworkAuditor",
    "CredentialHardeningAuditor",
    "SecretScanner",
    "PersistenceMonitor",
    "DefensiveRiskAssessor",
]
