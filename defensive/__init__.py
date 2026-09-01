"""
Defensive Security Architecture & Risk Assessment Suite.
Provides internal visibility, network exposure auditing, credential protection checks,
secret scanning, and persistence vector monitoring/defense rule generation.
"""

from defensive.network_audit import NetworkAuditor
from defensive.credential_hardening import CredentialHardeningAuditor, SecretScanner
from defensive.persistence_monitor import PersistenceMonitor
from defensive.manager import DefensiveRiskAssessor

__all__ = [
    "NetworkAuditor",
    "CredentialHardeningAuditor",
    "SecretScanner",
    "PersistenceMonitor",
    "DefensiveRiskAssessor",
]
