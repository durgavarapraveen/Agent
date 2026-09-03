"""
Cloud privilege-escalation analysis (Feature #9).

Enumerates privilege-escalation paths across cloud identity surfaces:
  * AWS IAM  — detects known IAM privesc techniques from a principal's permissions
  * K8s RBAC — flags dangerous role/binding permissions (exec, secrets, escalate…)
  * Containers — heuristics for escape-prone container configuration

Analysis is data-driven: feed it exported policy documents (no live creds needed),
or let it enumerate live permissions when cloud SDKs + credentials are available.
"""

from core.cloud.iam_privesc import (
    IAMPrivescAnalyzer,
    K8sRBACAnalyzer,
    ContainerEscapeChecker,
    CloudPrivescScanner,
)

__all__ = [
    "IAMPrivescAnalyzer",
    "K8sRBACAnalyzer",
    "ContainerEscapeChecker",
    "CloudPrivescScanner",
]
