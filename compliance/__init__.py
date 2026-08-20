"""
compliance — Multi-framework compliance mapping.

Public interface:
  FRAMEWORKS / FRAMEWORK_NAMES / available_frameworks / category_for_cwe
  ComplianceMapper / ComplianceHit  — map findings -> controls.
  ComplianceReporter / ControlResult — per-framework scan summary.
"""

from .frameworks import (FRAMEWORKS, FRAMEWORK_NAMES, CWE_CATEGORY, CATEGORIES,
                         available_frameworks, category_for_cwe)
from .mapper import ComplianceMapper, ComplianceHit
from .reporter import ComplianceReporter, ControlResult

__all__ = [
    "FRAMEWORKS", "FRAMEWORK_NAMES", "CWE_CATEGORY", "CATEGORIES",
    "available_frameworks", "category_for_cwe",
    "ComplianceMapper", "ComplianceHit",
    "ComplianceReporter", "ControlResult",
]
