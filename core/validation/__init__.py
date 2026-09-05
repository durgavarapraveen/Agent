"""
validation — Finding validation & false-positive reduction.

Public interface:
  ReachabilityAnalyzer / ReachabilityResult — is the vulnerable symbol reachable?
  DedupStore / fingerprint / DedupResult    — cross-scan dedup (new/recurring/resolved).
  assess / assess_finding / gate            — evidence-based confidence scoring.
  ConfidenceVerdict                         — confidence output.
"""

from .reachability import (ReachabilityAnalyzer, ReachabilityResult,
                           REACHABLE, UNREACHABLE, INDETERMINATE)
from .dedup import (DedupStore, DedupResult, fingerprint,
                    NEW, RECURRING, RESOLVED)
from .confidence import (ConfidenceVerdict, assess, assess_finding, gate,
                         HIGH, MEDIUM, LOW)

__all__ = [
    "ReachabilityAnalyzer", "ReachabilityResult",
    "REACHABLE", "UNREACHABLE", "INDETERMINATE",
    "DedupStore", "DedupResult", "fingerprint", "NEW", "RECURRING", "RESOLVED",
    "ConfidenceVerdict", "assess", "assess_finding", "gate", "HIGH", "MEDIUM", "LOW",
]
