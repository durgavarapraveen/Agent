"""
Differential testing subsystem (spec PHASE 5 / Point A / P1.5).

Send supposedly-equivalent requests, compare the responses, surface every
divergence as an anomaly for the hypothesis pipeline.
"""
from core.intelligence.differential.comparison import (
    Divergence,
    ResponseSnapshot,
    all_equivalent,
    body_similarity,
    compare_snapshots,
    normalize_body,
)
from core.intelligence.differential.engine import DifferentialEngine, DifferentialResult
from core.intelligence.differential.representations import (
    HttpRequest,
    representation_variants,
    send,
)

__all__ = [
    "Divergence",
    "ResponseSnapshot",
    "all_equivalent",
    "body_similarity",
    "compare_snapshots",
    "normalize_body",
    "DifferentialEngine",
    "DifferentialResult",
    "HttpRequest",
    "representation_variants",
    "send",
]
