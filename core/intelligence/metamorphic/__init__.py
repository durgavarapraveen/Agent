"""
Metamorphic testing subsystem (spec PHASE 5 / Point B / P1.6).

Semantic-preserving input transforms + output-relation oracles. Violations are
surfaced as anomalies for the hypothesis pipeline.
"""
from core.intelligence.metamorphic.engine import (
    MetamorphicEngine,
    MetamorphicResult,
    MetamorphicViolation,
)
from core.intelligence.metamorphic.relations import BUILTIN_RELATIONS, MetamorphicRelation

__all__ = [
    "MetamorphicEngine",
    "MetamorphicResult",
    "MetamorphicViolation",
    "BUILTIN_RELATIONS",
    "MetamorphicRelation",
]
