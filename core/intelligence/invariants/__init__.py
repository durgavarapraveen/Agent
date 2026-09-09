"""
Security-invariant subsystem (spec PHASE 5 / P1.4 / Point F / Point K).

Encodes assumptions that should always hold (no error/stack/DB leakage, no
version disclosure, failed-auth establishes no session) and reports violations
as evidence-backed anomalies.
"""
from core.intelligence.invariants.engine import InvariantEngine, InvariantViolation
from core.intelligence.invariants.library import BUILTIN_INVARIANTS, SecurityInvariant

__all__ = [
    "InvariantEngine",
    "InvariantViolation",
    "BUILTIN_INVARIANTS",
    "SecurityInvariant",
]
