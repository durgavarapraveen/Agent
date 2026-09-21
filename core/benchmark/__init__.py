"""Generic, benchmark-agnostic challenge corpus + scoring (spec §16-19)."""
from core.benchmark.corpus import (
    Challenge, BenchmarkResult, BenchmarkCorpus,
    CONFIRMED, PARTIAL, NOT_FOUND, NOT_APPLICABLE, BLOCKED, ERROR,
)

__all__ = [
    "Challenge", "BenchmarkResult", "BenchmarkCorpus",
    "CONFIRMED", "PARTIAL", "NOT_FOUND", "NOT_APPLICABLE", "BLOCKED", "ERROR",
]
