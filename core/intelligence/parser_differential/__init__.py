"""
Parser-differential research subsystem (spec PHASE 5 / Point C / P1.7).

Discovers request-parsing inconsistencies (duplicate parameters, query-vs-body
precedence, case/whitespace handling, layered URL-decoding, JSON duplicate keys)
using benign distinguishable markers.
"""
from core.intelligence.parser_differential.engine import (
    ParserAnalysis,
    ParserDifferentialEngine,
    ParserObservation,
)
from core.intelligence.parser_differential.mutations import (
    ParserProbe,
    build_parser_probes,
    json_probe_control,
)

__all__ = [
    "ParserAnalysis",
    "ParserDifferentialEngine",
    "ParserObservation",
    "ParserProbe",
    "build_parser_probes",
    "json_probe_control",
]
