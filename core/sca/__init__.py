"""Container / dependency SCA (spec §5/§20/§21).

Static software-composition analysis: manifest/lockfile parsing, advisory
matching, and Dockerfile weakness checks. Engagement scope-gated, deterministic.
"""
from core.sca.parsers import Package, parse_files, parser_for
from core.sca.advisories import (
    Advisory, Range, AdvisorySource, StaticAdvisorySource, OsvSource,
)
from core.sca.matcher import match, is_vulnerable, version_in_range
from core.sca.dockerfile import analyze_dockerfile
from core.sca.agent import ScaAgent

__all__ = [
    "Package", "parse_files", "parser_for",
    "Advisory", "Range", "AdvisorySource", "StaticAdvisorySource", "OsvSource",
    "match", "is_vulnerable", "version_in_range",
    "analyze_dockerfile", "ScaAgent",
]
