"""Phase 11.2 — DVWA benchmark suite.

DVWA exposes the same vulnerability categories at four security levels (low,
medium, high, impossible). The agent should find more at 'low' and gracefully
degrade toward 'impossible'. Scoring is per security level. Pure/testable; live
runs execute in CI against a DVWA container.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Set

SECURITY_LEVELS = ("low", "medium", "high", "impossible")


@dataclass(frozen=True)
class DVWACase:
    id: str
    category: str
    vuln_class: str
    executor: str
    # Levels at which the vuln is expected to remain exploitable.
    exploitable_at: tuple = ("low", "medium")


DVWA_CASES: List[DVWACase] = [
    DVWACase("sqli", "sql_injection", "sqli", "sql_injection", ("low", "medium", "high")),
    DVWACase("sqli_blind", "sql_injection_blind", "sqli", "sql_injection", ("low", "medium")),
    DVWACase("xss_reflected", "xss_reflected", "xss", "xss", ("low", "medium", "high")),
    DVWACase("xss_stored", "xss_stored", "xss", "xss", ("low", "medium")),
    DVWACase("command_injection", "command_injection", "command_injection", "sql_injection", ("low", "medium")),
    DVWACase("file_inclusion", "file_inclusion", "lfi", "generic", ("low", "medium")),
    DVWACase("file_upload", "file_upload", "file_upload", "generic", ("low",)),
    DVWACase("csrf", "csrf", "csrf", "authorization", ("low", "medium")),
    DVWACase("brute_force", "brute_force", "auth_bypass", "authentication", ("low", "medium")),
]


def expected_at_level(level: str, catalog: List[DVWACase] = None) -> Set[str]:
    catalog = catalog or DVWA_CASES
    return {c.id for c in catalog if level in c.exploitable_at}


def score_by_level(found_by_level: Dict[str, Iterable[str]],
                   catalog: List[DVWACase] = None) -> Dict[str, Any]:
    """found_by_level: {level: iterable of solved case ids}. Scores each level
    against what is expected to be exploitable there."""
    catalog = catalog or DVWA_CASES
    out: Dict[str, Any] = {}
    for level in SECURITY_LEVELS:
        expected = expected_at_level(level, catalog)
        found = set(found_by_level.get(level, [])) & {c.id for c in catalog}
        # True positives: found ∩ expected. False positives-at-level: found beyond expected.
        tp = found & expected
        pct = round(len(tp) / len(expected) * 100, 1) if expected else 100.0
        out[level] = {"expected": len(expected), "found": len(tp),
                      "pct": pct, "unexpected": sorted(found - expected)}
    # Graceful degradation: the agent should solve at least as many cases at
    # 'low' as at 'high' (harder levels expose fewer vulns).
    out["degrades_gracefully"] = out["low"]["found"] >= out["high"]["found"]
    return out
