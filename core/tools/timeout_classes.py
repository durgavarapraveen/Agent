from __future__ import annotations

from enum import Enum
from typing import Dict


class TimeoutScope(str, Enum):
    TOOL = "TOOL"
    TARGET = "TARGET"
    PHASE = "PHASE"
    SCAN = "SCAN"
    GLOBAL = "GLOBAL"


# Named budgets in seconds.
CLASSES: Dict[str, int] = {
    "quick": 60,
    "standard": 300,     # 5 min
    "deep": 600,         # 10 min
    "long": 1200,        # 20 min — only for owner-approved deep scans
}


SCOPE_CAPS: Dict[TimeoutScope, int] = {
    TimeoutScope.TOOL:   600,        # 10 min per tool invocation
    TimeoutScope.TARGET: 30 * 60,    # 30 min per target
    TimeoutScope.PHASE:  60 * 60,    # 1 hour per phase
    TimeoutScope.SCAN:   4 * 60 * 60,  # 4 hours per scan
    TimeoutScope.GLOBAL: 12 * 60 * 60,  # 12 hour absolute
}


def budget_for(cls: str) -> int:
    return CLASSES.get((cls or "").lower(), CLASSES["standard"])


def cap_for(scope: TimeoutScope) -> int:
    return SCOPE_CAPS[scope]


def clamp(seconds: int, scope: TimeoutScope = TimeoutScope.TOOL) -> int:
    return max(1, min(int(seconds or 0), cap_for(scope)))


# Recommended default class per capability. The router can use this so
# `directory_bruteforce` can't accidentally get a `deep` budget.
DEFAULT_CLASS: Dict[str, str] = {
    "port_scanning": "standard",
    "port_discovery": "standard",
    "subdomain_enumeration": "standard",
    "dns_enumeration": "quick",
    "technology_fingerprinting": "quick",
    "waf_detection": "quick",
    "web_crawling": "standard",
    "endpoint_discovery": "standard",
    "directory_bruteforce": "standard",
    "vulnerability_scanning": "deep",
    "sql_injection": "long",
    "xss_scanning": "standard",
    "tls_analysis": "quick",
    "http_analysis": "quick",
}


# Per-capability TOOL-scope ceiling override (seconds). A few tools legitimately
# need longer than the generic 600s per-invocation cap — notably sqlmap's
# boolean/time-based blind confirmation, which was being SIGKILLed at 600s with
# zero results (600s wasted). Raise ONLY those capabilities; everything else
# still clamps to the generic TOOL cap so runaway tools stay bounded.
TOOL_CAP_OVERRIDES: Dict[str, int] = {
    # sqlmap at level5/risk3/BEUSTQ was SIGKILLed at the 900s floor with zero
    # results. Give it the "long" 1200s budget so blind confirmation actually
    # finishes (with -o optimization it fits); other tools stay at the 600s cap.
    "sql_injection": 1200,
}


def default_class_for(capability: str) -> str:
    return DEFAULT_CLASS.get((capability or "").lower(), "standard")


def default_seconds_for(capability: str) -> int:
    c = (capability or "").lower()
    secs = budget_for(default_class_for(c))
    cap = TOOL_CAP_OVERRIDES.get(c, cap_for(TimeoutScope.TOOL))
    return max(1, min(int(secs), cap))
