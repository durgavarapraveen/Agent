"""Scan execution mode — how *thoroughly* each injection point is tested.

Orthogonal to ``scan_profile`` (which decides *which families* run):

  * ``FAST``      → stop at the first confirmation per (point, class). Quick
                    triage / CI / gentle on fragile or not-fully-owned targets.
  * ``COVERAGE``  → **default**. Keep testing after a hit, but bounded by a
                    per-point payload budget (ranked + dedup). Real production
                    pentests: catches multiple distinct bugs on one endpoint
                    (reflected *and* DOM XSS; error-based *and* blind SQLi)
                    without a request explosion.
  * ``BENCHMARK`` → exhaustive: no early stop, no budget cap — every applicable
                    payload and oracle runs so each distinct benchmark challenge
                    sharing an endpoint/class gets its specific trigger. For
                    AUTHORIZED labs/CTFs (OWASP Juice Shop) only.

Precedence: ``NEO_SCAN_MODE`` env wins; else default ``coverage``.
"""
from __future__ import annotations

import os

FAST = "fast"
COVERAGE = "coverage"
BENCHMARK = "benchmark"
_VALID = {FAST, COVERAGE, BENCHMARK}

# Per-point payload budget for COVERAGE when the caller passed none (0/unset).
_COVERAGE_BUDGET = "NEO_COVERAGE_BUDGET"
_DEFAULT_COVERAGE_BUDGET = 12
# FAST per-point floor when the caller passed no budget (early-stop caps effort).
_FAST_DEFAULT_BUDGET = 8
# A large ceiling that stands in for "all applicable payloads" under BENCHMARK.
_BENCHMARK_CEIL = 100000


def mode() -> str:
    m = (os.getenv("NEO_SCAN_MODE", COVERAGE) or COVERAGE).strip().lower()
    return m if m in _VALID else COVERAGE


def stop_after_first() -> bool:
    """True → break at the first confirmation per (point, class) (FAST only).
    COVERAGE and BENCHMARK keep collecting distinct confirmations."""
    return mode() == FAST


def is_benchmark() -> bool:
    return mode() == BENCHMARK


def effective_budget(base_budget: int) -> int:
    """Adjust a caller-supplied per-point payload budget for the active mode.

    BENCHMARK → uncapped (all applicable payloads). COVERAGE → the caller's
    budget, or a sensible default when it passed 0/none. FAST → the caller's
    budget (early-stop makes its size largely moot)."""
    try:
        base = int(base_budget or 0)
    except (TypeError, ValueError):
        base = 0
    m = mode()
    if m == BENCHMARK:
        return _BENCHMARK_CEIL
    if m == COVERAGE:
        if base > 0:
            return base
        try:
            return max(1, int(os.getenv(_COVERAGE_BUDGET, str(_DEFAULT_COVERAGE_BUDGET))))
        except ValueError:
            return _DEFAULT_COVERAGE_BUDGET
    # FAST: early-stop caps effort anyway; floor an unset budget so a non-vuln
    # point doesn't fire the whole catalog before giving up.
    return base if base > 0 else _FAST_DEFAULT_BUDGET
