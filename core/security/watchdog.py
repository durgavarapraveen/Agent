"""External watchdog + kill switch + budgets + impact tiers (§26, §39, §40, §46).

The agent must NOT be the only thing that can stop itself. This module is a
deterministic, LLM-independent governor:

  * Budgets (§39): hard ceilings on requests / runtime / bandwidth / browser
    sessions / LLM cost. The planner may spend within them; it can never raise them.
  * Impact tiers (§40): OBSERVE < LOW_IMPACT < POC < ELEVATED < DESTRUCTIVE.
    A test above the authorized ceiling is refused.
  * Kill switch (§46): an out-of-band trigger (a file, or an API calling
    trigger_kill) that terminates the scan regardless of agent state.

Every network call and loop iteration consults the watchdog. On any breach the
answer is fail-closed: stop. It is a process-wide singleton so brokers, the loop,
and a control endpoint all see the same state.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Impact ordering (§40) — index = severity of side effect.
IMPACT_TIERS = ["OBSERVE", "LOW_IMPACT", "POC", "ELEVATED", "DESTRUCTIVE"]


def impact_rank(impact: str) -> int:
    try:
        return IMPACT_TIERS.index(str(impact or "OBSERVE").upper())
    except ValueError:
        return len(IMPACT_TIERS)  # unknown → most restrictive (treated as too high)


@dataclass
class ScanBudget:
    max_requests: int = 100_000
    max_runtime_s: float = 7_200.0          # 2h
    max_bandwidth_mb: float = 5_000.0
    max_browser_sessions: int = 5
    max_llm_cost: float = 100.0
    max_impact: str = "POC"

    @classmethod
    def from_env(cls) -> "ScanBudget":
        def _f(name, default):
            try:
                return type(default)(os.getenv(name, default))
            except (TypeError, ValueError):
                return default
        return cls(
            max_requests=_f("BUDGET_MAX_REQUESTS", 100_000),
            max_runtime_s=_f("BUDGET_MAX_RUNTIME_S", 7_200.0),
            max_bandwidth_mb=_f("BUDGET_MAX_BANDWIDTH_MB", 5_000.0),
            max_browser_sessions=_f("BUDGET_MAX_BROWSER_SESSIONS", 5),
            max_llm_cost=_f("BUDGET_MAX_LLM_COST", 100.0),
            max_impact=os.getenv("AUTHZ_MAX_IMPACT", "POC").upper(),
        )


class WatchdogTripped(Exception):
    """Raised (fail-closed) when a budget/impact/kill-switch limit is hit."""


class Watchdog:
    def __init__(self, budget: Optional[ScanBudget] = None):
        self.budget = budget or ScanBudget.from_env()
        self._lock = threading.RLock()
        # Monotonic clock for durations: immune to system wall-clock adjustments
        # (NTP steps, DST) that could otherwise skew the runtime budget over a
        # multi-hour scan. Never mix with time.time() here (implemented.md §7.5).
        self._start = time.monotonic()
        self._requests = 0
        self._bytes = 0
        self._llm_cost = 0.0
        self._browser_sessions = 0
        self._killed = False
        self._kill_reason = ""
        self._kill_file = os.getenv("KILL_SWITCH_FILE", "").strip()

    # ── external kill switch (§46) ──────────────────────────────────────
    def trigger_kill(self, reason: str = "manual") -> None:
        with self._lock:
            self._killed = True
            self._kill_reason = reason
        logger.critical("[Watchdog] KILL SWITCH TRIGGERED: %s", reason)

    def _kill_file_present(self) -> bool:
        return bool(self._kill_file) and os.path.exists(self._kill_file)

    @property
    def killed(self) -> bool:
        with self._lock:
            if self._killed:
                return True
        if self._kill_file_present():
            self.trigger_kill(f"kill-switch file present: {self._kill_file}")
            return True
        return False

    # ── metering ────────────────────────────────────────────────────────
    def record_request(self, response_bytes: int = 0) -> None:
        with self._lock:
            self._requests += 1
            self._bytes += max(0, int(response_bytes or 0))

    def record_llm_cost(self, cost: float) -> None:
        with self._lock:
            self._llm_cost += max(0.0, float(cost or 0))

    def open_browser_session(self) -> None:
        with self._lock:
            self._browser_sessions += 1

    def close_browser_session(self) -> None:
        with self._lock:
            self._browser_sessions = max(0, self._browser_sessions - 1)

    # ── enforcement ─────────────────────────────────────────────────────
    def breach_reason(self) -> Optional[str]:
        if self.killed:
            return f"kill switch: {self._kill_reason or 'triggered'}"
        with self._lock:
            b = self.budget
            if self._requests >= b.max_requests:
                return f"max_requests {b.max_requests} reached"
            if b.max_runtime_s > 0 and (time.monotonic() - self._start) >= b.max_runtime_s:
                return f"max_runtime {b.max_runtime_s}s reached"
            if (self._bytes / 1_048_576.0) >= b.max_bandwidth_mb:
                return f"max_bandwidth {b.max_bandwidth_mb}MB reached"
            if self._llm_cost >= b.max_llm_cost:
                return f"max_llm_cost {b.max_llm_cost} reached"
        return None

    def should_continue(self) -> bool:
        return self.breach_reason() is None

    def elapsed_fraction(self) -> float:
        """Fraction of the runtime budget consumed (0.0–…). Used for a SOFT
        deadline so the orchestrator can wind down to reporting cleanly BEFORE
        the hard max_runtime kill halts it mid-operation."""
        try:
            b = self.budget
            if b.max_runtime_s <= 0:
                return 0.0
            return (time.monotonic() - self._start) / b.max_runtime_s
        except Exception:
            return 0.0

    def check(self) -> None:
        """Fail-closed gate: raise WatchdogTripped on any breach. Call before
        every network request / loop iteration."""
        reason = self.breach_reason()
        if reason is not None:
            raise WatchdogTripped(reason)

    def impact_allowed(self, impact: str) -> bool:
        return impact_rank(impact) <= impact_rank(self.budget.max_impact)

    def browser_session_allowed(self) -> bool:
        with self._lock:
            return self._browser_sessions < self.budget.max_browser_sessions

    def stats(self) -> Dict:
        with self._lock:
            return {
                "requests": self._requests,
                "elapsed_s": round(time.monotonic() - self._start, 1),
                "bandwidth_mb": round(self._bytes / 1_048_576.0, 2),
                "llm_cost": round(self._llm_cost, 2),
                "browser_sessions": self._browser_sessions,
                "killed": self._killed,
                "budget": self.budget.__dict__,
            }


_watchdog: Optional[Watchdog] = None
_wlock = threading.RLock()


def get_watchdog() -> Watchdog:
    global _watchdog
    with _wlock:
        if _watchdog is None:
            _watchdog = Watchdog()
        return _watchdog


def reset_watchdog(budget: Optional[ScanBudget] = None) -> Watchdog:
    """Start a fresh budget window (call at scan start)."""
    global _watchdog
    with _wlock:
        _watchdog = Watchdog(budget)
        return _watchdog
