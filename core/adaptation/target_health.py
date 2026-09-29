"""Live target-health signal for adaptive re-planning.

The network broker feeds every response outcome here; the adaptive controller reads
the state to decide whether to keep testing, back off and wait, or wind down when a
target is unreachable — instead of blindly burning the whole budget against a host
that is 503-ing or timing out.

State machine (sliding window of the most recent outcomes):
  HEALTHY   — normal.
  DEGRADED  — elevated hard-failure rate; proceed but watch.
  DOWN      — sustained hard failures (503/502/504/timeouts/conn errors); back off.

A "hard failure" is a transport error or a 502/503/504 (server unavailable). 4xx
(401/403/404/429…) are NOT failures — they are valid, informative pentest responses.
Per-scan singleton on the shared context so all producers share one view.
"""
from __future__ import annotations

import time
from collections import deque
from typing import Deque, Optional, Tuple

_HARD_STATUSES = frozenset({502, 503, 504})
_WINDOW = 25            # outcomes considered
_DOWN_STREAK = 6        # consecutive hard failures → DOWN
_DOWN_RATE = 0.7        # hard-failure fraction over a full window → DOWN
_DEGRADED_RATE = 0.35   # hard-failure fraction → DEGRADED

HEALTHY, DEGRADED, DOWN = "HEALTHY", "DEGRADED", "DOWN"


class TargetHealth:
    def __init__(self) -> None:
        self._w: Deque[bool] = deque(maxlen=_WINDOW)   # True = hard failure
        self._streak = 0
        self._total = 0
        self._hard = 0
        self._last_change = time.monotonic()
        self._down_since: Optional[float] = None

    def record(self, *, status: Optional[int] = None, transport_error: bool = False) -> None:
        """Record one request outcome. `transport_error` = timeout/conn refused/DNS."""
        hard = bool(transport_error) or (status in _HARD_STATUSES)
        self._w.append(hard)
        self._total += 1
        if hard:
            self._hard += 1
            self._streak += 1
        else:
            self._streak = 0
        st = self.state
        if st == DOWN and self._down_since is None:
            self._down_since = time.monotonic()
        elif st != DOWN:
            self._down_since = None

    @property
    def state(self) -> str:
        if self._streak >= _DOWN_STREAK:
            return DOWN
        n = len(self._w)
        if n >= 8:
            rate = sum(self._w) / n
            if rate >= _DOWN_RATE:
                return DOWN
            if rate >= _DEGRADED_RATE:
                return DEGRADED
        return HEALTHY

    @property
    def is_down(self) -> bool:
        return self.state == DOWN

    def down_seconds(self) -> float:
        return (time.monotonic() - self._down_since) if self._down_since else 0.0

    def summary(self) -> dict:
        return {"state": self.state, "streak": self._streak,
                "window": len(self._w), "hard_rate": round(sum(self._w) / len(self._w), 2) if self._w else 0.0,
                "total": self._total, "down_seconds": round(self.down_seconds(), 1)}


def get_target_health(ctx) -> TargetHealth:
    """Per-scan singleton stored on ctx (best-effort; a detached instance if ctx is
    unavailable so callers never crash)."""
    if ctx is None:
        return TargetHealth()
    th = getattr(ctx, "_target_health", None)
    if not isinstance(th, TargetHealth):
        th = TargetHealth()
        try:
            setattr(ctx, "_target_health", th)
        except Exception:
            pass
    return th


def record_response(ctx, status: Optional[int] = None, *, transport_error: bool = False) -> None:
    """Convenience hook for producers (the network broker) — never raises."""
    try:
        get_target_health(ctx).record(status=status, transport_error=transport_error)
    except Exception:
        pass


async def wait_for_recovery(probe, *, max_wait: float = 180.0,
                            interval: float = 15.0) -> bool:
    """Back off while a target is DOWN: call async `probe()` (returns True when the
    target answers healthily) every `interval` seconds up to `max_wait`. Returns True
    on recovery, False if it stayed down. `probe` must be a coroutine function."""
    import asyncio
    waited = 0.0
    while waited < max_wait:
        await asyncio.sleep(min(interval, max_wait - waited))
        waited += interval
        try:
            if await probe():
                return True
        except Exception:
            pass
    return False
