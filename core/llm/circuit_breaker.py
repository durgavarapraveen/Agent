"""Per-provider / per-model / per-phase circuit breaker for LLM calls.

Keeps the provider fallback chain honest: if one provider's `deepseek-reasoner`
model has failed 3 times in the last 60 s during the EXPLOIT phase, subsequent
requests for `(deepseek, deepseek-reasoner, exploit)` fast-fail with
`CircuitOpen` for the next 60 s so the harness moves on immediately instead
of adding another round-trip on each call.

Independent of `core/intelligence/_provider_gate.py` which is scoped to OSINT
feeds. Both use the same failure-window + cooldown pattern, but LLM policy
is far more restrictive (planning stalls are extremely visible to operators).

Usage:

    from core.llm.circuit_breaker import get_llm_breaker, CircuitOpen
    breaker = get_llm_breaker("deepseek", "deepseek-reasoner", phase="exploit")
    if breaker.is_open():
        raise CircuitOpen(str(breaker))
    try:
        result = await client.generate(...)
        breaker.record_success()
    except Exception:
        breaker.record_failure()
        raise
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Dict, Tuple

logger = logging.getLogger(__name__)


class CircuitOpen(RuntimeError):
    """Raised when a caller tries to use an open circuit."""


_STREAK_TRIP = int(os.environ.get("LLM_BREAKER_STREAK", "3"))
_FAILURE_WINDOW_S = float(os.environ.get("LLM_BREAKER_WINDOW_S", "120"))
_COOLDOWN_S = float(os.environ.get("LLM_BREAKER_COOLDOWN_S", "60"))


class _Breaker:
    def __init__(self, key: str):
        self.key = key
        self._streak = 0
        self._last_failure_at = 0.0
        self._open_until = 0.0
        self._lock = threading.Lock()

    def is_open(self) -> bool:
        return time.monotonic() < self._open_until

    def record_success(self) -> None:
        with self._lock:
            self._streak = 0

    def record_failure(self) -> None:
        now = time.monotonic()
        with self._lock:
            if now - self._last_failure_at > _FAILURE_WINDOW_S:
                self._streak = 0
            self._streak += 1
            self._last_failure_at = now
            if self._streak >= _STREAK_TRIP:
                self._open_until = now + _COOLDOWN_S
                logger.warning(
                    "[LLM breaker] %s OPEN for %.0fs after %d failures",
                    self.key, _COOLDOWN_S, self._streak,
                )

    def __str__(self) -> str:
        remaining = max(0.0, self._open_until - time.monotonic())
        return f"circuit '{self.key}' open ({remaining:.0f}s remaining)"


_BREAKERS: Dict[str, _Breaker] = {}
_BREAKERS_LOCK = threading.Lock()


def get_llm_breaker(provider: str, model: str, phase: str = "any") -> _Breaker:
    key = f"{(provider or 'unknown').lower()}::{(model or 'unknown').lower()}::{(phase or 'any').lower()}"
    with _BREAKERS_LOCK:
        b = _BREAKERS.get(key)
        if b is None:
            b = _Breaker(key)
            _BREAKERS[key] = b
        return b


def snapshot() -> list[Tuple[str, bool, int]]:
    """Returns `(key, is_open, streak)` per breaker — for a /debug/breakers
    admin endpoint or ops dashboard."""
    with _BREAKERS_LOCK:
        return [(b.key, b.is_open(), b._streak) for b in _BREAKERS.values()]
