from __future__ import annotations

import logging
import os
import threading
import time
from typing import Dict, Tuple

logger = logging.getLogger(__name__)


class CircuitOpen(RuntimeError):


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
    with _BREAKERS_LOCK:
        return [(b.key, b.is_open(), b._streak) for b in _BREAKERS.values()]
