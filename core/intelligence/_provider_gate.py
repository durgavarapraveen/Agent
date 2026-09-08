"""Per-provider rate limiter + circuit breaker for OSINT clients.

Every third-party feed (Shodan, Censys, VirusTotal, AbuseIPDB, NVD, GitHub,
crt.sh, urlscan, hackertarget, ...) has its own per-key quota and its own
outage cadence. Prior to this, each client raced against every other client
without a shared throttle, and any provider going down would hang the whole
recon phase until the outer LLM timeout fired.

`ProviderGate` is a small, dependency-free primitive:

    from core.intelligence._provider_gate import get_gate
    gate = get_gate("censys")
    async with gate.acquire():
        # do the request

    # or, when a call fails:
    gate.record_failure(reason="429")
    # subsequent acquires will short-circuit until the cooldown expires
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from typing import Dict, Optional

logger = logging.getLogger(__name__)


# Defaults per provider. Override with env `OSINT_RATE_<PROVIDER>=<req/sec>`
# and `OSINT_COOLDOWN_<PROVIDER>=<seconds>`.
_DEFAULT_RATES = {
    "censys": 1.0,        # 1 req/s — respects Free tier
    "shodan": 1.0,
    "virustotal": 0.5,     # 4/min on public tier
    "abuseipdb": 1.0,
    "nvd": 0.5,             # unauth default is 5/30s
    "github": 1.0,
    "crtsh": 0.5,
    "urlscan": 1.0,
    "otx": 1.0,
    "urlhaus": 1.0,
    "threatfox": 1.0,
    "hackertarget": 0.5,
    "*": 2.0,
}
_DEFAULT_COOLDOWN_S = 60.0
_FAILURE_STREAK_TRIP = 3   # consecutive failures before opening the circuit
_FAILURE_WINDOW_S = 120.0  # streak resets after this quiet period


class ProviderGate:
    """Single-instance-per-provider gate. Tracks the last-request timestamp
    for rate limiting and a failure streak for the circuit breaker."""

    def __init__(self, provider: str):
        self.provider = provider
        self._rate_req_per_s = float(os.environ.get(
            f"OSINT_RATE_{provider.upper()}",
            _DEFAULT_RATES.get(provider, _DEFAULT_RATES["*"]),
        ))
        self._cooldown_s = float(os.environ.get(
            f"OSINT_COOLDOWN_{provider.upper()}", _DEFAULT_COOLDOWN_S))
        self._min_interval = 1.0 / max(self._rate_req_per_s, 0.001)

        self._lock = asyncio.Lock()
        self._last_request_at = 0.0
        self._failure_streak = 0
        self._last_failure_at = 0.0
        self._open_until = 0.0  # circuit-breaker: acquires short-circuit while > now

    def is_open(self) -> bool:
        """Circuit-breaker state. True → the caller should skip this provider."""
        return time.monotonic() < self._open_until

    def record_success(self) -> None:
        self._failure_streak = 0

    def record_failure(self, reason: str = "") -> None:
        now = time.monotonic()
        # Reset streak if we've been quiet a while.
        if now - self._last_failure_at > _FAILURE_WINDOW_S:
            self._failure_streak = 0
        self._failure_streak += 1
        self._last_failure_at = now
        if self._failure_streak >= _FAILURE_STREAK_TRIP:
            self._open_until = now + self._cooldown_s
            logger.warning(
                "[ProviderGate:%s] circuit OPEN for %.0fs after %d failures "
                "(last reason: %s)",
                self.provider, self._cooldown_s, self._failure_streak, reason,
            )

    class _AcquireCtx:
        def __init__(self, gate: "ProviderGate"):
            self.gate = gate

        async def __aenter__(self):
            await self.gate._wait_slot()
            return self.gate

        async def __aexit__(self, exc_type, exc, tb):
            # Auto-record failure on typical network exceptions. Consumers can
            # also call record_failure() explicitly for HTTP 429/5xx.
            if exc is not None and isinstance(exc, (OSError, TimeoutError)):
                self.gate.record_failure(reason=type(exc).__name__)
            return False

    def acquire(self) -> "ProviderGate._AcquireCtx":
        return ProviderGate._AcquireCtx(self)

    async def _wait_slot(self) -> None:
        if self.is_open():
            raise ProviderCircuitOpen(
                f"provider '{self.provider}' circuit is open "
                f"({self._open_until - time.monotonic():.0f}s remaining)")
        async with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last_request_at)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_at = time.monotonic()


class ProviderCircuitOpen(RuntimeError):
    """Raised by ProviderGate.acquire when the circuit is open."""


_GATES: Dict[str, ProviderGate] = {}
_GATES_LOCK = threading.Lock()


def get_gate(provider: str) -> ProviderGate:
    """Return the (process-wide) gate for a provider, creating it on first
    access. Provider name is lower-cased for consistency."""
    key = (provider or "*").strip().lower()
    with _GATES_LOCK:
        g = _GATES.get(key)
        if g is None:
            g = ProviderGate(key)
            _GATES[key] = g
        return g
