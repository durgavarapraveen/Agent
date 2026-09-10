from __future__ import annotations

import logging
import time
from collections import deque
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_WINDOW = 30
_DEGRADE_5XX_RATE = 0.10
_THROTTLE_5XX_RATE = 0.25
_PAUSE_5XX_RATE = 0.50
_DEGRADE_LATENCY_MS = 5000
_THROTTLE_LATENCY_MS = 10000


class TargetHealthManager:

    def __init__(self, target: str, max_concurrency: int = 10):
        self.target = target
        self.state = "HEALTHY"
        self._max_concurrency = max_concurrency
        self._current_concurrency = max_concurrency
        self._responses: deque = deque(maxlen=200)
        self._last_check = time.monotonic()
        self._events: list = []

    @property
    def concurrency(self) -> int:
        return self._current_concurrency

    @property
    def can_run_expensive_tests(self) -> bool:
        return self.state in ("HEALTHY", "DEGRADED")

    @property
    def can_run_exploitation(self) -> bool:
        return self.state in ("HEALTHY", "DEGRADED", "THROTTLED")

    @property
    def is_paused(self) -> bool:
        return self.state == "PAUSED"

    def record_response(self, status_code: int, latency_ms: float) -> None:
        self._responses.append({
            "status": status_code,
            "latency_ms": latency_ms,
            "ts": time.monotonic(),
        })
        self._evaluate()

    def record_timeout(self) -> None:
        self._responses.append({
            "status": 0,
            "latency_ms": 999999,
            "ts": time.monotonic(),
        })
        self._evaluate()

    def record_connection_failure(self) -> None:
        self._responses.append({
            "status": -1,
            "latency_ms": 0,
            "ts": time.monotonic(),
        })
        self._evaluate()

    def _evaluate(self) -> None:
        now = time.monotonic()
        if now - self._last_check < 2:
            return
        self._last_check = now

        cutoff = now - _WINDOW
        recent = [r for r in self._responses if r["ts"] > cutoff]
        if len(recent) < 3:
            return

        total = len(recent)
        errors_5xx = sum(1 for r in recent if 500 <= r.get("status", 0) < 600)
        timeouts = sum(1 for r in recent if r.get("status") == 0)
        conn_fail = sum(1 for r in recent if r.get("status") == -1)
        error_rate = (errors_5xx + timeouts + conn_fail) / total
        avg_latency = sum(r["latency_ms"] for r in recent if r["latency_ms"] < 900000) / max(1, total - timeouts)

        old_state = self.state

        if self.state == "HEALTHY":
            if error_rate >= _PAUSE_5XX_RATE:
                self._transition("PAUSED", error_rate, avg_latency)
            elif error_rate >= _THROTTLE_5XX_RATE or avg_latency > _THROTTLE_LATENCY_MS:
                self._transition("THROTTLED", error_rate, avg_latency)
            elif error_rate >= _DEGRADE_5XX_RATE or avg_latency > _DEGRADE_LATENCY_MS:
                self._transition("DEGRADED", error_rate, avg_latency)

        elif self.state == "DEGRADED":
            if error_rate >= _THROTTLE_5XX_RATE:
                self._transition("THROTTLED", error_rate, avg_latency)
            elif error_rate < _DEGRADE_5XX_RATE and avg_latency < _DEGRADE_LATENCY_MS:
                self._transition("HEALTHY", error_rate, avg_latency)

        elif self.state == "THROTTLED":
            if error_rate >= _PAUSE_5XX_RATE:
                self._transition("PAUSED", error_rate, avg_latency)
            elif error_rate < _DEGRADE_5XX_RATE:
                self._transition("DEGRADED", error_rate, avg_latency)

        elif self.state == "PAUSED":
            self._transition("RECOVERY_CHECK", error_rate, avg_latency)

        elif self.state == "RECOVERY_CHECK":
            if error_rate < _DEGRADE_5XX_RATE:
                self._transition("HEALTHY", error_rate, avg_latency)
            else:
                self._transition("PAUSED", error_rate, avg_latency)

    def _transition(self, new_state: str, error_rate: float, avg_latency: float) -> None:
        old = self.state
        self.state = new_state

        concurrency_map = {
            "HEALTHY": self._max_concurrency,
            "DEGRADED": max(1, self._max_concurrency // 2),
            "THROTTLED": max(1, self._max_concurrency // 4),
            "PAUSED": 0,
            "RECOVERY_CHECK": 1,
        }
        self._current_concurrency = concurrency_map.get(new_state, 1)

        event = {
            "from": old, "to": new_state,
            "error_rate": round(error_rate, 3),
            "avg_latency_ms": round(avg_latency, 1),
            "concurrency": self._current_concurrency,
        }
        self._events.append(event)
        logger.warning(f"TARGET_HEALTH {old} -> {new_state} "
                       f"error_rate={error_rate:.1%} latency={avg_latency:.0f}ms "
                       f"concurrency={self._current_concurrency}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "state": self.state,
            "concurrency": self._current_concurrency,
            "max_concurrency": self._max_concurrency,
            "recent_responses": len(self._responses),
            "events": self._events[-20:],
        }
