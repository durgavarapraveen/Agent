"""Rate-limited logging helpers for the many `except Exception: pass` sites
across the exploitation modules.

The pattern

    try:
        risky_op()
    except Exception:
        pass

is common in `core/exploitation/*` because a single tool run may fire hundreds
of probes and one probe failing must not tank the whole loop. But the audit
(#146) flagged it because the failures never surface — an entire executor
silently returning nothing looks identical to a clean run.

Use the helper below instead:

    from core.common.error_hygiene import log_and_swallow
    try:
        risky_op()
    except Exception as e:
        log_and_swallow(logger, e, context="probe X on Y")

`log_and_swallow` logs the FIRST occurrence per (logger, exception_type) at
WARNING, then subsequent occurrences at DEBUG for the next 5 minutes, then
WARNING again once. This keeps the output signal-heavy without spamming.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Dict, Tuple

_lock = threading.Lock()
_last_warned: Dict[Tuple[str, str], float] = {}

# WARN once, then throttle further messages of the same key to DEBUG until
# this many seconds have passed.
_WARN_THROTTLE_S = 300.0


def log_and_swallow(logger: logging.Logger, exc: BaseException, *,
                    context: str = "") -> None:
    """Log an exception and continue. First occurrence per (logger, type) is
    a WARNING; subsequent occurrences drop to DEBUG for ~5 min; then WARN
    again to indicate the failure is still happening."""
    key = (logger.name, type(exc).__name__)
    now = time.monotonic()
    with _lock:
        last = _last_warned.get(key, 0.0)
        should_warn = (now - last) >= _WARN_THROTTLE_S
        if should_warn:
            _last_warned[key] = now
    if should_warn:
        logger.warning("swallowed %s: %s (context: %s)",
                       type(exc).__name__, exc, context or "-")
    else:
        logger.debug("swallowed %s: %s (context: %s)",
                     type(exc).__name__, exc, context or "-")
