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
