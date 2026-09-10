from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from core.observability.correlation import get_context as _get_correlation_context

_logger = logging.getLogger("event")


def log_event(event: str, **fields: Any) -> None:
    payload: Dict[str, Any] = {"event": event}
    payload.update(_get_correlation_context())
    payload.update(fields)
    try:
        _logger.info(json.dumps(payload, default=str))
    except Exception:
        # Never let logging failures propagate.
        _logger.info(f"event={event} fields={fields!r}")


def log_decision(decision_id: str, topic: str, verdict: str, reason: str,
                 parent_id: Optional[str] = None, **extra: Any) -> None:
    log_event(
        "decision",
        decision_id=decision_id,
        parent_decision_id=parent_id or "",
        topic=topic,
        verdict=verdict,
        reason=reason,
        **extra,
    )

