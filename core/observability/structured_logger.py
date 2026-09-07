"""
P3-2: structured JSON logging.

Emit one dict-per-event rather than free-form messages, so log-scrapers
and the report builder can consume the same source of truth.

Wraps stdlib logging — no new sink required. Use `log_event(...)` at
call sites you want machine-parseable.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

_logger = logging.getLogger("event")


def log_event(event: str, **fields: Any) -> None:
    """Emit a single JSON line under logger 'event'.

    Example:
        log_event("tool.completed", tool="katana", target=t,
                  status="partial", exit_code=2, duration_ms=1234,
                  evidence_count=83, confidence=0.71)
    """
    payload: Dict[str, Any] = {"event": event}
    payload.update(fields)
    try:
        _logger.info(json.dumps(payload, default=str))
    except Exception:
        # Never let logging failures propagate.
        _logger.info(f"event={event} fields={fields!r}")


def log_decision(decision_id: str, topic: str, verdict: str, reason: str,
                 parent_id: Optional[str] = None, **extra: Any) -> None:
    """P3-3 helper for decision provenance events."""
    log_event(
        "decision",
        decision_id=decision_id,
        parent_decision_id=parent_id or "",
        topic=topic,
        verdict=verdict,
        reason=reason,
        **extra,
    )
