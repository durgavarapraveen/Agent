from __future__ import annotations

import contextvars
from dataclasses import dataclass, field
import uuid
from typing import Dict, Any, Optional

_correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default=""
)
_scan_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "scan_id", default=""
)
_experiment_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "experiment_id", default=""
)


def new_correlation_id() -> str:
    cid = uuid.uuid4().hex[:16]
    _correlation_id.set(cid)
    return cid


def get_correlation_id() -> str:
    cid = _correlation_id.get()
    if not cid:
        return new_correlation_id()
    return cid


def set_correlation_id(cid: str) -> None:
    _correlation_id.set(cid)


def set_scan_id(sid: str) -> None:
    _scan_id.set(sid)


def get_scan_id() -> str:
    return _scan_id.get()


def set_experiment_id(eid: str) -> None:
    _experiment_id.set(eid)


def get_experiment_id() -> str:
    return _experiment_id.get()


@dataclass
class CorrelationContext:
    correlation_id: str = ""
    scan_id: str = ""
    experiment_id: str = ""
    _tokens: list = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if not self.correlation_id:
            self.correlation_id = uuid.uuid4().hex[:16]

    def to_dict(self) -> Dict[str, str]:
        return {
            "correlation_id": self.correlation_id,
            "scan_id": self.scan_id,
            "experiment_id": self.experiment_id,
        }

    def __enter__(self) -> "CorrelationContext":
        self._tokens = [
            _correlation_id.set(self.correlation_id),
            _scan_id.set(self.scan_id),
            _experiment_id.set(self.experiment_id),
        ]
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._tokens:
            _correlation_id.reset(self._tokens[0])
            _scan_id.reset(self._tokens[1])
            _experiment_id.reset(self._tokens[2])


def set_context(ctx: CorrelationContext) -> None:
    _correlation_id.set(ctx.correlation_id)
    _scan_id.set(ctx.scan_id)
    _experiment_id.set(ctx.experiment_id)


def get_context() -> Dict[str, str]:
    """Return all correlation context for embedding in logs, telemetry, evidence."""
    return {
        "correlation_id": get_correlation_id(),
        "scan_id": get_scan_id(),
        "experiment_id": get_experiment_id(),
    }

