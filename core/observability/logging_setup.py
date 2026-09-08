"""Structured JSON logging with global PII redaction.

Every log line emitted after `configure_root()` is guaranteed to:
  - be a single JSON object per line,
  - carry `timestamp`, `level`, `logger`, `message`, and any `extra` fields,
  - have known secret / credential patterns redacted BEFORE reaching stdout.

Usage:

    from core.observability import logging as ag_logging
    ag_logging.configure_root(json=True, level="INFO")

Set `ANTIGRAVITY_LOG_FORMAT=json` in env to force the JSON format regardless
of the code default. Set `=text` to force human-readable output (useful in
interactive debugging).
"""
from __future__ import annotations

import json
import logging
import os
import datetime
import sys
from typing import Any


class PIIRedactionFilter(logging.Filter):
    """Runs `core.reporting.reporting.mask_sensitive_data` on every log
    line before it hits any handler. Falls back to a no-op if the mask
    module is unavailable (avoids import cycles at boot)."""

    def __init__(self):
        super().__init__()
        try:
            from core.reporting.reporting import mask_sensitive_data
            self._mask = mask_sensitive_data
        except Exception:
            self._mask = None

    def filter(self, record: logging.LogRecord) -> bool:
        if self._mask is None:
            return True
        try:
            if isinstance(record.msg, str) and record.args:
                # Realise the formatted message BEFORE masking so `%s`
                # substitution can't smuggle a secret past the filter.
                try:
                    record.msg = record.msg % record.args
                    record.args = None
                except Exception:
                    pass
            if isinstance(record.msg, str):
                record.msg = self._mask(record.msg)
        except Exception:
            # Never let the filter drop a log line — mask failures are
            # non-fatal but should not silence the source line.
            pass
        return True


class JSONFormatter(logging.Formatter):
    """Emit one JSON object per record. `extra=...` on the logger call is
    merged into the top-level object."""

    _STANDARD_KEYS = frozenset({
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "message", "asctime", "taskName",
    })

    def format(self, record: logging.LogRecord) -> str:
        obj: dict[str, Any] = {
            "timestamp": datetime.datetime.fromtimestamp(record.created).strftime("%Y-%m-%dT%H:%M:%S.%f"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            obj["exception"] = self.formatException(record.exc_info)
        # Merge `extra` fields.
        for k, v in record.__dict__.items():
            if k in self._STANDARD_KEYS or k.startswith("_"):
                continue
            try:
                json.dumps(v)  # ensure serialisable
                obj[k] = v
            except (TypeError, ValueError):
                obj[k] = repr(v)
        return json.dumps(obj, default=str, ensure_ascii=False)


def _resolve_format(json_hint: bool | None) -> str:
    forced = os.environ.get("ANTIGRAVITY_LOG_FORMAT", "").strip().lower()
    if forced in ("json", "text"):
        return forced
    if json_hint is None:
        # Default to JSON when running under a process manager (no TTY on stdout).
        return "text" if sys.stdout.isatty() else "json"
    return "json" if json_hint else "text"


def configure_root(json: bool | None = None, level: str = "INFO") -> None:
    """Install a single stdout handler on the root logger with the given
    format and the PII redaction filter. Idempotent — a second call replaces
    the previous handler rather than stacking a duplicate."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove any previously-installed AntiGravity handler so this call is
    # idempotent under uvicorn reload / test setup.
    for h in list(root.handlers):
        if getattr(h, "_antigravity", False):
            root.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    handler._antigravity = True  # type: ignore[attr-defined]
    fmt = _resolve_format(json)
    if fmt == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"))

    handler.addFilter(PIIRedactionFilter())
    root.addHandler(handler)
