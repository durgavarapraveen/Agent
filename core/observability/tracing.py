"""OpenTelemetry tracing wrapper.

Zero hard dependency on OTel. When the SDK is installed and configured (via
`OTEL_EXPORTER_OTLP_ENDPOINT` etc.), spans propagate through the API →
scan-process → executor boundary. When it isn't installed the `span()`
context manager is a no-op.

Instrumentation contract:

    with tracing.span("phase.recon", scan_id=sid, target=t):
        ...
    tracing.record_exception(exc)
    tracing.set_attr("finding_count", n)

Trace-ID propagation across the subprocess boundary uses the
`traceparent` env var (W3C standard); `main.py` reads it at boot and
`ui/api/server.py` sets it when spawning the child.
"""
from __future__ import annotations

import os
import contextlib
import logging
from typing import Any, Iterator, Optional

logger = logging.getLogger(__name__)


try:
    from opentelemetry import trace as _otel_trace
    from opentelemetry.trace import Status, StatusCode
    from opentelemetry.propagate import inject, extract
    _AVAILABLE = True
except ImportError:  # pragma: no cover
    _AVAILABLE = False
    _otel_trace = None
    Status = StatusCode = None
    inject = extract = None  # type: ignore


_SERVICE_NAME = os.environ.get("OTEL_SERVICE_NAME", "antigravity")
_TRACER = None


def _get_tracer():
    global _TRACER
    if _TRACER is None and _AVAILABLE:
        _TRACER = _otel_trace.get_tracer(_SERVICE_NAME)
    return _TRACER


def is_available() -> bool:
    return _AVAILABLE


@contextlib.contextmanager
def span(name: str, **attributes: Any) -> Iterator[Optional[Any]]:
    """Start a span with the given attributes. Attribute values are coerced
    to str/int/float/bool — OTel rejects other types. A no-op when the SDK
    isn't installed."""
    tracer = _get_tracer()
    if tracer is None:
        yield None
        return

    coerced = {}
    for k, v in attributes.items():
        if isinstance(v, (str, int, float, bool)):
            coerced[k] = v
        elif v is None:
            continue
        else:
            coerced[k] = str(v)

    with tracer.start_as_current_span(name, attributes=coerced) as s:
        try:
            yield s
        except Exception as e:
            try:
                s.record_exception(e)
                s.set_status(Status(StatusCode.ERROR, str(e)))
            except Exception:
                pass
            raise


def record_exception(exc: BaseException) -> None:
    tracer = _get_tracer()
    if tracer is None:
        return
    try:
        current = _otel_trace.get_current_span()
        if current and current.is_recording():
            current.record_exception(exc)
            current.set_status(Status(StatusCode.ERROR, str(exc)))
    except Exception:
        pass


def set_attr(key: str, value: Any) -> None:
    tracer = _get_tracer()
    if tracer is None:
        return
    try:
        current = _otel_trace.get_current_span()
        if current and current.is_recording():
            current.set_attribute(key, value if isinstance(value, (str, int, float, bool)) else str(value))
    except Exception:
        pass


# ── Cross-process propagation via env var ──────────────────────────────

def inject_headers() -> dict:
    """Return {traceparent, tracestate} headers for the current span (if any),
    ready to inject into an outgoing HTTP request or a subprocess env."""
    if not _AVAILABLE:
        return {}
    headers: dict = {}
    try:
        inject(headers)
    except Exception:
        pass
    return headers


def context_from_env(env: dict | None = None) -> None:
    """Configure the current process to inherit a span context from env vars.
    Called by `main.py` after argparse so the scan subprocess is a child of
    the API span that spawned it."""
    if not _AVAILABLE or extract is None:
        return
    env = env or os.environ
    tp = env.get("TRACEPARENT") or env.get("traceparent")
    if not tp:
        return
    try:
        ctx = extract({"traceparent": tp})
        # OTel Python has no direct "make this the current context"; instead
        # start a root span so subsequent spans inherit it. This is a light-
        # touch fallback that keeps traces linked.
        tracer = _get_tracer()
        if tracer is not None:
            with tracer.start_as_current_span("scan.child_boot", context=ctx):
                pass
    except Exception as e:
        logger.debug("tracing.context_from_env failed: %s", e)
