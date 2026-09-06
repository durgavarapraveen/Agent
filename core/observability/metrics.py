"""Prometheus metrics.

Zero hard dependency on `prometheus_client`. When it's installed, every
recorded metric is a real Prometheus object; when it isn't, every operation
is a no-op (still safe to call). The `/api/metrics` endpoint in `ui/api/server.py`
returns the exposition format when available, or 501 otherwise.
"""
from __future__ import annotations

try:
    from prometheus_client import (
        Counter, Gauge, Histogram, CollectorRegistry, REGISTRY,
        generate_latest, CONTENT_TYPE_LATEST,
    )
    _AVAILABLE = True
except ImportError:  # pragma: no cover
    _AVAILABLE = False
    Counter = Gauge = Histogram = CollectorRegistry = None  # type: ignore
    REGISTRY = None
    CONTENT_TYPE_LATEST = "text/plain"

    def generate_latest(*_a, **_kw) -> bytes:  # type: ignore
        return b""


class _Noop:
    """Duck-typed replacement for Counter/Gauge/Histogram when
    prometheus_client is missing. All operations are silent no-ops."""

    def __init__(self, *a, **kw): pass
    def labels(self, *a, **kw): return self
    def inc(self, *a, **kw): pass
    def dec(self, *a, **kw): pass
    def set(self, *a, **kw): pass
    def observe(self, *a, **kw): pass
    def time(self):
        class _CM:
            def __enter__(self): return self
            def __exit__(self, *a): return False
        return _CM()


def _counter(name, doc, labelnames=()):
    if _AVAILABLE:
        return Counter(name, doc, labelnames=labelnames)
    return _Noop()


def _gauge(name, doc, labelnames=()):
    if _AVAILABLE:
        return Gauge(name, doc, labelnames=labelnames)
    return _Noop()


def _histogram(name, doc, labelnames=(), buckets=None):
    if _AVAILABLE:
        return Histogram(name, doc, labelnames=labelnames,
                          buckets=buckets or Histogram.DEFAULT_BUCKETS)
    return _Noop()


# ── Metric definitions ────────────────────────────────────────────────
# Names follow the Prometheus convention: `<namespace>_<subsystem>_<name>_<unit>`.

SCAN_STARTED = _counter(
    "antigravity_scans_started_total",
    "Total number of scans started, labeled by tier.",
    labelnames=("tier",),
)
SCAN_FINISHED = _counter(
    "antigravity_scans_finished_total",
    "Total number of scans that finished, labeled by tier and terminal status.",
    labelnames=("tier", "status"),
)
SCAN_ACTIVE = _gauge(
    "antigravity_scans_active",
    "Current count of running/starting/stopping scans.",
)
SCAN_DURATION_SECONDS = _histogram(
    "antigravity_scan_duration_seconds",
    "Wall-clock duration of completed scans.",
    labelnames=("tier",),
    buckets=(30, 60, 120, 300, 600, 1200, 3600, 7200, 14400),
)

FINDING_INGESTED = _counter(
    "antigravity_findings_ingested_total",
    "Findings persisted to the vulnerabilities table.",
    labelnames=("severity", "type"),
)

LLM_REQUEST = _counter(
    "antigravity_llm_requests_total",
    "LLM API requests, labeled by provider and status.",
    labelnames=("provider", "status"),
)
LLM_REQUEST_DURATION_SECONDS = _histogram(
    "antigravity_llm_request_duration_seconds",
    "LLM API request round-trip duration.",
    labelnames=("provider",),
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 180),
)
LLM_TOKENS = _counter(
    "antigravity_llm_tokens_total",
    "LLM tokens consumed, labeled by provider and direction.",
    labelnames=("provider", "direction"),
)

TOOL_INVOCATION = _counter(
    "antigravity_tool_invocations_total",
    "External tool invocations, labeled by tool and terminal status.",
    labelnames=("tool", "status"),
)
TOOL_INVOCATION_DURATION_SECONDS = _histogram(
    "antigravity_tool_invocation_duration_seconds",
    "External tool wall-clock duration.",
    labelnames=("tool",),
    buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1200),
)

DB_POOL_CONNECTIONS_IN_USE = _gauge(
    "antigravity_db_pool_connections_in_use",
    "Currently borrowed connections from the DB pool.",
)
DB_POOL_ERRORS = _counter(
    "antigravity_db_pool_errors_total",
    "DB pool errors, labeled by kind (e.g. poisoning, exhausted).",
    labelnames=("kind",),
)

WS_CLIENTS = _gauge(
    "antigravity_ws_clients",
    "Currently connected WebSocket clients for live scan feed.",
)

HTTP_REQUEST = _counter(
    "antigravity_http_requests_total",
    "HTTP requests to the API, labeled by method, route, and status class.",
    labelnames=("method", "route", "status_class"),
)


def render() -> tuple[bytes, str]:
    """Return `(body_bytes, content_type)` for the `/api/metrics` endpoint."""
    if not _AVAILABLE:
        return b"# prometheus_client not installed\n", "text/plain"
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


def is_available() -> bool:
    return _AVAILABLE
