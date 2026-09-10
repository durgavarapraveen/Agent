from __future__ import annotations

try:
    from prometheus_client import (  # type: ignore
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

# ── SLO metrics (reliability + security) ─────────────────────────────
POLICY_DECISIONS = _counter(
    "antigravity_policy_decisions_total",
    "Policy engine decisions, labeled by verdict (allow/deny) and action type.",
    labelnames=("verdict", "action"),
)
POLICY_DECISION_LATENCY = _histogram(
    "antigravity_policy_decision_duration_seconds",
    "Latency of policy engine evaluation.",
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0),
)
EVIDENCE_INTEGRITY_CHECKS = _counter(
    "antigravity_evidence_integrity_checks_total",
    "Evidence graph integrity verifications, labeled by result.",
    labelnames=("result",),
)
SECRET_OPERATIONS = _counter(
    "antigravity_secret_operations_total",
    "Secret lifecycle operations (store, retrieve, rotate, expire, delete).",
    labelnames=("operation", "category"),
)
TENANT_BOUNDARY_VIOLATIONS = _counter(
    "antigravity_tenant_boundary_violations_total",
    "Attempted cross-tenant data access. Should always be 0.",
)
EXPERIMENT_RECONSTRUCTION_SUCCESS = _counter(
    "antigravity_experiment_reconstructions_total",
    "End-to-end experiment reconstructions, labeled by success/failure.",
    labelnames=("result",),
)
REDACTION_EVENTS = _counter(
    "antigravity_redaction_events_total",
    "Secret redaction events across logs, evidence, and reports.",
    labelnames=("source",),
)


def render() -> tuple[bytes, str]:
    if not _AVAILABLE:
        return b"# prometheus_client not installed\n", "text/plain"
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


def is_available() -> bool:
    return _AVAILABLE
