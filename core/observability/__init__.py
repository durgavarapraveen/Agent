"""Observability primitives — metrics, tracing, and structured logging.

All three modules are graceful no-ops when their optional dependencies are
not installed. Enabling them is a matter of installing the extra:

    pip install prometheus-client              # for metrics
    pip install opentelemetry-sdk opentelemetry-api  # for tracing

Import surface:

    from core.observability import metrics, tracing, logging as ag_logging
    metrics.SCAN_DURATION.observe(elapsed)
    with tracing.span("phase.recon", scan_id=sid): ...
    ag_logging.configure_root(json=True, level="INFO")
"""
from core.observability import metrics, tracing
from core.observability import logging_setup as logging  # noqa: F401  (re-export)
