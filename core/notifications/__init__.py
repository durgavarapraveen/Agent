"""Pluggable notifier sinks — Slack, PagerDuty, SIEM, webhook.

Only stdlib + httpx are hard dependencies. Every backend is opt-in by env var:

    SLACK_WEBHOOK_URL         — Slack incoming webhook URL
    PAGERDUTY_ROUTING_KEY     — Events API v2 routing key
    SIEM_HTTP_URL             — generic HTTP receiver (Splunk HEC / Elastic / ...)
    SIEM_HTTP_TOKEN           — bearer token for SIEM_HTTP_URL
    NOTIFIER_GENERIC_WEBHOOK  — user-supplied catchall URL

Usage:

    from core.notifications import notify
    notify.scan_finished(scan_id, target, findings_by_severity)
    notify.critical_finding(scan_id, finding_dict)
    notify.exploit_authorized(scan_id, target, technique)

Each `notify.*` helper fans out to every configured backend in parallel and
returns synchronously — a slow provider CANNOT stall the caller because the
HTTP call is bounded by a 5-second timeout.
"""
from core.notifications.notify import (  # noqa: F401
    notify_scan_finished,
    notify_critical_finding,
    notify_exploit_authorized,
    notify_platform_error,
)
