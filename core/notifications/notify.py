"""Fan-out notifier for Slack / PagerDuty / SIEM / generic webhook.

Every send:
  - Runs with a 5-second HTTP timeout — a slow provider can't stall callers.
  - Redacts PII / secrets via `core.reporting.reporting.mask_sensitive_data`
    before the payload leaves the process.
  - Swallows and logs its own failures — a broken notifier never blocks a scan.

Designed to be called from both async and sync contexts.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any, Dict, Iterable, Optional

import httpx

logger = logging.getLogger(__name__)


_HTTP_TIMEOUT = 5.0


def _mask(text: str) -> str:
    try:
        from core.reporting.reporting import mask_sensitive_data
        return mask_sensitive_data(text or "", enabled=True)
    except Exception:
        return text or ""


def _post_json(url: str, payload: Dict[str, Any], headers: Optional[Dict] = None) -> None:
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT) as c:
            r = c.post(url, json=payload, headers=headers or {})
            if r.status_code >= 400:
                logger.warning("Notifier %s returned %d: %s", url, r.status_code, r.text[:200])
    except Exception as e:
        logger.warning("Notifier post to %s failed: %s", url, e)


def _fanout_async(fns: Iterable) -> None:
    """Fire every function in its own daemon thread so caller returns fast."""
    for fn in fns:
        t = threading.Thread(target=fn, daemon=True)
        t.start()


# ── Backend adapters ───────────────────────────────────────────────────

def _slack(title: str, body: str, severity: str = "info") -> None:
    url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not url:
        return
    color = {
        "critical": "#dc2626", "high": "#ea580c", "medium": "#f59e0b",
        "low": "#0ea5e9", "info": "#64748b",
    }.get(severity.lower(), "#64748b")
    payload = {
        "attachments": [{
            "color": color,
            "title": _mask(title)[:150],
            "text": _mask(body)[:2000],
            "footer": "AntiGravity",
        }]
    }
    _post_json(url, payload)


def _pagerduty(title: str, body: str, severity: str, dedup_key: str) -> None:
    key = os.environ.get("PAGERDUTY_ROUTING_KEY", "").strip()
    if not key:
        return
    # Only page for critical + high.
    if severity.lower() not in ("critical", "high"):
        return
    payload = {
        "routing_key": key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": _mask(title)[:1024],
            "severity": "critical" if severity.lower() == "critical" else "error",
            "source": "antigravity",
            "custom_details": {"body": _mask(body)[:2000]},
        },
    }
    _post_json("https://events.pagerduty.com/v2/enqueue", payload)


def _siem(kind: str, payload: Dict[str, Any]) -> None:
    url = os.environ.get("SIEM_HTTP_URL", "").strip()
    if not url:
        return
    token = os.environ.get("SIEM_HTTP_TOKEN", "").strip()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    envelope = {
        "source": "antigravity",
        "kind": kind,
        "payload": json.loads(_mask(json.dumps(payload, default=str))),
    }
    _post_json(url, envelope, headers=headers)


def _generic(kind: str, payload: Dict[str, Any]) -> None:
    url = os.environ.get("NOTIFIER_GENERIC_WEBHOOK", "").strip()
    if not url:
        return
    envelope = {
        "source": "antigravity",
        "kind": kind,
        "payload": json.loads(_mask(json.dumps(payload, default=str))),
    }
    _post_json(url, envelope)


# ── Public helpers ─────────────────────────────────────────────────────

def notify_scan_finished(scan_id: str, target: str,
                          findings_by_severity: Dict[str, int],
                          duration_s: float) -> None:
    title = f"Scan {scan_id} finished on {target}"
    lines = [f"{s}: {n}" for s, n in findings_by_severity.items() if n]
    body = f"Duration: {duration_s:.0f}s\n" + "\n".join(lines) if lines else f"Duration: {duration_s:.0f}s\n(no findings)"
    _fanout_async([
        lambda: _slack(title, body, "info"),
        lambda: _siem("scan_finished", {"scan_id": scan_id, "target": target,
                                         "counts": findings_by_severity,
                                         "duration_s": duration_s}),
        lambda: _generic("scan_finished", {"scan_id": scan_id, "target": target,
                                            "counts": findings_by_severity}),
    ])


def notify_critical_finding(scan_id: str, finding: Dict[str, Any]) -> None:
    severity = str(finding.get("severity", "high")).lower()
    title = f"[{severity.upper()}] {finding.get('title') or finding.get('type', 'Finding')}"
    body = (
        f"Scan: {scan_id}\n"
        f"Target: {finding.get('target') or finding.get('location', 'unknown')}\n"
        f"Type: {finding.get('type', '?')}\n"
        f"Confidence: {finding.get('confidence_score', '?')}\n"
        f"Details: {(finding.get('details') or '')[:400]}"
    )
    dedup_key = str(finding.get("finding_id") or f"{scan_id}:{finding.get('title')}")
    _fanout_async([
        lambda: _slack(title, body, severity),
        lambda: _pagerduty(title, body, severity, dedup_key),
        lambda: _siem("finding", {"scan_id": scan_id, "finding": finding}),
        lambda: _generic("finding", {"scan_id": scan_id, "finding": finding}),
    ])


def notify_exploit_authorized(scan_id: str, target: str, technique: str) -> None:
    title = f"Exploit authorized on {target}"
    body = f"Scan: {scan_id}\nTechnique: {technique}"
    _fanout_async([
        lambda: _slack(title, body, "high"),
        lambda: _siem("exploit_authorized", {"scan_id": scan_id, "target": target,
                                              "technique": technique}),
        lambda: _generic("exploit_authorized", {"scan_id": scan_id, "target": target,
                                                 "technique": technique}),
    ])


def notify_platform_error(component: str, error: str, scan_id: str = "") -> None:
    title = f"[PLATFORM] {component} error"
    body = f"Scan: {scan_id}\nError: {error}"
    _fanout_async([
        lambda: _slack(title, body, "high"),
        lambda: _pagerduty(title, body, "critical", f"platform:{component}"),
        lambda: _siem("platform_error", {"component": component, "error": error,
                                          "scan_id": scan_id}),
    ])
