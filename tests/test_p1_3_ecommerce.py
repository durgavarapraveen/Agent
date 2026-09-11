"""Phase 1.3 — e-commerce tampering executor."""
from __future__ import annotations

import json

from core.execution.executors.ecommerce import (
    coupon_bruteforce_probe,
    coupon_stacking_probe,
    detect_ecommerce_endpoints,
    is_coupon_endpoint,
    is_payment_callback,
    payment_callback_replay_probe,
)
from core.exploitation.workflow_interceptor import (
    ReplayResponse,
    WorkflowInterceptor,
    classify_param,
)


def test_endpoint_detection():
    urls = ["https://shop.test/api/cart", "https://shop.test/about",
            "https://shop.test/checkout", "https://shop.test/api/coupon",
            "https://shop.test/payment/callback"]
    ec = detect_ecommerce_endpoints(urls)
    assert "https://shop.test/api/cart" in ec
    assert "https://shop.test/about" not in ec
    assert is_coupon_endpoint("https://shop.test/api/coupon")
    assert not is_coupon_endpoint("https://shop.test/api/cart")
    assert is_payment_callback("https://shop.test/payment/callback")
    assert not is_payment_callback("https://shop.test/about")


def test_currency_mutation_via_interceptor():
    assert classify_param("currency", "USD") == "currency"
    req = {"method": "POST", "url": "https://shop.test/api/cart",
           "post_data": json.dumps({"currency": "USD", "price": 10}), "headers": {}}
    muts = WorkflowInterceptor(replayer=lambda r: ReplayResponse(200)).generate_param_mutations(req)
    assert "currency_change" in {m.strategy for m in muts}


def test_coupon_stacking_vulnerable_and_secure():
    # Vulnerable: every application accepted.
    assert coupon_stacking_probe("https://shop.test/coupon",
                                 lambda r: ReplayResponse(200)) is not None
    # Secure: only the first application succeeds, the rest are rejected.
    state = {"n": 0}

    def secure(req):
        state["n"] += 1
        return ReplayResponse(200) if state["n"] == 1 else ReplayResponse(409, "already applied")

    assert coupon_stacking_probe("https://shop.test/coupon", secure) is None


def test_coupon_bruteforce_finds_valid_code():
    def replayer(req):
        body = req.get("post_data", "")
        if "SAVE10" in body:
            return ReplayResponse(200, body="discount applied: 10%")
        return ReplayResponse(200, body="invalid coupon")  # same status, different body

    found = coupon_bruteforce_probe("https://shop.test/coupon", replayer, candidates=("SAVE10", "NOPE"))
    assert found and "SAVE10" in found[0]["valid_coupons"]
    assert "NOPE" not in found[0]["valid_coupons"]


def test_payment_callback_replay():
    assert payment_callback_replay_probe("https://shop.test/pay/callback",
                                         lambda r: ReplayResponse(200, "ok"))["severity"] == "critical"
    assert payment_callback_replay_probe("https://shop.test/pay/callback",
                                         lambda r: ReplayResponse(403, "denied")) is None


def test_ecommerce_executor_end_to_end(monkeypatch):
    from core.domain.experiment import SecurityExperiment
    from core.execution.executors.ecommerce import EcommerceExecutor

    ex = EcommerceExecutor()
    # Vulnerable storefront: accepts everything.
    monkeypatch.setattr(ex, "_probe", lambda url, method="GET", headers=None, data=None: (200, "ok", {}))

    exp = SecurityExperiment(
        hypothesis_id="h", endpoint_id="https://shop.test", capability="ecommerce",
        input_parameters={
            "url": "https://shop.test",
            "endpoints": [
                {"url": "https://shop.test/api/cart"},
                {"url": "https://shop.test/api/coupon"},
                {"url": "https://shop.test/payment/callback"},
            ],
        },
    )
    result = ex.execute(exp)
    findings = result.evidence.get("ecommerce_findings", [])
    tests = {f.get("test") for f in findings}
    assert "coupon_stacking" in tests
    assert "payment_callback_replay" in tests
    assert "business_logic" in tests  # interceptor tamper findings
