"""Phase 1.1 — workflow interception & mutation engine."""
from __future__ import annotations

import json

from core.exploitation.request_capture import CapturedRequest
from core.exploitation.workflow_interceptor import (
    BusinessLogicFinding,
    ReplayResponse,
    WorkflowInterceptor,
    classify_param,
    identify_mutable_params,
)


def test_classify_param_kinds():
    assert classify_param("price", "9.99") == "price"
    assert classify_param("total_amount", 10) == "price"
    assert classify_param("quantity", 2) == "quantity"
    assert classify_param("coupon", "SAVE10") == "discount"
    assert classify_param("order_id", 42) == "id"
    assert classify_param("productId", 7) == "id"
    assert classify_param("csrf_token", "abc") == "token"
    assert classify_param("count", 3) == "quantity"
    assert classify_param("label", "hello") == "string"
    assert classify_param("rating", 5) == "number"


def test_identify_mutable_params_query_and_json():
    req = CapturedRequest(
        method="POST",
        url="https://shop.test/api/cart?ref=123",
        post_data=json.dumps({"price": 19.99, "quantity": 2, "coupon": "X", "note": "hi"}),
        headers={"Content-Type": "application/json"},
    )
    params = identify_mutable_params(req)
    by_name = {p.name: p for p in params}
    assert by_name["ref"].location == "query" and by_name["ref"].kind == "id"
    assert by_name["price"].location == "json" and by_name["price"].kind == "price"
    assert by_name["quantity"].kind == "quantity"
    assert by_name["coupon"].kind == "discount"
    assert by_name["note"].kind == "string"


def test_generate_param_mutations_covers_strategies():
    req = {"method": "POST", "url": "https://shop.test/api/cart",
           "post_data": json.dumps({"price": 20, "quantity": 1, "csrf": "tok"}),
           "headers": {}}
    interceptor = WorkflowInterceptor(replayer=lambda r: ReplayResponse(200))
    muts = interceptor.generate_param_mutations(req)
    strategies = {m.strategy for m in muts}
    assert "zero_price" in strategies
    assert "negative_price" in strategies
    assert "overflow" in strategies
    assert "negative_quantity" in strategies
    assert "drop_token" in strategies  # csrf token → drop mutation


def _vulnerable_replayer(request):
    """Accepts everything with 200 — models an app with no server-side checks."""
    return ReplayResponse(200, body="ok")


def _secure_replayer(request):
    """Rejects tampered values: negative/zero price or quantity, over-discounts,
    missing csrf token → 400; otherwise 200."""
    body = request.get("post_data", "") or ""
    try:
        data = json.loads(body)
    except Exception:
        data = {}
    if isinstance(data, dict):
        if "csrf" not in data and request.get("method") != "GET":
            return ReplayResponse(403, body="missing csrf")
        for k in ("price", "amount", "total"):
            if k in data and float(data[k]) <= 0:
                return ReplayResponse(400, body="invalid price")
        for k in ("quantity", "count"):
            if k in data and float(data[k]) <= 0:
                return ReplayResponse(400, body="invalid quantity")
        if "discount" in data and float(data["discount"]) > 50:
            return ReplayResponse(400, body="invalid discount")
    return ReplayResponse(200, body="ok")


def _checkout_sequence():
    return [
        CapturedRequest(method="GET", url="https://shop.test/product/1"),
        CapturedRequest(
            method="POST", url="https://shop.test/api/cart",
            post_data=json.dumps({"price": 19.99, "quantity": 2, "csrf": "t"}),
            headers={"Content-Type": "application/json"}),
        CapturedRequest(
            method="POST", url="https://shop.test/api/checkout",
            post_data=json.dumps({"discount": 10, "csrf": "t"}),
            headers={"Content-Type": "application/json"}),
    ]


def test_analyze_flags_vulnerable_app():
    interceptor = WorkflowInterceptor(replayer=_vulnerable_replayer)
    findings = interceptor.analyze(_checkout_sequence())
    assert findings, "vulnerable app should yield business-logic findings"
    assert all(isinstance(f, BusinessLogicFinding) for f in findings)
    strategies = {f.strategy for f in findings}
    # zeroing/negating price and over-applying a discount all accepted → flagged
    assert "zero_price" in strategies
    assert "negative_price" in strategies
    assert {"max_discount", "over_discount"} & strategies


def test_analyze_clean_on_secure_app():
    interceptor = WorkflowInterceptor(replayer=_secure_replayer)
    findings = interceptor.analyze(_checkout_sequence())
    # The secure app rejects every tampered value, so no high-signal finding for
    # price/quantity/discount tampering should remain.
    bad = [f for f in findings if f.strategy in (
        "zero_price", "negative_price", "negative_quantity",
        "max_discount", "over_discount", "drop_token")]
    assert not bad, f"secure app should reject tampering, got: {[f.strategy for f in bad]}"


def test_replayer_exception_does_not_crash():
    def boom(request):
        raise RuntimeError("network down")

    interceptor = WorkflowInterceptor(replayer=boom)
    # Should complete without raising; a status-0 baseline yields no findings.
    assert interceptor.analyze(_checkout_sequence()) == []


def test_sequence_mutation_duplicate_step():
    interceptor = WorkflowInterceptor(replayer=_vulnerable_replayer)
    muts = interceptor.generate_sequence_mutations(_checkout_sequence())
    assert any(m.strategy == "duplicate_step" for m in muts)


def test_business_logic_executor_uses_interceptor(monkeypatch):
    """BusinessLogicExecutor.execute drives the interceptor over captured
    requests and reports tamper findings (no live target — _probe mocked)."""
    from core.domain.experiment import SecurityExperiment
    from core.execution.executors.generic import BusinessLogicExecutor

    ex = BusinessLogicExecutor()

    # Simulate a vulnerable app: every request (incl. tampered) returns 200.
    monkeypatch.setattr(ex, "_probe", lambda url, method="GET", headers=None, data=None: (200, "ok", {}))

    captured = [
        {"method": "POST", "url": "https://shop.test/api/cart",
         "post_data": json.dumps({"price": 19.99, "quantity": 2, "csrf": "t"}),
         "headers": {"Content-Type": "application/json"}},
    ]
    exp = SecurityExperiment(
        hypothesis_id="h1", endpoint_id="https://shop.test/api/cart",
        capability="business_logic",
        input_parameters={"url": "https://shop.test/api/cart", "captured_requests": captured},
    )
    result = ex.execute(exp)
    logic = result.evidence.get("logic_findings", [])
    strategies = {f.get("strategy") for f in logic if f.get("test") == "business_logic"}
    assert strategies, "executor should surface interceptor findings"
    assert {"zero_price", "negative_price"} & strategies
