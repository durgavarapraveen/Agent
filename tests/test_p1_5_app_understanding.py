"""Phase 1.5 — LLM semantic application understanding."""
from __future__ import annotations

from core.intelligence.app_understanding import (
    AppSignals,
    AppUnderstandingEngine,
)


class _FakeLLM:
    def __init__(self, payload):
        self.payload = payload
        self.calls = 0

    async def generate_json(self, prompt, system=None, max_tokens=2048,
                            mandatory_fields=None, tier=None):
        self.calls += 1
        return self.payload


def _ecommerce_signals():
    return AppSignals(
        ui_text="Add to cart and proceed to checkout with your coupon",
        form_labels=["Card Number", "CVV", "Shipping Address", "Email"],
        api_fields=["price", "quantity", "coupon", "sku"],
        endpoints=["https://shop.test/api/cart", "https://shop.test/api/checkout"],
    )


def test_heuristic_detects_ecommerce():
    eng = AppUnderstandingEngine()
    u = eng.heuristic(_ecommerce_signals())
    assert u.business_domain == "ecommerce"
    assert u.domain_confidence > 0
    assert u.source == "heuristic"
    assert any(h.capability == "ecommerce" for h in u.hypotheses)


def test_heuristic_detects_healthcare_and_sensitivity():
    sig = AppSignals(
        ui_text="View patient diagnosis and prescription; book appointment with provider",
        form_labels=["Patient SSN", "Email", "Diagnosis"],
        api_fields=["patient_id", "diagnosis", "ssn", "email"],
    )
    u = AppUnderstandingEngine().heuristic(sig)
    assert u.business_domain == "healthcare"
    # Sensitivity classification picks up PII + health fields
    classes = set(u.data_sensitivity.values())
    assert "pii" in classes
    assert "health" in classes


async def test_analyze_uses_llm_when_available():
    payload = {
        "business_domain": "fintech",
        "domain_confidence": 0.9,
        "data_sensitivity": {"iban": "financial"},
        "business_rules": ["No negative transfers"],
        "hypotheses": [
            {"title": "Transfers reject negative amounts", "rationale": "money",
             "capability": "business_logic", "target_hint": "/api/transfer"},
        ],
    }
    eng = AppUnderstandingEngine(llm=_FakeLLM(payload))
    u = await eng.analyze(_ecommerce_signals())
    assert u.source == "llm"
    assert u.business_domain == "fintech"
    assert u.hypotheses[0].capability == "business_logic"


async def test_analyze_falls_back_to_heuristic_on_empty_llm():
    eng = AppUnderstandingEngine(llm=_FakeLLM({}))  # LLM returns nothing usable
    u = await eng.analyze(_ecommerce_signals())
    assert u.source == "heuristic"
    assert u.business_domain == "ecommerce"


async def test_analyze_sanitizes_bad_capability():
    payload = {"business_domain": "x", "hypotheses": [
        {"title": "t", "capability": "totally_made_up"}]}
    u = await AppUnderstandingEngine(llm=_FakeLLM(payload)).analyze(_ecommerce_signals())
    assert u.hypotheses[0].capability == "business_logic"  # coerced to a valid capability


def test_to_test_specs():
    eng = AppUnderstandingEngine()
    u = eng.heuristic(_ecommerce_signals())
    specs = eng.to_test_specs(u, base_endpoints=["https://shop.test/api/cart"])
    assert specs
    caps = {s["capability"] for s in specs}
    assert "ecommerce" in caps
    assert all("hypothesis" in s and "capability" in s for s in specs)
    assert specs[0]["target_endpoints"] == ["https://shop.test/api/cart"]


def test_signals_from_context():
    class Ctx:
        endpoints = [{"url": "https://shop.test/api/cart", "params": "price,quantity"}]
        crawled_text = "checkout"
        form_labels = ["Email"]
        error_messages = ["Invalid coupon"]
    sig = AppSignals.from_context(Ctx())
    assert "https://shop.test/api/cart" in sig.endpoints
    assert "price,quantity" in sig.api_fields
