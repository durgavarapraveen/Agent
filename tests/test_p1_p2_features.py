"""Regression tests for P1.2 (AssetRegistry), P1.5 (attack-path correlation),
P2.7 (MutationLedger), P2.8 (LLM redaction)."""
import pytest


# ---- P1.2 AssetRegistry ----------------------------------------------------

def test_asset_origin_preserved_not_rewritten():
    from core.domain.asset_registry import AssetRegistry
    reg = AssetRegistry()
    reg.register("https://preview.example.com/main.js", discovered_by="capture")
    # An absolute ref keeps its origin; a relative ref resolves to the real origin.
    assert reg.resolve("https://preview.example.com/main.js", "http://localhost:3000") \
        == "https://preview.example.com/main.js"
    assert reg.primary_origin() == "https://preview.example.com"
    assert reg.resolve("/chunk.js", reg.primary_origin()) == "https://preview.example.com/chunk.js"


def test_asset_localhost_not_injected_when_real_origin_known():
    from core.domain.asset_registry import AssetRegistry
    reg = AssetRegistry()
    reg.register("https://cdn.example.net/app.bundle.js", discovered_by="capture")
    # Relative ref with no explicit base uses the learned real origin, never localhost.
    out = reg.resolve("/vendor.js", "")
    assert out == "https://cdn.example.net/vendor.js"
    assert "localhost" not in out


def test_asset_dedup_and_js_listing():
    from core.domain.asset_registry import AssetRegistry
    reg = AssetRegistry()
    a = reg.register("https://h/main.js")
    b = reg.register("https://h/main.js")   # same url
    assert a.asset_id == b.asset_id
    assert reg.js_urls() == ["https://h/main.js"]


# ---- P1.5 attack-path correlation -----------------------------------------

def test_confirmed_only_filters_unconfirmed():
    from core.analysis.correlation_engine import CorrelationEngine
    findings = [
        {"type": "SQL_INJECTION", "severity": "CRITICAL", "status": "SUSPECTED",
         "location": "https://h/x"},
    ]
    ce = CorrelationEngine()
    assert ce.correlate(findings, confirmed_only=True) == []
    # Same finding confirmed -> standalone chain appears.
    findings[0]["status"] = "CONFIRMED"
    assert len(ce.correlate(findings, confirmed_only=True)) >= 1


def test_evidence_link_required_prevents_unrelated_merge():
    from core.analysis.correlation_engine import CorrelationEngine
    a = {"type": "INFORMATION_DISCLOSURE", "severity": "HIGH", "confirmed": True,
         "location": "https://h/leak", "proof": "leaked token ABC123XYZ890"}
    b_unrelated = {"type": "AUTHENTICATION_BYPASS", "severity": "CRITICAL",
                   "confirmed": True, "location": "https://h/login",
                   "proof": "no dependency here"}
    ce = CorrelationEngine()
    # Strict: no evidence dependency -> no chain.
    strict = ce.correlate([a, b_unrelated], confirmed_only=True, require_evidence_link=True)
    multi = [c for c in strict if len(c.findings) == 2]
    assert multi == []
    # Now b references a's leaked artifact -> evidence link -> chain forms.
    b_related = dict(b_unrelated, proof="used ABC123XYZ890 to bypass auth")
    strict2 = ce.correlate([a, b_related], confirmed_only=True, require_evidence_link=True)
    assert any(len(c.findings) == 2 and c.evidence_link and c.confirmed for c in strict2)


# ---- P2.7 MutationLedger ---------------------------------------------------

def test_mutation_recorded_from_created_id():
    from core.security.mutation_ledger import MutationLedger
    led = MutationLedger()
    m = led.record("POST", "https://h/api/users", 201,
                   body_text='{"data":{"id":"42","email":"x@y.z"}}',
                   session_id="admin")
    assert m is not None
    assert m.resource_id == "42"
    assert m.resource_url == "https://h/api/users/42"
    assert m.session_id == "admin"


def test_mutation_ignores_non_creating_calls():
    from core.security.mutation_ledger import MutationLedger
    led = MutationLedger()
    assert led.record("GET", "https://h/api/users", 200, body_text='{"id":"1"}') is None
    assert led.record("POST", "https://h/api/users", 400, body_text='{"error":"bad"}') is None
    assert led.record("POST", "https://h/api/users", 201, body_text='no id here') is None
    assert led.entries() == []


def test_mutation_prefers_location_header():
    from core.security.mutation_ledger import MutationLedger
    led = MutationLedger()
    m = led.record("POST", "https://h/api/orders", 201, body_text="{}",
                   headers={"Location": "https://h/api/orders/abc-99"})
    assert m.resource_url == "https://h/api/orders/abc-99"
    assert m.resource_id == "abc-99"


# ---- P2.8 LLM redaction ----------------------------------------------------

def test_redact_masks_bearer_and_email():
    from core.security.llm_redact import redact_for_llm
    out = redact_for_llm("Authorization: Bearer abcDEF123ghiJKL456 and user a@b.com")
    assert "abcDEF123ghiJKL456" not in out
    assert "a@b.com" not in out


def test_redact_messages_shallow_copies():
    from core.security.llm_redact import redact_messages
    msgs = [{"role": "tool", "content": "password=SuperSecret123"}]
    out = redact_messages(msgs)
    assert "SuperSecret123" not in out[0]["content"]
    assert "SuperSecret123" in msgs[0]["content"]   # original untouched


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
