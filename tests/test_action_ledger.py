"""Action fingerprint + duplicate-action ledger (spec Phase 11)."""
import pytest

from core.orchestration.action_ledger import (
    ActionLedger, action_fingerprint, payload_class, get_ledger, reset_ledger,
)


# ── fingerprint ────────────────────────────────────────────────────────
def test_same_probe_different_operand_same_fingerprint():
    a = action_fingerprint("sqlmap", "sqli", "https://x/users?id=1",
                           {"id": "1' OR 1=1--", "method": "GET"})
    b = action_fingerprint("sqlmap", "sqli", "https://x/users?id=1",
                           {"id": "9' OR 2=2--", "method": "GET"})
    assert a == b  # operand differs, action identity is the same


def test_fragment_and_query_operand_ignored():
    a = action_fingerprint("http", "get", "https://x/a?id=1#frag", {})
    b = action_fingerprint("http", "get", "https://x/a?id=2", {})
    assert a == b  # query VALUE + fragment don't change the action


def test_distinct_method_param_payloadclass_are_distinct():
    base = ("dalfox", "xss", "https://x/s", {"q": "1"})
    fp = action_fingerprint(*base)
    assert fp != action_fingerprint("dalfox", "xss", "https://x/s",
                                    {"q": "1", "method": "POST"})
    assert fp != action_fingerprint("dalfox", "xss", "https://x/s",
                                    {"other": "1"})  # different param name
    assert fp != action_fingerprint("nuclei", "xss", "https://x/s", {"q": "1"})  # tool


def test_identity_changes_fingerprint():
    a = action_fingerprint("http", "get", "https://x/me", {},
                           audit_context={"identity": "alice"})
    b = action_fingerprint("http", "get", "https://x/me", {},
                           audit_context={"identity": "bob"})
    assert a != b  # same request, different acting identity = distinct action


def test_payload_class_detection():
    assert payload_class("", {"p": "' OR 1=1--"}) == "sqli"
    assert payload_class("", {"p": "<script>alert(1)</script>"}) == "xss"
    assert payload_class("", {"p": "../../etc/passwd"}) == "traversal"
    assert payload_class("scan", {"p": "hello"}) == "generic"


# ── ledger ─────────────────────────────────────────────────────────────
def test_claim_then_duplicate_blocked():
    led = ActionLedger()
    fp = "abc"
    assert led.claim(fp) is True          # first claim wins
    assert led.claim(fp) is False         # concurrent/second claim blocked
    ok, reason = led.should_execute(fp)
    assert ok is False and "duplicate" in reason


def test_conclusive_blocks_reexecution():
    led = ActionLedger()
    led.claim("fp1")
    led.record("fp1", "success")
    ok, reason = led.should_execute("fp1")
    assert ok is False and reason == "already_success"
    assert led.claim("fp1") is False


def test_transient_released_allows_one_retry():
    led = ActionLedger()
    led.claim("fp2")
    led.record("fp2", "timeout")          # transient → released
    ok, reason = led.should_execute("fp2")
    assert ok is True and reason == "new"
    assert led.claim("fp2") is True       # retry allowed


def test_registry_is_per_session():
    reset_ledger("s1")
    reset_ledger("s2")
    l1, l2 = get_ledger("s1"), get_ledger("s2")
    assert l1 is not l2
    l1.claim("x")
    assert l2.claim("x") is True          # independent per session
    assert get_ledger("s1") is l1         # stable within a session


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
