"""Impact validation engine (spec Phase 19/23)."""
import pytest

from core.verification.impact_engine import (
    ImpactLevel as I, assess_impact, gate_finding,
)


def test_open_redirect_param_accepted_is_no_impact():
    lvl, _ = assess_impact({"type": "Open Redirect",
                            "title": "Open Redirect via callbackUrl",
                            "proof": "callbackUrl parameter accepted, HTTP 200"})
    assert lvl == I.NO_IMPACT_PROVEN


def test_open_redirect_offsite_after_auth_is_resource_access():
    lvl, _ = assess_impact({"type": "Open Redirect",
                            "redirect_occurred": True, "external_redirect": True,
                            "post_auth": True})
    assert lvl == I.RESOURCE_ACCESS_PROVEN


def test_info_disclosure_nonsecret_is_no_impact():
    lvl, _ = assess_impact({"type": "Information Disclosure",
                            "title": "Widget JavaScript architecture visible",
                            "proof": "internal component names in JS bundle"})
    assert lvl == I.NO_IMPACT_PROVEN


def test_info_disclosure_secret_is_sensitive_data():
    lvl, _ = assess_impact({"type": "Information Disclosure",
                            "proof": "response contained AKIAABCDEFGHIJKLMNOP"})
    assert lvl == I.SENSITIVE_DATA_ACCESS_PROVEN


def test_jwt_in_evidence_is_sensitive_data():
    lvl, _ = assess_impact({"type": "Info Disclosure",
                            "response_body": "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                                             "eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4"})
    assert lvl == I.SENSITIVE_DATA_ACCESS_PROVEN


def test_idor_with_data_access_is_resource_access():
    lvl, _ = assess_impact({"type": "IDOR", "other_user_data": True,
                            "proof": "returned another user's record"})
    assert lvl == I.RESOURCE_ACCESS_PROVEN


def test_authz_cross_identity_is_privilege():
    lvl, _ = assess_impact({"type": "Broken Access Control",
                            "cross_identity_access": True})
    assert lvl == I.PRIVILEGE_PROVEN


def test_gate_caps_noisy_no_impact_at_suspected():
    f = {"type": "Open Redirect", "title": "Open Redirect via callbackUrl",
         "proof": "param accepted", "status": "CONFIRMED"}  # scanner claimed confirmed
    gate_finding(f)
    assert f["impact_level"] == "NO_IMPACT_PROVEN"
    assert f["lifecycle"] == "SUSPECTED"        # capped, not VALIDATED
    assert f.get("confidence_label") == "INCONCLUSIVE"


def test_gate_advances_proven_impact_to_impact_confirmed():
    f = {"type": "IDOR", "other_user_data": True, "status": "VALIDATED"}
    gate_finding(f)
    assert f["impact_level"] == "RESOURCE_ACCESS_PROVEN"
    assert f["lifecycle"] == "IMPACT_CONFIRMED"


def test_ctx_add_vulnerability_caps_noisy_finding():
    from core.memory.shared_context import SharedContextV2
    ctx = SharedContextV2(target="https://x/")
    ctx.add_vulnerability({"type": "Open Redirect", "title": "open redirect",
                           "location": "https://x/go?callbackUrl=y",
                           "parameter": "callbackUrl",
                           "proof": "parameter accepted", "status": "CONFIRMED"})
    assert ctx.vulnerabilities[0]["lifecycle"] == "SUSPECTED"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
