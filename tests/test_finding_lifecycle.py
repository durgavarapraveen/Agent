"""Canonical finding lifecycle (spec Phase 6)."""
import pytest

from core.domain.finding_lifecycle import (
    FindingLifecycle as L, can_transition, advance, from_legacy,
    to_legacy_state, infer_lifecycle, set_lifecycle,
)


def test_forward_transitions_allowed():
    assert can_transition(L.OBSERVED, L.SUSPECTED)
    assert can_transition(L.VALIDATED, L.EXPLOITED)
    assert can_transition(L.OBSERVED, L.VALIDATED)  # skips allowed (scanner jump)


def test_backward_transitions_blocked():
    assert not can_transition(L.EXPLOITED, L.VALIDATED)
    assert not can_transition(L.VALIDATED, L.OBSERVED)


def test_reject_from_any_nonterminal_then_terminal():
    assert can_transition(L.SUSPECTED, L.REJECTED)
    assert can_transition(L.VALIDATED, L.REJECTED)
    assert not can_transition(L.REJECTED, L.VALIDATED)   # terminal
    assert not can_transition(L.IMPACT_CONFIRMED, L.EXPLOITED)  # terminal


def test_advance_keeps_current_when_disallowed():
    assert advance(L.EXPLOITED, L.OBSERVED) == L.EXPLOITED
    assert advance(L.OBSERVED, L.EXPLOITED) == L.EXPLOITED


def test_legacy_mapping_both_vocabularies():
    assert from_legacy("CANDIDATE") == L.SUSPECTED
    assert from_legacy("VALIDATING") == L.REPRODUCED
    assert from_legacy("CONFIRMED") == L.VALIDATED
    assert from_legacy("MITIGATED") == L.VALIDATED
    assert from_legacy(None) == L.OBSERVED
    assert to_legacy_state(L.EXPLOITED) == "VALIDATED"
    assert to_legacy_state(L.REJECTED) == "REJECTED"
    assert to_legacy_state(L.SUSPECTED) == "CANDIDATE"


def test_infer_from_dict_signals():
    assert infer_lifecycle({"impact_confirmed": True}) == L.IMPACT_CONFIRMED
    assert infer_lifecycle({"exploited": True}) == L.EXPLOITED
    assert infer_lifecycle({"status": "CONFIRMED"}) == L.VALIDATED
    assert infer_lifecycle({"evidence": [{"x": 1}]}) == L.VALIDATED
    assert infer_lifecycle({}) == L.OBSERVED
    assert infer_lifecycle({"lifecycle": "REPRODUCED"}) == L.REPRODUCED


def test_set_lifecycle_guards_and_stamps_legacy():
    f = {"status": "CONFIRMED"}       # → VALIDATED
    new, changed = set_lifecycle(f, L.EXPLOITED)
    assert new == L.EXPLOITED and changed
    assert f["lifecycle"] == "EXPLOITED" and f["finding_state"] == "VALIDATED"
    # cannot regress
    new2, changed2 = set_lifecycle(f, L.OBSERVED)
    assert new2 == L.EXPLOITED and not changed2


def test_ctx_add_vulnerability_stamps_lifecycle():
    from core.memory.shared_context import SharedContextV2
    ctx = SharedContextV2(target="https://x/")
    ctx.add_vulnerability({"type": "XSS", "title": "reflected xss",
                           "location": "https://x/s?q=1", "exploited": True})
    assert ctx.vulnerabilities[0]["lifecycle"] == "EXPLOITED"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
