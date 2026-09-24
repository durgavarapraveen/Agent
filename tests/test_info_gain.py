"""Information-gain action selection (spec Phase 10/12)."""
import pytest

from core.orchestration.info_gain import (
    generate_candidates, rank_candidates, select_next, expected_info_gain,
    build_state_from_ctx, priority_actions_hint, ActionCandidate,
)
from core.orchestration.action_ledger import (
    get_ledger, reset_ledger, action_fingerprint,
)


def _state():
    return {"parameters": [
        {"name": "id", "endpoint": "https://a/u", "auth_context": "alice",
         "tested_classes": []},
        {"name": "q", "endpoint": "https://a/s", "tested_classes": ["xss"]},
    ]}


def test_generates_relevant_untested_candidates():
    cands = generate_candidates(_state())
    ops = {(c.params["parameter"], c.payload_class) for c in cands}
    assert ("id", "idor") in ops and ("id", "sqli") in ops  # id-like → idor/sqli
    assert ("q", "xss") not in ops                          # already tested
    assert ("q", "sqli") in ops


def test_ranking_prefers_novel_high_value():
    ranked = rank_candidates(_state(), session_id="ig1", limit=10)
    assert ranked
    # id param is behind auth → higher target_value; idor/sqli high class_value
    top = ranked[0]
    assert top.params["parameter"] == "id"
    assert top.factors["novelty"] == 1.0


def test_already_tried_action_drops_out():
    reset_ledger("ig2")
    state = {"parameters": [{"name": "id", "endpoint": "https://a/u",
                             "tested_classes": []}]}
    # Mark the idor probe on id as already conclusively tried.
    fp = action_fingerprint("http", "idor", "https://a/u",
                            {"parameter": "id", "method": "GET",
                             "_payload_class": "idor", "identity": ""})
    led = get_ledger("ig2")
    led.claim(fp)
    led.record(fp, "success")
    ranked = rank_candidates(state, session_id="ig2", limit=10)
    assert all(not (c.params["parameter"] == "id" and c.payload_class == "idor")
               for c in ranked), "conclusively-tried action should have lower/zero novelty"
    # its novelty must be 0
    scored = {(_c.payload_class): _c for _c in
              [expected_info_gain(c, state, "ig2") for c in generate_candidates(state)]}
    assert scored["idor"].factors["novelty"] == 0.0


def test_select_next_returns_top():
    reset_ledger("ig3")
    c = select_next(_state(), session_id="ig3")
    assert isinstance(c, ActionCandidate) and c.score > 0


def test_empty_state_no_candidates():
    assert rank_candidates({"parameters": []}) == []
    assert select_next({"parameters": []}) is None


def test_build_state_from_ctx_tolerant():
    class Ctx:
        parameters = [{"name": "id", "endpoint": "https://a/u"}]
        endpoints = {"GET:https://a/u": 1}
        vulnerabilities = []
    st = build_state_from_ctx(Ctx())
    assert st["parameters"] and st["parameters"][0]["name"] == "id"
    assert st["endpoints"] == ["GET:https://a/u"]


def test_priority_hint_text_shape():
    class Ctx:
        parameters = [{"name": "id", "endpoint": "https://a/u", "auth_context": "alice"}]
        endpoints = {}
        vulnerabilities = []
    hint = priority_actions_hint(Ctx(), session_id="ig4", top=3)
    assert "HIGH-VALUE NEXT ACTIONS" in hint and "param=id" in hint


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
