"""Phase 1.2 — workflow state-machine crawler."""
from __future__ import annotations

import json
from types import SimpleNamespace

from core.discovery.workflow_crawler import (
    WorkflowCrawler,
    WorkflowStateMachine,
    WorkflowStep,
    normalize_path,
)


def test_normalize_path_collapses_ids():
    assert normalize_path("https://shop.test/cart/42/item/7") == "/cart/{id}/item/{id}"
    assert normalize_path("/users/550e8400-e29b-41d4-a716-446655440000") == "/users/{id}"
    assert normalize_path("/api/products") == "/api/products"


def _checkout_flow():
    return [
        {"method": "GET", "url": "https://shop.test/product/1"},
        {"method": "POST", "url": "https://shop.test/api/cart",
         "post_data": json.dumps({"product": 1, "quantity": 1})},
        {"method": "GET", "url": "https://shop.test/checkout"},
        {"method": "POST", "url": "https://shop.test/api/checkout",
         "post_data": json.dumps({"pay": True})},
    ]


def test_build_state_machine_and_classification():
    sm = WorkflowCrawler().build_from_requests(_checkout_flow(), name="checkout")
    assert len(sm.steps) == 4
    # 4 transitions from ENTRY through terminal
    assert len(sm.transitions) == 4
    assert sm.transitions[0].src == WorkflowStateMachine.ENTRY
    # The two POSTs are required; the two GETs optional
    req = {t.step_index for t in sm.required_transitions()}
    assert req == {1, 3}
    assert {t.step_index for t in sm.optional_transitions()} == {0, 2}
    assert sm.terminal_index == 3  # last state-changing step


def test_generate_test_cases_covers_kinds():
    sm = WorkflowCrawler().build_from_requests(_checkout_flow())
    cases = WorkflowCrawler().generate_test_cases(sm)
    kinds = {c.kind for c in cases}
    assert "skip_step" in kinds
    assert "direct_access_final" in kinds
    assert "reorder" in kinds
    assert "replay_step" in kinds

    # skip_step for the cart prerequisite (step 1) must omit it but keep terminal.
    skip_cart = [c for c in cases if c.kind == "skip_step" and 1 not in c.step_sequence]
    assert skip_cart and skip_cart[0].target_step == 3
    assert 3 in skip_cart[0].step_sequence

    # direct access hits only the terminal step.
    direct = [c for c in cases if c.kind == "direct_access_final"][0]
    assert direct.step_sequence == [3]


def test_materialize_produces_request_dicts():
    crawler = WorkflowCrawler()
    sm = crawler.build_from_requests(_checkout_flow())
    cases = crawler.generate_test_cases(sm)
    direct = [c for c in cases if c.kind == "direct_access_final"][0]
    reqs = crawler.materialize(direct, sm)
    assert len(reqs) == 1
    assert reqs[0]["url"] == "https://shop.test/api/checkout"
    assert reqs[0]["method"] == "POST"


def test_build_from_captured_groups_by_session():
    # Two sessions interleaved; WorkflowInventory should split them.
    reqs = [
        SimpleNamespace(request_id="a1", session_id="s1", timestamp=1,
                        method="POST", url="https://shop.test/api/cart", cookies={}),
        SimpleNamespace(request_id="b1", session_id="s2", timestamp=1,
                        method="POST", url="https://shop.test/api/login", cookies={}),
        SimpleNamespace(request_id="a2", session_id="s1", timestamp=2,
                        method="POST", url="https://shop.test/api/checkout", cookies={}),
        SimpleNamespace(request_id="b2", session_id="s2", timestamp=2,
                        method="GET", url="https://shop.test/dashboard", cookies={}),
    ]
    machines = WorkflowCrawler().build_from_captured(reqs)
    assert len(machines) == 2
    # Each machine has exactly its session's 2 steps.
    assert all(len(m.steps) == 2 for m in machines)


def test_short_flow_yields_no_test_cases():
    sm = WorkflowCrawler().build_from_requests([{"method": "GET", "url": "https://shop.test/"}])
    assert WorkflowCrawler().generate_test_cases(sm) == []
