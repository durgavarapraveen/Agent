"""Regression corpus for PlannerResponseNormalizer.

The non-native LLM path (claude_cli / deepseek) returns free-form JSON that the
normalizer must coerce into a canonical BrainDecision. LLMs emit many shapes;
each case below is a shape that HAS broken the planner in the past. This file is
the contract — add the offending JSON here whenever a new shape is found.
"""
import pytest

from core.common.normalizer import (
    PlannerResponseNormalizer,
    BrainDecision,
    BrainDecisionAction,
    PlannerSchemaError,
)

norm = PlannerResponseNormalizer.normalize


def _caps(decision: BrainDecision):
    return [str(getattr(t, "capability", "")).lower() for t in (decision.tasks or [])]


# ── Single tool-call shapes (DeepSeek / claude_cli often emit these) ──────────
@pytest.mark.parametrize("action", [
    "execute_capability", "execute_tool", "run_capability",
    "run_tool", "tool_call", "call_tool", "use_tool",
])
def test_single_tool_call_shapes_spawn_agents(action):
    d = norm({"action": action, "tool": "nuclei",
              "parameters": {"target": "https://x"}, "reason": "scan it"})
    assert d.action == BrainDecisionAction.SPAWN_AGENTS
    assert len(d.tasks) >= 1, f"{action} produced no tasks"


def test_singular_tool_infers_capability_not_default():
    # Regression: reading only plural `tools` collapsed everything to
    # technology_fingerprinting; the singular `tool` must be honored.
    d = norm({"action": "execute_capability", "tool": "sqlmap",
              "parameters": {"url": "https://x?id=1"}, "objective": "sqli test"})
    assert d.action == BrainDecisionAction.SPAWN_AGENTS
    assert d.tasks, "no task produced"
    assert "technology_fingerprinting" not in _caps(d)


def test_objective_falls_back_to_reason():
    d = norm({"action": "execute_tool", "tool": "nuclei",
              "parameters": {"target": "https://x"}, "reason": "baseline recon"})
    assert d.tasks
    assert (d.tasks[0].objective or "").strip()  # not empty


def test_params_alias_accepted_like_parameters():
    d = norm({"action": "use_tool", "tool": "httpx",
              "params": {"target": "https://x"}, "reason": "fingerprint"})
    assert d.tasks
    assert d.tasks[0].inputs  # params flowed into inputs


# ── Tasks array shapes ────────────────────────────────────────────────────────
def test_tasks_array_spawn_agents():
    d = norm({"action": "spawn_agents", "tasks": [
        {"objective": "scan", "tool": "nuclei", "parameters": {"target": "https://x"}},
        {"objective": "fuzz", "tool": "ffuf", "parameters": {"target": "https://x"}},
    ]})
    assert d.action == BrainDecisionAction.SPAWN_AGENTS
    assert len(d.tasks) == 2


def test_singular_agent_spec_converted_to_tasks():
    d = norm({"action": "spawn_agents",
              "agent_spec": {"objective": "scan", "tool": "nuclei",
                             "parameters": {"target": "https://x"}}})
    assert len(d.tasks) == 1


# ── Terminal / control actions ────────────────────────────────────────────────
@pytest.mark.parametrize("action,expected", [
    ("complete", BrainDecisionAction.COMPLETE),
    ("phase_complete", BrainDecisionAction.COMPLETE),
    ("done", BrainDecisionAction.COMPLETE),
    ("wait", BrainDecisionAction.WAIT),
    ("replan", BrainDecisionAction.REPLAN),
])
def test_control_actions(action, expected):
    d = norm({"action": action})
    assert d.action == expected


# ── Lenient parsing / error contract ──────────────────────────────────────────
def test_json_string_input_is_parsed():
    d = norm('{"action":"execute_capability","tool":"nuclei","parameters":{"target":"https://x"},"reason":"r"}')
    assert d.action == BrainDecisionAction.SPAWN_AGENTS
    assert d.tasks


def test_json_embedded_in_prose_is_extracted():
    raw = 'Sure, here is the plan:\n{"action":"complete"}\nHope that helps!'
    d = norm(raw)
    assert d.action == BrainDecisionAction.COMPLETE


def test_empty_input_raises():
    with pytest.raises(PlannerSchemaError):
        norm(None)


def test_non_dict_raises():
    with pytest.raises(PlannerSchemaError):
        norm("this is not json at all")
