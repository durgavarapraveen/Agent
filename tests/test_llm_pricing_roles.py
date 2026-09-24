"""Authoritative pricing + multi-model role routing (spec Phase 28/29/32)."""
import pytest

from core.economics import pricing
from core.llm.model_roles import (
    ModelRole, classify_task, model_for_role, role_tier, resolve, has_role_model,
)


@pytest.fixture(autouse=True)
def _clear(monkeypatch):
    pricing.reset_cache()
    yield
    pricing.reset_cache()


# ── pricing ────────────────────────────────────────────────────────────
def test_known_models_exact_rates():
    assert pricing.price_for("us.anthropic.claude-haiku-4-5") == (0.80, 4.00)
    assert pricing.price_for("us.anthropic.claude-sonnet-4-20250514") == (3.00, 15.00)
    assert pricing.is_known("deepseek-v3.2") is True


def test_unknown_model_is_zero_not_fabricated():
    assert pricing.is_known("some-random-model-x") is False
    assert pricing.price_for("some-random-model-x") == (0.0, 0.0)   # not (1.0, 3.0)


def test_env_override_wins_and_more_specific_key(monkeypatch):
    monkeypatch.setenv("LLM_PRICING_JSON", '{"deepseek-v3.2": [0.5, 1.5]}')
    pricing.reset_cache()
    assert pricing.price_for("deepseek-v3.2-large") == (0.5, 1.5)
    # a bare deepseek id still uses the default
    assert pricing.price_for("deepseek-v3.1") == (0.27, 1.10)


def test_cost_is_exact_math():
    # 1000 in @0.80/1M + 2000 out @4.0/1M
    c = pricing.cost_usd("claude-haiku", 1000, 2000)
    assert abs(c - (1000 * 0.80 + 2000 * 4.00) / 1_000_000) < 1e-12


def test_bedrock_provider_uses_authoritative_pricing():
    from agents.providers.bedrock_provider import _price_for
    assert _price_for("claude-sonnet-4") == (3.00, 15.00)
    assert _price_for("unknown-xyz") == (0.0, 0.0)


# ── role routing ───────────────────────────────────────────────────────
def test_classify_task_to_roles():
    assert classify_task("classify_severity") == ModelRole.FAST       # 'classif'
    assert classify_task("normalize_tool_output") == ModelRole.FAST   # 'normaliz'
    assert classify_task("attack_path_planning") == ModelRole.PLANNER
    assert classify_task("code_analysis") == ModelRole.CODING
    assert classify_task("screenshot_analysis") == ModelRole.VISION
    assert classify_task("embed_docs") == ModelRole.EMBEDDING
    assert classify_task("exploit_validation") == ModelRole.REASONING
    assert classify_task("") == ModelRole.REASONING                    # default quality


def test_role_env_override(monkeypatch):
    monkeypatch.setenv("AWS_BEDROCK_FAST_MODEL", "fast-model-id")
    monkeypatch.setenv("AWS_BEDROCK_PLANNER_MODEL", "planner-model-id")
    assert model_for_role(ModelRole.FAST) == "fast-model-id"
    assert model_for_role(ModelRole.PLANNER) == "planner-model-id"
    assert has_role_model(ModelRole.FAST) is True
    assert has_role_model(ModelRole.VISION) is False                   # no override


def test_role_falls_back_to_small_large(monkeypatch):
    monkeypatch.delenv("AWS_BEDROCK_FAST_MODEL", raising=False)
    monkeypatch.setenv("AWS_BEDROCK_SMALL_MODEL", "the-small")
    monkeypatch.setenv("AWS_BEDROCK_LARGE_MODEL", "the-large")
    assert model_for_role(ModelRole.FAST) == "the-small"
    assert model_for_role(ModelRole.REASONING) == "the-large"


def test_role_tier_mapping():
    from core.common.schemas import TaskTier
    assert role_tier(ModelRole.FAST) == TaskTier.SMALL
    assert role_tier(ModelRole.PLANNER) == TaskTier.LARGE


def test_resolve_accepts_role_name_or_task(monkeypatch):
    monkeypatch.setenv("AWS_BEDROCK_SMALL_MODEL", "s")
    monkeypatch.setenv("AWS_BEDROCK_LARGE_MODEL", "l")
    r1 = resolve("fast")
    assert r1["role"] == ModelRole.FAST and r1["model"] == "s"
    r2 = resolve("attack_path_planning")
    assert r2["role"] == ModelRole.PLANNER and r2["model"] == "l"


def test_provider_get_model_for_role(monkeypatch):
    monkeypatch.setenv("AWS_BEDROCK_SMALL_MODEL", "small-x")
    monkeypatch.setenv("AWS_BEDROCK_LARGE_MODEL", "large-x")
    monkeypatch.setenv("AWS_BEDROCK_CODING_MODEL", "coder-x")
    from agents.providers.bedrock_provider import BedrockProvider
    p = BedrockProvider(client=object())
    assert p.get_model_for_role(ModelRole.FAST) == "small-x"
    assert p.get_model_for_role(ModelRole.CODING) == "coder-x"
    assert p.get_model_for_role("reasoning") == "large-x"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
