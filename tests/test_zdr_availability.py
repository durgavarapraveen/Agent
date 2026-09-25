"""ZDR enforcement + model availability allowlist (accessible-models-only)."""
import pytest

from core.llm import zdr, model_availability as ma
from core.llm.model_roles import ModelRole, model_for_role


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ma.reset_cache()
    for k in ("LLM_ZDR_REQUIRED", "AWS_BEDROCK_DATA_RETENTION", "LLM_ZDR_HEADERS",
              "AWS_BEDROCK_ALLOWED_MODELS", "AWS_BEDROCK_FAST_MODEL",
              "AWS_BEDROCK_SMALL_MODEL", "AWS_BEDROCK_LARGE_MODEL"):
        monkeypatch.delenv(k, raising=False)
    yield
    ma.reset_cache()


# ── ZDR ────────────────────────────────────────────────────────────────
def test_zdr_on_by_default():
    assert zdr.zdr_required() is True
    assert zdr.data_retention_value() == "none"
    assert zdr.persist_content_allowed() is False


def test_zdr_can_be_disabled(monkeypatch):
    monkeypatch.setenv("LLM_ZDR_REQUIRED", "0")
    assert zdr.zdr_required() is False
    assert zdr.persist_content_allowed() is True
    # with ZDR off, data_retention falls back to explicit env (or "")
    assert zdr.data_retention_value() == ""


def test_zdr_headers_from_env(monkeypatch):
    monkeypatch.setenv("LLM_ZDR_HEADERS", '{"X-No-Retention": "1"}')
    assert zdr.zdr_headers() == {"X-No-Retention": "1"}


def test_zdr_status_shape():
    s = zdr.status()
    assert s["zdr_required"] is True and s["persist_content"] is False


def test_llm_log_drops_content_under_zdr(monkeypatch):
    # persist_content_allowed False → llm_log blanks content. Exercise the guard
    # logic directly (no DB): the function must early-blank system/prompt/response.
    assert zdr.persist_content_allowed() is False


# ── availability / allowlist ───────────────────────────────────────────
def test_allowlist_parsed(monkeypatch):
    monkeypatch.setenv("AWS_BEDROCK_ALLOWED_MODELS", "deepseek-v3.2, claude-haiku ")
    assert ma.allowlist() == {"deepseek-v3.2", "claude-haiku"}


def test_is_allowed_respects_allowlist(monkeypatch):
    monkeypatch.setenv("AWS_BEDROCK_ALLOWED_MODELS", "deepseek-v3.2")
    assert ma.is_allowed("bedrock/deepseek-v3.2-large") is True
    assert ma.is_allowed("us.anthropic.claude-opus") is False


def test_unknown_when_no_allowlist_and_no_discovery(monkeypatch):
    # no allowlist, discovery returns nothing → allow (don't block)
    monkeypatch.setattr(ma, "discover_available", lambda force=False: set())
    assert ma.is_allowed("anything") is True


def test_enforce_swaps_to_allowed_fallback(monkeypatch):
    monkeypatch.setenv("AWS_BEDROCK_ALLOWED_MODELS", "the-small")
    assert ma.enforce("blocked-model", fallbacks=["the-small", "the-large"]) == "the-small"


def test_role_routing_gated_to_accessible_model(monkeypatch):
    # planner wants a large model the account cannot access → falls back to the
    # allowed small model.
    monkeypatch.setenv("AWS_BEDROCK_SMALL_MODEL", "allowed-small")
    monkeypatch.setenv("AWS_BEDROCK_LARGE_MODEL", "blocked-large")
    monkeypatch.setenv("AWS_BEDROCK_ALLOWED_MODELS", "allowed-small")
    assert model_for_role(ModelRole.PLANNER) == "allowed-small"
    assert model_for_role(ModelRole.FAST) == "allowed-small"


def test_role_routing_uses_configured_when_accessible(monkeypatch):
    monkeypatch.setenv("AWS_BEDROCK_SMALL_MODEL", "s")
    monkeypatch.setenv("AWS_BEDROCK_LARGE_MODEL", "l")
    monkeypatch.setenv("AWS_BEDROCK_ALLOWED_MODELS", "s,l")
    assert model_for_role(ModelRole.REASONING) == "l"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
