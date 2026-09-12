"""Verifies the built modules are wired into the runtime pipeline.

The executor-registry test constructs CentralBrain (needs Postgres) so it is
@integration — it runs in CI and documents the wiring contract; it skips on a
DB-less dev box. The singleton checks are plain unit tests.
"""
from __future__ import annotations

import pytest


def test_cost_log_singleton():
    from core.economics.cost_log import get_cost_log
    assert get_cost_log() is get_cost_log()


def test_response_cache_singleton():
    from core.llm.response_cache import get_response_cache
    assert get_response_cache() is get_response_cache()


def test_harness_wires_cost_cache_json():
    """The harness generate_response/generate_json reference the wired modules."""
    import inspect
    from agents.universal_llm_harness import UniversalLLMHarness
    gr = inspect.getsource(UniversalLLMHarness.generate_response)
    assert "get_cost_log" in gr, "harness must record per-scan LLM cost"
    assert "get_response_cache" in gr, "harness must consult the response cache"
    gj = inspect.getsource(UniversalLLMHarness.generate_json)
    assert "json_enforcer" in gj or "parse_with_repair" in gj, "generate_json must repair JSON"


@pytest.mark.integration
def test_new_executors_registered_in_brain():
    from core.orchestration.central_brain import CentralBrain
    from core.execution.executors.ecommerce import EcommerceExecutor
    from core.execution.executors.role_escalation import RoleEscalationExecutor
    from core.execution.executors.llm_app_testing import LLMAppTestingExecutor

    brain = CentralBrain(target="http://example.com", scope={"domains": ["example.com"]})
    reg = brain.executor_registry
    assert isinstance(reg.get("ecommerce_tampering_01"), EcommerceExecutor)
    assert isinstance(reg.get("role_escalation_bola_01"), RoleEscalationExecutor)
    assert isinstance(reg.get("llm_app_injection_01"), LLMAppTestingExecutor)
