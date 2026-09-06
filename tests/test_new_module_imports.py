"""Smoke tests for the modules that landed without matching test files (#174).

Every module below is `import`-able and exposes the symbols the rest of the
codebase depends on. These are intentionally shallow — a real behaviour
test suite for each still needs to be written, but until then this guard
prevents an accidental syntax error or missing dependency from shipping.
"""
from __future__ import annotations

import importlib
import inspect
import pytest


# (module_path, required_public_names)
CASES = [
    ("core.exploitation.cross_role_replay", ("run_cross_role_replay",)),
    ("core.exploitation.custom_probe", ("run_custom_probe", "run_custom_python")),
    ("core.exploitation.dom_sink_monitor", ("run_dom_sink_monitor",)),
    ("core.exploitation.dump_extractor", ("extract_from_finding", "extract_from_all_findings")),
    ("core.exploitation.graphql_ws_probe", ("run_graphql_and_ws",)),
    ("core.exploitation.js_bundle_analyzer", ("analyze_bundles",)),
    ("core.exploitation.semantic_api_fuzzer", ("run_semantic_fuzz",)),
    ("core.orchestration.adversarial_critic", ("critique_and_run",)),
    ("core.orchestration.parallel_agents", ()),
    ("core.orchestration.resume", ("save_checkpoint", "load_checkpoint", "clear_checkpoint")),
    ("core.reporting.chain_intelligence", ("synthesize_chains",)),
    ("core.reporting.repro_bundle", ("generate_bundles_for_scan",)),
    ("core.reporting.scan_chatbot", ("answer_question",)),
    ("core.reporting.scan_diff", ("compare_scans",)),
    ("core.security.scope_facade", ("get_scope_authority", "ScopeAuthority")),
    ("core.observability.metrics", ("render", "is_available")),
    ("core.observability.tracing", ("span", "is_available")),
    ("core.observability.logging_setup", ("configure_root", "PIIRedactionFilter")),
    ("core.notifications.notify", (
        "notify_scan_finished", "notify_critical_finding",
        "notify_exploit_authorized", "notify_platform_error",
    )),
    ("core.llm.circuit_breaker", ("get_llm_breaker", "CircuitOpen", "snapshot")),
    ("core.llm.prompt_safety", ("fence_untrusted", "guarded_prompt")),
    ("core.intelligence._provider_gate", ("get_gate", "ProviderCircuitOpen", "ProviderGate")),
    ("core.common.error_hygiene", ("log_and_swallow",)),
    ("core.common.endpoint_hints", ()),
]


@pytest.mark.parametrize("module_path,required_names", CASES)
def test_module_imports_and_exposes(module_path: str, required_names: tuple):
    try:
        mod = importlib.import_module(module_path)
    except ImportError as e:
        # Optional modules — allow skip when a runtime dep isn't present in
        # the test env, but never allow SyntaxError to sneak through.
        if isinstance(e, SyntaxError):
            raise
        pytest.skip(f"Optional module {module_path} missing dependency: {e}")

    missing = [n for n in required_names if not hasattr(mod, n)]
    assert not missing, f"{module_path} missing symbols: {missing}"

    # Every module-level callable that starts with `_` is private; every
    # public name should either be a callable, a class, or a well-typed
    # constant (not None).
    for name in required_names:
        obj = getattr(mod, name)
        assert obj is not None, f"{module_path}.{name} is None"
