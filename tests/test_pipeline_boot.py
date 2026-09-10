from __future__ import annotations

import inspect

import pytest


def test_central_brain_constructs() -> None:
    from core.orchestration.central_brain import CentralBrain
    brain = CentralBrain(target="http://example.com", scope={"domains": ["example.com"]})
    assert brain is not None
    assert getattr(brain, "target", None) == "http://example.com"


def test_central_brain_entry_points_present() -> None:
    from core.orchestration.central_brain import CentralBrain
    for name in ("run_main_loop", "run_phase"):
        fn = getattr(CentralBrain, name, None)
        assert fn is not None, f"CentralBrain.{name} missing"
        assert inspect.iscoroutinefunction(fn), f"CentralBrain.{name} must be async"


def test_shared_context_v2_lock_present() -> None:
    from core.memory.shared_context import SharedContextV2
    ctx = SharedContextV2("http://example.com")
    assert hasattr(ctx, "_state_lock"), "SharedContextV2._state_lock is required"


def test_authorization_scope_validator_loads() -> None:
    from core.security.authorization import TargetScopeValidator
    scope = TargetScopeValidator.get()
    assert scope is not None
