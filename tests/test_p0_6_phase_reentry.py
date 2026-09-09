"""P0.6 — controlled phase re-entry on dependency events, bounded by budget.

Proves normal completion does NOT re-enter, but a real new-discovery event does,
and only up to the budget.
"""
import pytest

from core.orchestration.phase_reentry import (
    PhaseReentryController, DependencyEvent, snapshot_ctx)


def test_no_event_stays_forward_only():
    c = PhaseReentryController()
    completed = {"RECON", "ACTIVE_SCANNING"}
    # No signals -> completed unchanged (RECON does not re-enter).
    assert c.consume_reentries(set(completed)) == completed


def test_new_host_reenters_recon_once_within_budget():
    c = PhaseReentryController(budget_per_phase=2)
    c.signal(DependencyEvent.NEW_HOST)
    out = c.consume_reentries({"RECON", "ACTIVE_SCANNING"})
    assert "RECON" not in out          # re-opened for one more pass
    assert "ACTIVE_SCANNING" in out


def test_reentry_budget_exhausts():
    c = PhaseReentryController(budget_per_phase=1)
    c.signal(DependencyEvent.NEW_HOST)
    first = c.consume_reentries({"RECON"})
    assert "RECON" not in first
    # Simulate RECON completing again, then another event: budget now 0.
    c.signal(DependencyEvent.NEW_HOST)
    second = c.consume_reentries({"RECON"})
    assert "RECON" in second           # budget exhausted -> no more re-entry


def test_event_for_uncompleted_phase_is_noop():
    c = PhaseReentryController()
    c.signal(DependencyEvent.POSITIVE_FINDING_SIGNAL)  # targets EXPLOITATION
    out = c.consume_reentries({"RECON"})               # EXPLOITATION not completed
    assert out == {"RECON"}


def test_detect_emits_events_on_growth():
    c = PhaseReentryController()
    prev = {"hosts": 1, "endpoints": 10, "vulns": 0, "sessions": 0}
    cur = {"hosts": 2, "endpoints": 10, "vulns": 1, "sessions": 1}
    c.detect(prev, cur)
    out = c.consume_reentries({"RECON", "ACTIVE_SCANNING", "EXPLOITATION"})
    # NEW_HOST -> RECON, POSITIVE_FINDING -> EXPLOITATION, NEW_AUTH -> ACTIVE_SCANNING
    assert "RECON" not in out
    assert "EXPLOITATION" not in out
    assert "ACTIVE_SCANNING" not in out


def test_snapshot_ctx_tolerates_missing_attrs():
    class _C:  # no attrs
        pass
    snap = snapshot_ctx(_C())
    assert snap == {"hosts": 0, "endpoints": 0, "vulns": 0, "sessions": 0}


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
