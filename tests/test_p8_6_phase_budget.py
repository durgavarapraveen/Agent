"""Phase 8.6 — streaming token budget with auto-downgrade + phase reservations."""
from __future__ import annotations

from core.common.schemas import TaskTier
from core.economics.budget_governor import BudgetGovernor


class _Budget:
    def __init__(self, maxb, spent=0.0):
        self.max_budget_usd = maxb
        self.spent_usd = spent

    def can_afford(self, *a, **k):
        return True


def test_reserve_phases_splits_budget():
    gov = BudgetGovernor(_Budget(100.0))
    caps = gov.reserve_phases()
    assert caps["RECON"] == 15.0
    assert caps["ACTIVE_SCANNING"] == 40.0
    assert caps["EXPLOITATION"] == 30.0
    assert caps["REPORTING"] == 15.0


def test_custom_reservations():
    gov = BudgetGovernor(_Budget(200.0))
    caps = gov.reserve_phases({"RECON": 0.5, "SCAN": 0.5})
    assert caps == {"RECON": 100.0, "SCAN": 100.0}


def test_auto_downgrade_when_over_threshold():
    # 80% spent, downgrade at 70% → LARGE downgraded to SMALL.
    gov = BudgetGovernor(_Budget(100.0, spent=80.0), downgrade_pct=0.70)
    assert gov.adjust_tier(TaskTier.LARGE) == TaskTier.SMALL
    # SMALL stays SMALL.
    assert gov.adjust_tier(TaskTier.SMALL) == TaskTier.SMALL


def test_no_downgrade_under_threshold():
    gov = BudgetGovernor(_Budget(100.0, spent=10.0), downgrade_pct=0.70)
    assert gov.adjust_tier(TaskTier.LARGE) == TaskTier.LARGE


def test_hard_stop_blocks_requests():
    gov = BudgetGovernor(_Budget(100.0, spent=100.0), hard_stop_pct=1.00)
    assert gov.allow_request() is False


def test_phase_cap_blocks_when_exceeded():
    budget = _Budget(100.0, spent=0.0)
    gov = BudgetGovernor(budget)
    gov.reserve_phases()               # RECON cap = 15
    gov.start_phase("RECON")
    budget.spent_usd = 16.0            # exceeded RECON's 15 cap
    assert gov.allow_request() is False


def test_telemetry_reports_caps():
    gov = BudgetGovernor(_Budget(100.0))
    gov.reserve_phases()
    tel = gov.telemetry()
    assert tel["phase_caps"]["RECON"] == 15.0
