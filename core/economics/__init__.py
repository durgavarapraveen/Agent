"""
Economic controls for autonomous runs (Feature #5).

BudgetGovernor sits on top of the harness TokenBudget and turns a hard spend
limit into a graded policy: downgrade expensive reasoning calls to cheap models
as the budget fills, enforce per-phase spend caps, and expose spend telemetry so
an unattended run cannot silently overspend.
"""

from core.economics.budget_governor import BudgetGovernor, get_budget_governor

__all__ = ["BudgetGovernor", "get_budget_governor"]
