"""
BudgetGovernor — graded economic controller for LLM spend.

The harness TokenBudget already tracks $ spent and refuses a request that cannot
be afforded. That is binary. The governor adds policy so an autonomous run degrades
gracefully instead of hard-stopping:

  spent < downgrade_pct        -> full quality (LARGE reasoning allowed)
  downgrade_pct <= spent < hard_pct -> route LARGE tasks to the SMALL/cheap model
  spent >= hard_pct            -> block further LLM calls entirely

It also supports per-phase spend caps (e.g. cap EXPLOITATION at 40% of budget) and
emits telemetry for reporting.

Config (.env):
  BUDGET_GOVERNOR_ENABLED=true
  LLM_DOWNGRADE_PCT=0.70       # start routing LARGE->SMALL here
  LLM_HARD_STOP_PCT=1.00       # block all LLM calls at/after this
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:  # avoid a hard import cycle if the harness is unavailable
    from agents.universal_llm_harness import TaskTier
except Exception:  # pragma: no cover
    from enum import Enum

    class TaskTier(Enum):  # type: ignore
        SMALL = "small"
        LARGE = "large"


class BudgetGovernor:
    def __init__(
        self,
        budget: Any,
        downgrade_pct: float = 0.70,
        hard_stop_pct: float = 1.00,
    ):
        """
        Args:
            budget: a TokenBudget (has .spent_usd, .max_budget_usd, .can_afford()).
        """
        self.budget = budget
        self.downgrade_pct = float(downgrade_pct)
        self.hard_stop_pct = float(hard_stop_pct)
        self._downgrades = 0
        self._blocks = 0
        self._phase_caps: Dict[str, float] = {}          # phase -> cap_usd
        self._phase_spend_start: Dict[str, float] = {}    # phase -> spent_usd at entry
        self._current_phase: Optional[str] = None
        self._warned_downgrade = False
        self._warned_hardstop = False

    # ------------------------------------------------------------- accounting

    @property
    def max_budget(self) -> float:
        return float(getattr(self.budget, "max_budget_usd", 0.0) or 0.0)

    @property
    def spent(self) -> float:
        return float(getattr(self.budget, "spent_usd", 0.0) or 0.0)

    def pct_spent(self) -> float:
        if self.max_budget <= 0:
            return 0.0
        return self.spent / self.max_budget

    # ------------------------------------------------------------ tier policy

    def adjust_tier(self, tier: TaskTier) -> TaskTier:
        """Downgrade LARGE reasoning to SMALL once the budget crosses the threshold."""
        pct = self.pct_spent()
        if pct >= self.downgrade_pct and getattr(tier, "value", tier) == TaskTier.LARGE.value:
            self._downgrades += 1
            if not self._warned_downgrade:
                logger.warning(f"[BudgetGovernor] {pct:.0%} of budget spent — routing "
                               f"LARGE tasks to the cheap model to conserve budget")
                self._warned_downgrade = True
            return TaskTier.SMALL
        return tier

    def allow_request(self, estimated_tokens: int = 0, provider: str = "", model: str = "") -> bool:
        """Return False when the hard stop is reached or the request is unaffordable."""
        pct = self.pct_spent()
        if pct >= self.hard_stop_pct:
            self._blocks += 1
            if not self._warned_hardstop:
                logger.error(f"[BudgetGovernor] HARD STOP — {pct:.0%} of "
                             f"${self.max_budget:.2f} spent; blocking further LLM calls")
                self._warned_hardstop = True
            return False
        # Per-phase cap check.
        if self._current_phase and self._current_phase in self._phase_caps:
            phase_spent = self.spent - self._phase_spend_start.get(self._current_phase, self.spent)
            if phase_spent >= self._phase_caps[self._current_phase]:
                logger.warning(f"[BudgetGovernor] phase '{self._current_phase}' cap "
                               f"${self._phase_caps[self._current_phase]:.2f} reached")
                return False
        if estimated_tokens and hasattr(self.budget, "can_afford"):
            try:
                return bool(self.budget.can_afford(estimated_tokens, provider or "deepseek", model or ""))
            except Exception:
                return True
        return True

    # -------------------------------------------------------------- phases

    def set_phase_cap(self, phase: str, cap_usd: float) -> None:
        self._phase_caps[phase] = float(cap_usd)

    def start_phase(self, phase: str) -> None:
        self._current_phase = phase
        self._phase_spend_start[phase] = self.spent

    def phase_spend(self, phase: str) -> float:
        return self.spent - self._phase_spend_start.get(phase, self.spent)

    # ------------------------------------------------------------- telemetry

    def telemetry(self) -> Dict[str, Any]:
        return {
            "max_budget_usd": round(self.max_budget, 4),
            "spent_usd": round(self.spent, 4),
            "pct_spent": round(self.pct_spent(), 4),
            "remaining_usd": round(self.max_budget - self.spent, 4),
            "downgrades": self._downgrades,
            "blocks": self._blocks,
            "phase_caps": self._phase_caps,
            "hard_stop_reached": self.pct_spent() >= self.hard_stop_pct,
        }


_GOVERNOR: Optional[BudgetGovernor] = None


def get_budget_governor(budget: Any = None) -> Optional[BudgetGovernor]:
    """Return (creating if needed) the process-wide governor bound to a budget."""
    global _GOVERNOR
    if _GOVERNOR is not None:
        return _GOVERNOR
    if budget is None:
        return None
    try:
        from core.common.config import get_config
        cfg = get_config()
        if not cfg.get_bool("BUDGET_GOVERNOR_ENABLED", True):
            return None
        downgrade = float(cfg.get("LLM_DOWNGRADE_PCT", "0.70"))
        hard = float(cfg.get("LLM_HARD_STOP_PCT", "1.00"))
    except Exception:
        downgrade, hard = 0.70, 1.00
    _GOVERNOR = BudgetGovernor(budget, downgrade_pct=downgrade, hard_stop_pct=hard)
    return _GOVERNOR
