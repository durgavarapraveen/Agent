
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

from core.common.schemas import TaskTier  # canonical enum


class BudgetGovernor:
    def __init__(
        self,
        budget: Any,
        downgrade_pct: float = 0.70,
        hard_stop_pct: float = 1.00,
    ):
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


    def set_phase_cap(self, phase: str, cap_usd: float) -> None:
        self._phase_caps[phase] = float(cap_usd)

    # Phase 8.6: standard per-phase budget reservations (fractions of total).
    PHASE_RESERVATIONS = {"RECON": 0.15, "ACTIVE_SCANNING": 0.40,
                          "EXPLOITATION": 0.30, "REPORTING": 0.15}

    def reserve_phases(self, reservations: Optional[Dict[str, float]] = None) -> Dict[str, float]:
        """Set per-phase spend caps as fractions of the total budget so an
        early phase can't starve later ones. Returns the caps set."""
        reservations = reservations or self.PHASE_RESERVATIONS
        caps = {}
        for phase, frac in reservations.items():
            cap = round(self.max_budget * float(frac), 6)
            self.set_phase_cap(phase, cap)
            caps[phase] = cap
        return caps

    def start_phase(self, phase: str) -> None:
        self._current_phase = phase
        self._phase_spend_start[phase] = self.spent

    def phase_spend(self, phase: str) -> float:
        return self.spent - self._phase_spend_start.get(phase, self.spent)


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
