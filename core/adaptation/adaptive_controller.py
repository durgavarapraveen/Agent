"""Adaptive control layer — self-diagnosis + free-form re-planning.

Turns the fixed RECON→ACTIVE_SCANNING→EXPLOITATION→REPORTING sequence into a set of
*decisions*. At every phase boundary (and on demand) the controller reads live
runtime signals and may override the default next step: repeat a phase, jump BACK to
re-recon newly-discovered surface, hold/back-off while the target is down, or finalize
early. The phases and probes remain the safe, deterministic ACTIONS the controller
chooses between — so the agent re-plans freely without losing coverage or scope safety.

`diagnose()` is the general self-diagnosis (target health, tool failure rate, phase
progress/stall, coverage gaps, findings momentum, budget) — not tool-specific.
`replan_phase()` is the bounded decision that can override the hardcoded order.

All decisions are deterministic and cheap by default (no LLM on the hot path); an LLM
can be layered on later for ambiguous cases. Every path is fail-open: on any error the
controller returns None and the existing pipeline logic runs unchanged.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Bound backward re-planning so we can never loop forever (root-cause guard for the
# historical multi-hour phase re-entry).
_MAX_REPLANS = 2
# Fraction of NEW endpoints (vs. what existed when active-scanning last ran) that
# justifies jumping back to re-scan the expanded surface.
_RESCAN_GROWTH = 0.5


def _n(x) -> int:
    try:
        return len(x or [])
    except Exception:
        return 0


class AdaptiveController:
    """Attached to the brain as `brain.adaptive_controller`. Stateless except for
    small counters it stores on the brain (so it survives without wiring into ctx)."""

    def diagnose(self, brain) -> Dict[str, Any]:
        """General self-diagnosis: one snapshot of runtime health across signals.
        Cheap, side-effect-free, safe to call every heartbeat."""
        ctx = getattr(brain, "ctx", None)
        d: Dict[str, Any] = {}
        # 1. Target reachability.
        try:
            from core.adaptation.target_health import get_target_health
            d["target"] = get_target_health(ctx).summary()
        except Exception:
            d["target"] = {"state": "HEALTHY"}
        # 2. Tool failure momentum (from the effectiveness/health layer if present).
        try:
            th = getattr(brain, "tool_health", None)
            d["tools_cooldown"] = list(getattr(th, "cooldown_tools", []) or []) if th else []
        except Exception:
            d["tools_cooldown"] = []
        # 3. Coverage.
        try:
            cm = getattr(brain, "coverage_matrix", None)
            d["coverage_gaps"] = _n(cm.get_gaps()) if cm else 0
        except Exception:
            d["coverage_gaps"] = 0
        # 4. Findings momentum + phase.
        d["phase"] = getattr(getattr(brain, "current_phase", None), "value", None)
        d["vulns"] = _n(getattr(ctx, "vulnerabilities", None))
        d["endpoints"] = _n(getattr(ctx, "endpoints", None))
        d["failure_streak"] = int(getattr(brain, "failure_streak", 0) or 0)
        d["replans"] = int(getattr(brain, "_adaptive_replans", 0) or 0)
        return d

    def target_down(self, brain) -> bool:
        try:
            from core.adaptation.target_health import get_target_health
            return get_target_health(getattr(brain, "ctx", None)).is_down
        except Exception:
            return False

    def replan_phase(self, brain):
        """Return an ExecutionPhase to OVERRIDE the default transition to, or None to
        let the normal logic run. Can move BACKWARD (re-recon) — the free-form part.
        Bounded by `_MAX_REPLANS`. Never raises."""
        try:
            from core.orchestration.central_brain import ExecutionPhase
        except Exception:
            return None
        try:
            cur = getattr(brain, "current_phase", None)
            if cur is None:
                return None
            replans = int(getattr(brain, "_adaptive_replans", 0) or 0)
            if replans >= _MAX_REPLANS:
                return None

            ctx = getattr(brain, "ctx", None)
            # Re-recon trigger: the attack surface expanded materially since we last
            # scanned it (e.g. crawl/JS-mining or a finding revealed new endpoints)
            # while we are already past scanning. Jump back to ACTIVE_SCANNING so the
            # new surface is actually tested — not left uncovered because it appeared
            # "too late" in the fixed pipeline.
            if cur in (ExecutionPhase.EXPLOITATION,):
                now_eps = _n(getattr(ctx, "endpoints", None))
                base = int(getattr(brain, "_eps_at_active_scan", 0) or 0)
                if base > 0 and now_eps >= base * (1.0 + _RESCAN_GROWTH):
                    brain._adaptive_replans = replans + 1
                    logger.warning(
                        "[Adaptive] surface grew %d→%d endpoints since scanning — "
                        "re-planning: jump back to ACTIVE_SCANNING (re-recon #%d)",
                        base, now_eps, replans + 1)
                    return ExecutionPhase.ACTIVE_SCANNING
            return None
        except Exception as e:
            logger.debug("[Adaptive] replan skipped: %s", e)
            return None

    def note_active_scanning(self, brain) -> None:
        """Snapshot endpoint count when ACTIVE_SCANNING runs, so replan_phase can
        detect later surface growth."""
        try:
            brain._eps_at_active_scan = _n(getattr(getattr(brain, "ctx", None), "endpoints", None))
        except Exception:
            pass


def get_controller(brain) -> AdaptiveController:
    c = getattr(brain, "adaptive_controller", None)
    if not isinstance(c, AdaptiveController):
        c = AdaptiveController()
        try:
            brain.adaptive_controller = c
        except Exception:
            pass
    return c
