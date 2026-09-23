from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SEV_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class AdaptivePlanner:
    """Coverage-driven planning (P1) + evidence-based phase transitions (P3).

    Replaces count-based ``agents_spawned >= N`` phase logic and static phase
    objectives with decisions grounded in coverage %, finding/discovery rates,
    and hypothesis / attack-chain state. Stateless-ish: rate tracking uses small
    counters stashed on the brain's ctx.
    """

    # ── Evidence-based phase transitions (P3) ──────────────────────────
    def should_transition_phase(self, brain) -> Optional[Any]:
        from core.orchestration.central_brain import ExecutionPhase
        ctx = brain.ctx
        phase = brain.current_phase

        # P1-F3: the live first phase is BUSINESS_UNDERSTANDING (see
        # central_brain init/order); the old ExecutionPhase.UNDERSTAND branch
        # never fired, leaving this fallback transition dead. Match the real phase
        # (accept both, since UNDERSTAND still exists as a distinct enum member).
        if phase in (ExecutionPhase.BUSINESS_UNDERSTANDING, ExecutionPhase.UNDERSTAND):
            # §3: once the app is understood (features/workflows observed) move to
            # recon. "Understood" = we have endpoints or a captured user journey.
            if (ctx.endpoints or getattr(ctx, "captured_requests", None)
                    or len(getattr(ctx, "agents_spawned", [])) >= 2):
                return ExecutionPhase.RECON
            return None

        if phase == ExecutionPhase.RECON:
            if (ctx.endpoints or getattr(ctx, "subdomains", None)) and self._discovery_rate(brain) < 0.5:
                return ExecutionPhase.ACTIVE_SCANNING
            # safety fallback: don't get stuck in recon forever
            if len(getattr(ctx, "agents_spawned", [])) >= 5:
                return ExecutionPhase.ACTIVE_SCANNING

        elif phase == ExecutionPhase.ACTIVE_SCANNING:
            cov = self._coverage_pct(brain)
            if cov > 0.7 or (ctx.vulnerabilities and self._finding_rate(brain) < 0.1):
                return ExecutionPhase.EXPLOITATION
            if len(getattr(ctx, "agents_spawned", [])) >= 8:
                return ExecutionPhase.EXPLOITATION

        elif phase == ExecutionPhase.EXPLOITATION:
            unvalidated = [f for f in ctx.vulnerabilities
                           if str(f.get("severity", "")).upper() in ("HIGH", "CRITICAL")
                           and str(f.get("status", "")).upper() not in ("CONFIRMED", "REJECTED", "REPORTABLE")]
            # Primary: all HIGH+ findings have a validation verdict.
            if not unvalidated:
                return ExecutionPhase.REPORTING
            # Otherwise hold the phase until exploitation genuinely stalls
            # (safety cap) — don't leave HIGH+ findings unvalidated prematurely.
            if len(getattr(ctx, "agents_spawned", [])) >= 12:
                return ExecutionPhase.REPORTING
        return None

    # ── Coverage gaps + next actions (P1) ──────────────────────────────
    def coverage_gaps(self, brain) -> List[Dict[str, Any]]:
        # Read through the unified facade (single API over matrix + engine).
        try:
            from core.coverage.unified_coverage import UnifiedCoverage
            return UnifiedCoverage.from_brain(brain).gaps()
        except Exception as e:
            logger.debug("unified coverage_gaps failed: %s", e)
            return []

    def plan_next_actions(self, brain, limit: int = 20) -> List[Dict[str, Any]]:
        """Ordered, evidence-driven actions: hypothesis engine + attack-chain
        missing links + coverage gaps, scored by (severity/priority)."""
        actions: List[Dict[str, Any]] = []

        # 1. Attack-chain missing links (highest leverage — completes a chain)
        try:
            from core.exploitation.chain_reasoner import ChainReasoner
            for s in ChainReasoner().suggest_next_tests(list(brain.ctx.vulnerabilities or [])):
                actions.append({"kind": "chain_link", "target": s.get("missing"),
                                "priority": 100 + s.get("priority", 0), "rationale": s["rationale"]})
        except Exception as e:
            logger.debug("chain suggestions failed: %s", e)

        # 2. Hypothesis engine's next best action
        try:
            from core.hypothesis.hypothesis_engine import get_engine
            hyp = get_engine().next_best_action()
            if hyp is not None:
                actions.append({"kind": "hypothesis", "vuln_class": getattr(hyp, "vuln_class", ""),
                                "endpoint": getattr(hyp, "endpoint", ""),
                                "parameter": getattr(hyp, "parameter", ""),
                                "priority": 50 + getattr(hyp, "priority", 0.5) * 10,
                                "rationale": getattr(hyp, "rationale", "hypothesis-driven test")})
        except Exception as e:
            logger.debug("hypothesis next_best_action failed: %s", e)

        # 3. Coverage gaps (cheap tests fill the matrix)
        for g in self.coverage_gaps(brain)[:limit]:
            actions.append({"kind": "coverage_gap", **g, "priority": 10,
                            "rationale": "untested coverage cell"})

        actions.sort(key=lambda a: a.get("priority", 0), reverse=True)
        return actions[:limit]

    def objective_hint(self, brain) -> str:
        """Compact, evidence-based objective string to augment the LLM phase
        objective (hypothesis-driven task generation)."""
        actions = self.plan_next_actions(brain, limit=6)
        if not actions:
            return ""
        lines = ["PRIORITIZED (evidence-based) next tests:"]
        for a in actions:
            tgt = a.get("target") or a.get("vuln_class") or a.get("test_id") or a.get("endpoint") or ""
            lines.append(f"- [{a['kind']} p{int(a.get('priority', 0))}] {tgt}: {a.get('rationale', '')}")
        return "\n".join(lines)

    # ── rate helpers (diminishing-returns detection) ───────────────────
    def _rate(self, brain, key: str, current: int) -> float:
        hist = getattr(brain.ctx, "_planner_rates", None)
        if hist is None:
            hist = {}
            try:
                setattr(brain.ctx, "_planner_rates", hist)
            except Exception:
                return 1.0
        prev = hist.get(key, 0)
        hist[key] = current
        return float(max(0, current - prev))

    def _discovery_rate(self, brain) -> float:
        return self._rate(brain, "endpoints", len(getattr(brain.ctx, "endpoints", []) or []))

    def _finding_rate(self, brain) -> float:
        return self._rate(brain, "vulns", len(getattr(brain.ctx, "vulnerabilities", []) or []))

    def _exploit_rate(self, brain) -> float:
        return self._rate(brain, "exploits", len(getattr(brain.ctx, "exploit_results", []) or []))

    def _coverage_pct(self, brain) -> float:
        try:
            from core.coverage.unified_coverage import UnifiedCoverage
            return UnifiedCoverage.from_brain(brain).pct_executed()
        except Exception:
            return 0.0
