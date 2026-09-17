from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class BlindSpotDetector:
    """Post-scan coverage auditor (P2): reports what was NOT tested.

    Reads the (multiple, unsynchronized) coverage systems + hypotheses off the
    brain and produces a structured report of gaps to include in the scan output
    under a "Coverage & Confidence" section.
    """

    def audit(self, brain) -> Dict[str, Any]:
        ctx = getattr(brain, "ctx", None)
        report: Dict[str, Any] = {
            "untested_endpoints": self._untested_endpoints(brain, ctx),
            "untested_tech": self._unchecked_tech(brain, ctx),
            "unresolved_hypotheses": self._unresolved_hypotheses(brain),
            "coverage_summary": self._coverage_summary(brain),
            "coverage_gaps": self._coverage_gaps(brain),
            "identity_coverage": self._identity_coverage(brain),
        }
        report["blind_spot_count"] = (
            len(report["untested_endpoints"]) + len(report["untested_tech"]) +
            len(report["unresolved_hypotheses"]) + len(report["coverage_gaps"])
        )
        return report

    # ── sections ───────────────────────────────────────────────────────
    def _untested_endpoints(self, brain, ctx) -> List[Dict[str, str]]:
        try:
            discovered = set()
            for e in (ctx.get_endpoints() if hasattr(ctx, "get_endpoints") else []):
                discovered.add(self._ep_str(e))
            tested = set()
            cm = getattr(brain, "coverage_matrix", None)
            if cm and hasattr(cm, "get_matrix"):
                for (ep, _test), state in cm.get_matrix().items():
                    if str(getattr(state, "name", state)) not in ("NOT_TESTED", "NOT_DISCOVERED", "NOT_APPLICABLE"):
                        tested.add(ep)
            return [{"endpoint": e, "reason": "never targeted"} for e in sorted(discovered - tested) if e]
        except Exception as e:
            logger.debug("untested_endpoints failed: %s", e)
            return []

    def _unchecked_tech(self, brain, ctx) -> List[Dict[str, str]]:
        try:
            from core.coverage.hypothesis_engine import TECH_ATTACK_MAP
        except Exception:
            return []
        try:
            techs = getattr(ctx, "technologies", {}) or {}
            detected = set()
            for v in techs.values():
                for t in (v if isinstance(v, list) else [v]):
                    detected.add(str(t).lower())
            out = []
            for tech in detected:
                for key in TECH_ATTACK_MAP:
                    if key in tech:
                        out.append({"tech": tech, "expected_tests": ", ".join(TECH_ATTACK_MAP[key][:4]),
                                    "reason": "tech detected — verify relevant tests ran"})
                        break
            return out
        except Exception as e:
            logger.debug("unchecked_tech failed: %s", e)
            return []

    def _unresolved_hypotheses(self, brain) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            from core.hypothesis.hypothesis_engine import get_engine, HypothesisState
            eng = get_engine()
            for h in getattr(eng, "open_hypotheses", lambda: [])():
                out.append({"id": getattr(h, "hyp_id", ""), "vuln_class": getattr(h, "vuln_class", ""),
                            "endpoint": getattr(h, "endpoint", ""), "state": getattr(h.state, "value", str(h.state))})
        except Exception as e:
            logger.debug("unresolved_hypotheses failed: %s", e)
        return out

    def _coverage_summary(self, brain) -> Dict[str, Any]:
        cm = getattr(brain, "coverage_matrix", None)
        try:
            if cm and hasattr(cm, "coverage_summary"):
                return cm.coverage_summary()
        except Exception as e:
            logger.debug("coverage_summary failed: %s", e)
        return {}

    def _coverage_gaps(self, brain) -> List[str]:
        ce = getattr(brain, "coverage_engine", None)
        try:
            if ce and hasattr(ce, "get_coverage_gaps"):
                return [str(g) for g in ce.get_coverage_gaps()]
        except Exception as e:
            logger.debug("coverage_gaps failed: %s", e)
        return []

    def _identity_coverage(self, brain) -> Dict[str, Any]:
        ic = getattr(brain, "identity_coverage", None)
        try:
            if ic and hasattr(ic, "summary"):
                return ic.summary()
        except Exception as e:
            logger.debug("identity_coverage failed: %s", e)
        return {}

    @staticmethod
    def _ep_str(e) -> str:
        if isinstance(e, str):
            return e
        if isinstance(e, dict):
            return str(e.get("url") or e.get("endpoint") or e.get("endpoint_id") or "")
        return str(getattr(e, "url", "") or getattr(e, "endpoint_id", "") or e)
