"""Forward attack-path engine (spec Phase 8).

The existing ``core.analysis.correlation_engine`` links CONFIRMED findings into
chains *after the fact*. This engine reasons *forward* over the environment's
findings graph to construct candidate multi-step attack paths toward high-value
targets, following the kill-chain order:

    initial_access → execution → credential_access → privilege_escalation
                   → lateral_movement → collection/impact

Paths are ranked by TRANSPARENT technical factors — reachability, validation
state, proven impact, privilege gain, evidence quality, and cost — and every
factor is stored on the path (spec Phase 32: never a hidden opaque score). It is
fully deterministic; no LLM assigns rank. It only *constructs and ranks*
candidates — it never claims exploitation that was not demonstrated (paths are
``hypothesized`` unless their steps are already EXPLOITED/IMPACT_CONFIRMED).
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from core.verification.impact_engine import _class_of, ImpactLevel, _IMPACT_ORDER
from core.domain.finding_lifecycle import infer_lifecycle, rank as lifecycle_rank

# Kill-chain stages, ordered.
_STAGE = {
    "initial_access": 0, "execution": 1, "credential_access": 2,
    "privilege_escalation": 3, "lateral_movement": 4, "collection": 5,
}

_CLASS_STAGE = {
    "sqli": "initial_access", "xss": "initial_access", "ssrf": "lateral_movement",
    "open_redirect": "initial_access", "other": "initial_access",
    "info_disclosure": "credential_access", "security_header": "initial_access",
    "idor": "privilege_escalation", "authz": "privilege_escalation",
}


def _host(f: Dict[str, Any]) -> str:
    from core.common.finding_ref import finding_location
    loc = finding_location(f)
    try:
        h = urlsplit(loc if "://" in loc else "http://" + loc).hostname
        return (h or loc or "").lower()
    except ValueError:
        return (loc or "").lower()


def _impact_level(f: Dict[str, Any]) -> ImpactLevel:
    try:
        return ImpactLevel(f.get("impact_level", "NO_IMPACT_PROVEN"))
    except ValueError:
        return ImpactLevel.NO_IMPACT_PROVEN


def _stage(f: Dict[str, Any]) -> str:
    cls = _class_of(f)
    # Data actually accessed → collection, regardless of the base class.
    if _IMPACT_ORDER[_impact_level(f)] >= _IMPACT_ORDER[ImpactLevel.RESOURCE_ACCESS_PROVEN] \
            and cls in ("sqli", "idor"):
        return "collection"
    return _CLASS_STAGE.get(cls, "initial_access")


def _value(f: Dict[str, Any]) -> float:
    """Target desirability: proven impact weighs most, then validation state."""
    return _IMPACT_ORDER[_impact_level(f)] * 2.0 + max(0, lifecycle_rank(infer_lifecycle(f)))


_SEV = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
        "LOW": "LOW", "INFO": "INFO"}


class AttackPathEngine:
    def __init__(self, findings: List[Dict[str, Any]],
                 identities: Optional[List[Dict[str, Any]]] = None,
                 max_paths: int = 50):
        self.findings = [f for f in (findings or []) if isinstance(f, dict)]
        self.identities = identities or []
        self.max_paths = max_paths

    # ── public ────────────────────────────────────────────────────────────
    def generate(self) -> List[Dict[str, Any]]:
        paths: List[Dict[str, Any]] = []
        by_host: Dict[str, List[Dict[str, Any]]] = {}
        for f in self.findings:
            by_host.setdefault(_host(f), []).append(f)

        # 1) Same-host chains: an initial-access step → each higher-stage step.
        for host, group in by_host.items():
            group = sorted(group, key=lambda x: _STAGE[_stage(x)])
            starts = [f for f in group if _STAGE[_stage(f)] <= _STAGE["execution"]]
            targets = [f for f in group
                       if _STAGE[_stage(f)] >= _STAGE["credential_access"]]
            for tgt in targets:
                start = next((s for s in starts
                              if _STAGE[_stage(s)] < _STAGE[_stage(tgt)]), None)
                steps = [f for f in (start, tgt) if f is not None]
                if len(steps) >= 2:
                    paths.append(self._path(steps, start="internet"))

        # 2) Cross-host credential pivot: creds found on host A used to escalate
        #    on host B (identity is the link).
        cred_sources = [f for f in self.findings
                        if _stage(f) == "credential_access"]
        escal = [f for f in self.findings
                 if _STAGE[_stage(f)] >= _STAGE["privilege_escalation"]]
        for src in cred_sources:
            for tgt in escal:
                if _host(src) != _host(tgt):
                    paths.append(self._path([src, tgt], start="internet"))

        # 3) Standalone high-value findings (proven impact or already exploited).
        for f in self.findings:
            if _IMPACT_ORDER[_impact_level(f)] >= _IMPACT_ORDER[ImpactLevel.RESOURCE_ACCESS_PROVEN] \
                    or lifecycle_rank(infer_lifecycle(f)) >= 4:  # EXPLOITED+
                paths.append(self._path([f], start="internet"))

        return self._rank_dedupe(paths)

    # ── path construction ─────────────────────────────────────────────────
    def _path(self, steps_findings: List[Dict[str, Any]], start: str) -> Dict[str, Any]:
        from core.common.finding_ref import finding_location
        steps = []
        for f in steps_findings:
            steps.append({
                "action": _class_of(f) or (f.get("type") or "step"),
                "target": finding_location(f) or _host(f),
                "precondition": f.get("title", ""),
                "tool": f.get("tool", "") or f.get("source", ""),
                "result": f.get("impact_level", ""),
                "finding_fingerprint": f.get("fingerprint", ""),
            })
        tgt_finding = steps_findings[-1]
        factors, score = self._score(steps_findings)
        sev = self._severity(steps_findings)
        return {
            "attack_path_id": str(uuid.uuid4()),
            "objective": self._objective(steps_findings),
            "starting_position": start,
            "target": _host(tgt_finding) or steps[-1]["target"],
            "severity": sev,
            "steps": steps,
            "techniques": sorted({_class_of(f) for f in steps_findings}),
            "evidence": "; ".join(str(f.get("proof", ""))[:120] for f in steps_findings),
            "factors": factors,
            "score": score,
            "detection_confidence": round(factors["validation"], 2),
            "exploit_confidence": round(min(0.9, 0.3 + 0.6 * factors["validation"]), 2),
            "status": self._status(steps_findings),
            "source": "attack_path_engine",
        }

    # ── transparent ranking (Phase 32) ────────────────────────────────────
    def _score(self, steps: List[Dict[str, Any]]):
        n = len(steps)
        impact = max(_IMPACT_ORDER[_impact_level(f)] for f in steps) / 4.0
        validation = max((max(0, lifecycle_rank(infer_lifecycle(f))) for f in steps),
                         default=0) / 5.0
        evidence_q = sum(1 for f in steps if f.get("proof") or f.get("evidence")) / n
        privilege = 1.0 if any(_STAGE[_stage(f)] >= _STAGE["privilege_escalation"]
                               for f in steps) else 0.0
        reachability = 1.0  # all start from internet in this model
        cost = 1.0 / n       # fewer steps = cheaper
        factors = {
            "reachability": round(reachability, 3),
            "validation": round(validation, 3),
            "impact": round(impact, 3),
            "privilege_gain": round(privilege, 3),
            "evidence_quality": round(evidence_q, 3),
            "cost_efficiency": round(cost, 3),
        }
        # Transparent weighted sum; weights are explicit, not hidden.
        weights = {"impact": 0.30, "validation": 0.25, "privilege_gain": 0.20,
                   "evidence_quality": 0.10, "reachability": 0.10,
                   "cost_efficiency": 0.05}
        score = round(sum(factors[k] * w for k, w in weights.items()), 4)
        return factors, score

    @staticmethod
    def _severity(steps: List[Dict[str, Any]]) -> str:
        best = max((_IMPACT_ORDER[_impact_level(f)] for f in steps), default=0)
        return {4: "CRITICAL", 3: "CRITICAL", 2: "HIGH", 1: "MEDIUM"}.get(best, "LOW")

    @staticmethod
    def _status(steps: List[Dict[str, Any]]) -> str:
        ranks = [lifecycle_rank(infer_lifecycle(f)) for f in steps]
        if ranks and min(ranks) >= 5:      # every step IMPACT_CONFIRMED
            return "impact_confirmed"
        if ranks and min(ranks) >= 4:      # every step EXPLOITED
            return "exploited"
        return "hypothesized"

    def _objective(self, steps: List[Dict[str, Any]]) -> str:
        tgt = steps[-1]
        cls = _class_of(tgt)
        stage = _stage(tgt)
        base = {"collection": "Access sensitive data",
                "privilege_escalation": "Escalate privileges",
                "credential_access": "Obtain credentials"}.get(stage, f"Exploit {cls}")
        return f"{base} via {' → '.join(_class_of(f) for f in steps)}"

    # ── dedupe + rank ──────────────────────────────────────────────────────
    def _rank_dedupe(self, paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen, out = set(), []
        for p in sorted(paths, key=lambda x: x["score"], reverse=True):
            key = (p["starting_position"], p["target"],
                   tuple(s["action"] for s in p["steps"]))
            if key in seen:
                continue
            seen.add(key)
            out.append(p)
            if len(out) >= self.max_paths:
                break
        return out
