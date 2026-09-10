from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.intelligence.differential.comparison import ResponseSnapshot, compare_snapshots
from core.intelligence.differential.representations import ProbeFn, send
from core.intelligence.parser_differential.mutations import (
    build_parser_probes,
    json_probe_control,
)

_MARKER_A = "qa9a9a0"
_MARKER_B = "qb8b8b1"


@dataclass
class ParserObservation:
    technique: str
    detail: str
    reflected: str = ""
    expected: str = ""
    severity: str = "low"
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "detail": self.detail,
            "reflected": self.reflected,
            "expected": self.expected,
            "severity": self.severity,
            **{f"ev_{k}": v for k, v in self.evidence.items()},
        }


@dataclass
class ParserAnalysis:
    param: str
    reflective: bool
    observations: List[ParserObservation] = field(default_factory=list)

    @property
    def diverged(self) -> bool:
        return bool(self.observations)

    def findings(self) -> List[Dict[str, Any]]:
        return [o.to_dict() for o in self.observations]


class ParserDifferentialEngine:
    def __init__(self, probe: ProbeFn, marker_a: str = _MARKER_A,
                 marker_b: str = _MARKER_B) -> None:
        self._probe = probe
        self._a = marker_a
        self._b = marker_b

    def _reflected(self, snap: ResponseSnapshot) -> str:
        nb = snap.normalized_body
        a, b = self._a in nb, self._b in nb
        if a and b:
            return "both"
        if a:
            return "A"
        if b:
            return "B"
        return "none"

    def analyze(self, base_url: str, param: str,
                auth_headers: Optional[Dict[str, str]] = None) -> ParserAnalysis:
        control = send(self._probe, json_probe_control(base_url, param, self._a, auth_headers))
        reflective = self._reflected(control) == "A"

        probes = build_parser_probes(base_url, param, self._a, self._b,
                                     auth_headers=auth_headers)
        snaps = {p.technique: send(self._probe, p.request) for p in probes}
        obs: List[ParserObservation] = []

        if reflective:
            for p in probes:
                r = self._reflected(snaps[p.technique])
                if p.expected in ("A", "B") and r in ("A", "B") and r != p.expected:
                    sev = "medium" if p.technique in (
                        "query_vs_body", "double_encoding", "case_variant_name") else "low"
                    obs.append(ParserObservation(
                        technique=p.technique,
                        detail=f"server acted on the value a conservative parser "
                               f"should ignore: {p.note}",
                        reflected=r, expected=p.expected, severity=sev,
                        evidence={"status": snaps[p.technique].status,
                                  "body_hash": snaps[p.technique].body_hash},
                    ))
            # Duplicate-parameter ordering rule (informative even when benign).
            ra = self._reflected(snaps["dup_query_a_first"])
            rb = self._reflected(snaps["dup_query_b_first"])
            if {ra, rb} <= {"A", "B"} and ra != "none" and rb != "none":
                rule = "last-wins" if (ra == "B" and rb == "A") else (
                    "first-wins" if (ra == "A" and rb == "B") else "position-independent")
                obs.append(ParserObservation(
                    technique="dup_param_rule", detail=f"duplicate query param rule: {rule}",
                    reflected=f"{ra}/{rb}", expected="either", severity="info",
                    evidence={"a_first": ra, "b_first": rb},
                ))

        # Structural fallback: for NON-reflective endpoints, a duplicate-order
        # change that still alters status/body signals order-sensitive parsing
        # (filter-bypass surface). Skipped when reflective, since an echo server
        # trivially differs just by reflecting the winning value.
        d = [] if reflective else compare_snapshots(
            snaps["dup_query_a_first"], snaps["dup_query_b_first"])
        material = [x for x in d if x.kind in ("status", "body", "content_type")]
        if material:
            obs.append(ParserObservation(
                technique="dup_param_order_divergence",
                detail="reordering a duplicated query parameter changed the response "
                       "(order-sensitive parsing / potential filter bypass surface)",
                severity="medium",
                evidence={"divergences": [x.to_dict() for x in material]},
            ))

        return ParserAnalysis(param=param, reflective=reflective, observations=obs)
