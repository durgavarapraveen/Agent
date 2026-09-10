from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.intelligence.differential.representations import HttpRequest, ProbeFn, send
from core.intelligence.metamorphic.relations import BUILTIN_RELATIONS, MetamorphicRelation


@dataclass
class MetamorphicViolation:
    relation: str
    detail: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"relation": self.relation, "detail": self.detail,
                "severity": self.severity, **{f"ev_{k}": v for k, v in self.evidence.items()}}


@dataclass
class MetamorphicResult:
    source_label: str
    nondeterministic: bool = False
    violations: List[MetamorphicViolation] = field(default_factory=list)
    relations_run: List[str] = field(default_factory=list)

    @property
    def violated(self) -> bool:
        return any(v.severity != "info" for v in self.violations)

    def findings(self) -> List[Dict[str, Any]]:
        return [v.to_dict() for v in self.violations]


class MetamorphicEngine:
    def __init__(self, probe: ProbeFn,
                 relations: Optional[List[MetamorphicRelation]] = None) -> None:
        self._probe = probe
        self._relations = relations if relations is not None else BUILTIN_RELATIONS

    def run(self, source: HttpRequest) -> MetamorphicResult:
        src_snap = send(self._probe, source)
        result = MetamorphicResult(source_label=source.label or source.url)
        if src_snap.status == 0:
            return result  # target unreachable; nothing to assert

        # Stability gate: idempotence first.
        nondeterministic = False
        for rel in self._relations:
            if rel.name != "idempotent_get":
                continue
            if not rel.applicable(source):
                break
            followups = [send(self._probe, r) for r in rel.build(source)]
            result.relations_run.append(rel.name)
            if rel.relation(src_snap, followups) is not None:
                nondeterministic = True
            break
        result.nondeterministic = nondeterministic

        for rel in self._relations:
            if rel.name == "idempotent_get":
                continue
            if not rel.applicable(source):
                continue
            followups = [send(self._probe, r) for r in rel.build(source)]
            live = [f for f in followups if f.status != 0]
            if not live:
                continue
            result.relations_run.append(rel.name)
            detail = rel.relation(src_snap, live)
            if detail is None:
                continue
            severity = rel.severity
            if nondeterministic and severity in ("low", "info"):
                severity = "info"
                detail += " (endpoint appears non-deterministic; treat as weak signal)"
            result.violations.append(MetamorphicViolation(
                relation=rel.name, detail=detail, severity=severity,
                evidence={"source_status": src_snap.status,
                          "source_hash": src_snap.body_hash},
            ))
        return result
