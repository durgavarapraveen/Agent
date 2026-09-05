"""
Compliance reporting.

Builds a per-framework compliance summary from a set of findings: for each
control in each active framework, how many findings touch it, a pass/fail
status, and references to the contributing findings (evidence).

A control is FAIL if any finding maps to it, PASS otherwise (i.e. no evidence
of a violation was found for that control this scan).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .frameworks import FRAMEWORKS, FRAMEWORK_NAMES
from .mapper import ComplianceMapper


@dataclass
class ControlResult:
    framework: str
    framework_name: str
    control_id: str
    control_title: str
    status: str                          # PASS | FAIL
    finding_count: int
    evidence: List[str] = field(default_factory=list)   # finding ids/titles

    def to_dict(self) -> Dict:
        return {"framework": self.framework, "framework_name": self.framework_name,
                "control_id": self.control_id, "control_title": self.control_title,
                "status": self.status, "finding_count": self.finding_count,
                "evidence": self.evidence}


class ComplianceReporter:
    def __init__(self, active_frameworks: Optional[List[str]] = None):
        self.mapper = ComplianceMapper(active_frameworks)
        self.active = self.mapper.active

    @staticmethod
    def _finding_ref(f: Dict) -> str:
        return str(f.get("id") or f.get("cve_id") or f.get("title")
                   or f.get("type") or "finding")

    def build(self, findings: List[Dict]) -> Dict:
        """Return a structured per-framework compliance summary."""
        index = self.mapper.map_findings(findings, self.active)
        by_control = index["by_control"]

        frameworks_out: Dict[str, Dict] = {}
        for fw in self.active:
            controls_out: List[ControlResult] = []
            fail = 0
            for cid, meta in FRAMEWORKS.get(fw, {}).items():
                idxs = by_control.get(f"{fw}:{cid}", [])
                status = "FAIL" if idxs else "PASS"
                if idxs:
                    fail += 1
                controls_out.append(ControlResult(
                    framework=fw, framework_name=FRAMEWORK_NAMES.get(fw, fw),
                    control_id=cid, control_title=meta.get("title", ""),
                    status=status, finding_count=len(idxs),
                    evidence=[self._finding_ref(findings[i]) for i in idxs][:20],
                ))
            frameworks_out[fw] = {
                "name": FRAMEWORK_NAMES.get(fw, fw),
                "controls": [c.to_dict() for c in controls_out],
                "controls_total": len(controls_out),
                "controls_failed": fail,
                "controls_passed": len(controls_out) - fail,
            }

        return {
            "active_frameworks": self.active,
            "total_mappings": index["hits"],
            "frameworks": frameworks_out,
        }

    def render_markdown(self, findings: List[Dict]) -> str:
        """Human-readable compliance section for scan reports."""
        summary = self.build(findings)
        lines = ["## Compliance Summary", ""]
        for fw, data in summary["frameworks"].items():
            lines.append(f"### {data['name']}  "
                         f"({data['controls_failed']} fail / "
                         f"{data['controls_total']} controls)")
            lines.append("")
            lines.append("| Control | Title | Status | Findings |")
            lines.append("|---|---|---|---|")
            for c in data["controls"]:
                lines.append(
                    f"| {c['control_id']} | {c['control_title']} | "
                    f"{c['status']} | {c['finding_count']} |")
            lines.append("")
        return "\n".join(lines)
