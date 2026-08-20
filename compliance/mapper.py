"""
Finding -> compliance control mapper.

Given a finding (with a CWE and/or a normalized category) and a set of active
frameworks, return every applicable control across those frameworks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .frameworks import (FRAMEWORKS, FRAMEWORK_NAMES, category_for_cwe,
                         category_for_type, available_frameworks)


@dataclass
class ComplianceHit:
    framework: str               # key, e.g. "pci"
    framework_name: str          # e.g. "PCI-DSS 4.0"
    control_id: str
    control_title: str
    relevance_note: str = ""

    def to_dict(self) -> Dict:
        return {"framework": self.framework, "framework_name": self.framework_name,
                "control_id": self.control_id, "control_title": self.control_title,
                "relevance_note": self.relevance_note}


def _resolve_category(finding: Dict) -> str:
    """Determine the normalized category for a finding (category -> CWE -> type)."""
    cat = str(finding.get("category", "")).lower().strip()
    if cat:
        return cat
    by_cwe = category_for_cwe(str(finding.get("cwe", "")))
    if by_cwe:
        return by_cwe
    return category_for_type(str(finding.get("type", "")))


class ComplianceMapper:
    """Maps findings to controls across selected frameworks."""

    def __init__(self, active_frameworks: Optional[List[str]] = None):
        self.active = self._normalize(active_frameworks)

    @staticmethod
    def _normalize(frameworks: Optional[List[str]]) -> List[str]:
        if not frameworks:
            return available_frameworks()
        valid = set(available_frameworks())
        out = [f.lower().strip() for f in frameworks if f.lower().strip() in valid]
        return out or available_frameworks()

    def map_finding(self, finding: Dict,
                    active_frameworks: Optional[List[str]] = None) -> List[ComplianceHit]:
        """Return all controls applicable to a single finding."""
        frameworks = self._normalize(active_frameworks) if active_frameworks else self.active
        category = _resolve_category(finding)
        hits: List[ComplianceHit] = []
        if not category:
            return hits

        for fw in frameworks:
            controls = FRAMEWORKS.get(fw, {})
            for cid, meta in controls.items():
                if category in meta.get("applicable_finding_categories", []):
                    hits.append(ComplianceHit(
                        framework=fw,
                        framework_name=FRAMEWORK_NAMES.get(fw, fw),
                        control_id=cid,
                        control_title=meta.get("title", ""),
                        relevance_note=(
                            f"Finding category '{category}' maps to "
                            f"{FRAMEWORK_NAMES.get(fw, fw)} {cid} "
                            f"({meta.get('title','')})."),
                    ))
        return hits

    def map_findings(self, findings: List[Dict],
                     active_frameworks: Optional[List[str]] = None) -> Dict:
        """Map many findings; attach '_compliance' to each and return an index.

        Returns {'by_control': {(fw, cid): [finding_idx...]}, 'hits': total}.
        """
        by_control: Dict[str, List[int]] = {}
        total = 0
        for idx, f in enumerate(findings):
            hits = self.map_finding(f, active_frameworks)
            f["_compliance"] = [h.to_dict() for h in hits]
            for h in hits:
                by_control.setdefault(f"{h.framework}:{h.control_id}", []).append(idx)
                total += 1
        return {"by_control": by_control, "hits": total}
