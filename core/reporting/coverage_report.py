from __future__ import annotations

from typing import Any, Dict, Optional

from core.coverage.coverage_matrix import CoverageMatrix, CoverageState
from core.findings.finding_store import FindingStore
from core.knowledge.knowledge_graph import KnowledgeGraph


class CoverageReport:

    def __init__(
        self,
        coverage_matrix: CoverageMatrix,
        finding_store: FindingStore,
        knowledge_graph: Optional[KnowledgeGraph] = None,
        test_category_map: Optional[Dict[str, str]] = None,
    ) -> None:
        self.matrix = coverage_matrix
        self.finding_store = finding_store
        self.kg = knowledge_graph
        self.cat_map = test_category_map or {}

    def generate(self) -> str:
        lines = []
        lines.append("COVERAGE ANALYSIS")
        lines.append("=" * 50)
        lines.append("")

        matrix = self.matrix.get_matrix()
        endpoints = list(matrix.keys())
        all_tests = set()
        for tests in matrix.values():
            all_tests.update(tests.keys())

        lines.append(f"Total Endpoints: {len(endpoints)}")
        lines.append(f"Applicable Tests: {len(all_tests) * len(endpoints)}")
        lines.append("")
        lines.append("By Vulnerability Class:")
        lines.append("")

        cat_stats = self._compute_category_stats(matrix)
        for cat, stats in sorted(cat_stats.items()):
            lines.append(f"  {cat}:")
            lines.append(
                f"    Applicable: {stats['applicable']} | "
                f"Tested: {stats['tested']} | "
                f"Confirmed: {stats['confirmed']} | "
                f"Rejected: {stats['rejected']} | "
                f"Blocked: {stats['blocked']} | "
                f"Untested: {stats['untested']}"
            )
            lines.append("")

        coverage = self.matrix.get_coverage()
        lines.append(f"OVERALL COVERAGE: {coverage:.0%}")

        gaps = self.matrix.get_gaps()
        blocked = self.matrix.get_blocked()
        converged = coverage >= 0.85 and not gaps
        lines.append(f"Converged: {'YES' if converged else 'NO'}")

        if gaps:
            lines.append(f"Remaining Gaps: {len(gaps)}")
            for ep, t in gaps[:10]:
                lines.append(f"  - {ep} / {t}")
            if len(gaps) > 10:
                lines.append(f"  ... and {len(gaps) - 10} more")

        if blocked:
            lines.append(f"Blocked Tests: {len(blocked)}")
            for ep, t in blocked[:10]:
                lines.append(f"  - {ep} / {t}")

        findings = self.finding_store.list_all()
        if findings:
            lines.append("")
            lines.append(f"Total Findings: {len(findings)}")
            confirmed = [f for f in findings if f.state == "confirmed"]
            lines.append(f"Confirmed Vulnerabilities: {len(confirmed)}")

        return "\n".join(lines)

    def generate_json(self) -> Dict[str, Any]:
        matrix = self.matrix.get_matrix()
        gaps = self.matrix.get_gaps()
        blocked = self.matrix.get_blocked()
        coverage = self.matrix.get_coverage()
        findings = self.finding_store.list_all()

        return {
            "total_endpoints": len(matrix),
            "overall_coverage": round(coverage, 4),
            "converged": coverage >= 0.85 and not gaps,
            "gaps": [{"endpoint": ep, "test": t} for ep, t in gaps],
            "blocked": [{"endpoint": ep, "test": t} for ep, t in blocked],
            "category_coverage": self.matrix.get_coverage_by_category(self.cat_map),
            "total_findings": len(findings),
            "confirmed_findings": len([f for f in findings if f.state == "confirmed"]),
        }

    def _compute_category_stats(self, matrix: Dict) -> Dict[str, Dict[str, int]]:
        stats: Dict[str, Dict[str, int]] = {}
        for ep_id, tests in matrix.items():
            for test_id, state in tests.items():
                cat = self.cat_map.get(test_id, "other")
                if cat not in stats:
                    stats[cat] = {"applicable": 0, "tested": 0, "confirmed": 0, "rejected": 0, "blocked": 0, "untested": 0}
                s = stats[cat]
                if state == CoverageState.NOT_APPLICABLE:
                    continue
                s["applicable"] += 1
                if state == CoverageState.CONFIRMED:
                    s["tested"] += 1
                    s["confirmed"] += 1
                elif state == CoverageState.REJECTED:
                    s["tested"] += 1
                    s["rejected"] += 1
                elif state == CoverageState.BLOCKED:
                    s["blocked"] += 1
                elif state == CoverageState.NOT_TESTED:
                    s["untested"] += 1
                else:
                    s["tested"] += 1
        return stats
