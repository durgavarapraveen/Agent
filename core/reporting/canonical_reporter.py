from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CanonicalReporter:

    def __init__(
        self,
        attack_surface=None,
        findings: Optional[List[Dict[str, Any]]] = None,
        coverage_engine=None,
        identity_coverage=None,
        learning_engine=None,
        convergence_engine=None,
        target_health=None,
    ):
        self._surface = attack_surface
        self._findings = findings or []
        self._coverage = coverage_engine
        self._identity_coverage = identity_coverage
        self._learning = learning_engine
        self._convergence = convergence_engine
        self._health = target_health

    def generate_summary(self) -> Dict[str, Any]:
        summary: Dict[str, Any] = {
            "generated_at": datetime.utcnow().isoformat(),
            "discovery": self._discovery_summary(),
            "findings": self._findings_summary(),
            "coverage": self._coverage_summary(),
            "health": self._health_summary(),
            "learning": self._learning_summary(),
            "convergence": self._convergence_summary(),
        }
        return summary

    def _discovery_summary(self) -> Dict[str, Any]:
        if not self._surface:
            return {"status": "no_attack_surface"}
        s = self._surface
        return {
            "assets": len(getattr(s, "assets", {})),
            "applications": len(getattr(s, "applications", {})),
            "endpoints": len(getattr(s, "endpoints", {})),
            "parameters": len(getattr(s, "parameters", {})),
            "technologies": len(getattr(s, "technologies", {})),
            "identities": len(getattr(s, "identities", {})),
            "sessions": len(getattr(s, "sessions", {})),
            "files": len(getattr(s, "files", {})),
            "workflows": len(getattr(s, "workflows", {})),
            "redirects": len(getattr(s, "redirects", {})),
        }

    def _findings_summary(self) -> Dict[str, Any]:
        by_state: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        for f in self._findings:
            state = f.get("state", "UNKNOWN")
            by_state[state] = by_state.get(state, 0) + 1
            sev = f.get("severity", "UNKNOWN")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            cat = f.get("category", f.get("attack_type", "UNKNOWN"))
            by_category[cat] = by_category.get(cat, 0) + 1

        confirmed = by_state.get("CONFIRMED", 0) + by_state.get("REPORTABLE", 0)
        false_pos = by_state.get("FALSE_POSITIVE", 0)
        uncertain = by_state.get("INCONCLUSIVE", 0) + by_state.get("UNCERTAIN", 0)

        return {
            "total": len(self._findings),
            "confirmed": confirmed,
            "false_positives": false_pos,
            "uncertain": uncertain,
            "by_state": by_state,
            "by_severity": by_severity,
            "by_category": by_category,
        }

    def _coverage_summary(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        if self._coverage:
            if hasattr(self._coverage, "get_coverage_status"):
                result["test_coverage"] = self._coverage.get_coverage_status()
            if hasattr(self._coverage, "calculate_coverage_pct"):
                result["coverage_pct"] = round(self._coverage.calculate_coverage_pct(), 1)
            if hasattr(self._coverage, "get_coverage_gaps"):
                gaps = self._coverage.get_coverage_gaps()
                result["gaps_count"] = len(gaps)
                result["gaps_sample"] = gaps[:10]
        if self._identity_coverage:
            result["identity_coverage"] = self._identity_coverage.summary()
        return result

    def _health_summary(self) -> Dict[str, Any]:
        if not self._health:
            return {"status": "no_health_manager"}
        if hasattr(self._health, "to_dict"):
            return self._health.to_dict()
        return {
            "state": getattr(self._health, "state", "UNKNOWN"),
            "concurrency": getattr(self._health, "concurrency", 0),
        }

    def _learning_summary(self) -> Dict[str, Any]:
        if not self._learning:
            return {"status": "no_learning_engine"}
        if hasattr(self._learning, "summary"):
            return self._learning.summary()
        return {}

    def _convergence_summary(self) -> Dict[str, Any]:
        if not self._convergence:
            return {"status": "no_convergence_engine"}
        if hasattr(self._convergence, "summary"):
            return self._convergence.summary()
        return {}

    def save_json(self, path: str = None, scan_id: str = None) -> str:
        from core.common.reports_config import reports_enabled, reports_dir
        summary = self.generate_summary()
        body = json.dumps(summary, indent=2, default=str)
        if reports_enabled():
            if path is None:
                path = str(reports_dir() / "canonical_summary.json")
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w") as f:
                f.write(body)
            logger.info(f"CANONICAL_REPORT saved to {path}")
            return path
        if scan_id:
            try:
                from core.database.pg_store import ScanArtifactRepo
                aid = ScanArtifactRepo.insert(
                    scan_id, "canonical_summary", "canonical_summary.json",
                    body, mime_type="application/json")
                logger.info(f"CANONICAL_REPORT persisted to DB (artifact_id={aid})")
                return f"db:scan_artifacts:{aid}"
            except Exception as e:
                logger.warning(f"[CanonicalReporter] DB persist failed: {e}")
        return ""

    def generate_markdown(self) -> str:
        s = self.generate_summary()
        lines = [
            "# Security Assessment Report",
            f"Generated: {s['generated_at']}",
            "",
            "## Discovery",
        ]
        disc = s["discovery"]
        if disc.get("status") != "no_attack_surface":
            for k, v in disc.items():
                lines.append(f"- **{k}**: {v}")

        lines.extend(["", "## Findings"])
        findings = s["findings"]
        lines.append(f"- **Total**: {findings['total']}")
        lines.append(f"- **Confirmed**: {findings['confirmed']}")
        lines.append(f"- **False Positives**: {findings['false_positives']}")
        lines.append(f"- **Uncertain**: {findings['uncertain']}")
        if findings["by_severity"]:
            lines.append("")
            lines.append("### By Severity")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = findings["by_severity"].get(sev, 0)
                if count:
                    lines.append(f"- {sev}: {count}")

        lines.extend(["", "## Coverage"])
        cov = s["coverage"]
        if "coverage_pct" in cov:
            lines.append(f"- **Coverage**: {cov['coverage_pct']}%")
        if "gaps_count" in cov:
            lines.append(f"- **Gaps**: {cov['gaps_count']}")
        if "identity_coverage" in cov:
            ic = cov["identity_coverage"]
            lines.append(f"- **Identity Coverage**: {ic.get('coverage_pct', 'N/A')}%")
            lines.append(f"- **AuthZ Coverage**: {ic.get('authz_coverage_pct', 'N/A')}%")

        lines.extend(["", "## Target Health"])
        health = s["health"]
        lines.append(f"- **State**: {health.get('state', health.get('status', 'N/A'))}")

        conv = s["convergence"]
        if conv.get("status") != "no_convergence_engine":
            lines.extend(["", "## Convergence"])
            lines.append(f"- **Coverage**: {conv.get('coverage_pct', 'N/A')}%")
            lines.append(f"- **Stalled**: {conv.get('is_stalled', 'N/A')}")

        lines.append("")
        return "\n".join(lines)
