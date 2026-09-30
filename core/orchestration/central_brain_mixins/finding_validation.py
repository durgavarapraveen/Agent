from __future__ import annotations

import logging

from core.compliance import available_frameworks
from core.validation import DedupStore, gate as confidence_gate

logger = logging.getLogger(__name__)


class FindingValidationMixin:
    """Confidence gating, cross-scan dedup, and active compliance frameworks.

    Extracted from CentralBrain; consumed by ReportingMixin via self.
    """

    def _active_frameworks(self):
        try:
            from core.common.config import get_config
            fw = get_config().config.get("COMPLIANCE_FRAMEWORKS")
            if fw:
                return fw
        except Exception:       # noqa: BLE001
            pass
        return available_frameworks()

    def _validate_findings(self, ts: str):
        # Work on shallow copies so we don't mutate the canonical vuln list.
        findings = [dict(v) for v in self.ctx.vulnerabilities]

        # 1. Confidence gate — LOW confidence -> needs_review (not main report).
        gated = confidence_gate(findings)
        reported, needs_review = gated["report"], gated["needs_review"]

        # 2. Cross-scan dedup — suppress recurring-unchanged, flag new/resolved.
        try:
            dedup = DedupStore()
            dd = dedup.process_scan(reported, scan_id=ts, include_recurring=True)
            reported = dd["report"]
            suppressed_findings = dd.get("suppressed_findings", [])
            
            # Explicit logging for suppressed findings
            for sf in suppressed_findings:
                reason = "recurring_deduplicated_by_fingerprint"
                logger.info(f"SUPPRESSED: {sf.get('id', 'unknown')} reason={reason}")
                
            dedup_summary = {
                "suppressed_recurring": dd["suppressed"],
                "suppressed_findings": [f.get("title") or f.get("name") or f.get("type") for f in suppressed_findings],
                "resolved": len(dd["resolved"]),
                "reported": len(reported)
            }
        except Exception as e:      # noqa: BLE001
            logger.warning(f"[report] dedup failed: {e}")
            dedup_summary = {"suppressed_recurring": 0, "suppressed_findings": [], "resolved": 0,
                             "reported": len(reported), "error": str(e)}

        logger.info(f"[report] findings: {len(reported)} reported, "
                    f"{len(needs_review)} need review, "
                    f"{dedup_summary['suppressed_recurring']} recurring suppressed")
        return {"reported": reported, "needs_review": needs_review,
                "dedup": dedup_summary}
