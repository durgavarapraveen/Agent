
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from core.reporting.risk_prioritizer import RiskPrioritizer
from core.reporting.remediation_engine import RemediationEngine
from core.reporting.trend_analyzer import TrendAnalyzer
from core.reporting.report_builder import CustomReportBuilder

logger = logging.getLogger(__name__)


class ReportingEngine:

    def __init__(self, output_dir: str = None):
        from core.common.reports_config import reports_enabled, reports_dir
        self._reports_enabled = reports_enabled()
        if output_dir is None:
            output_dir = str(reports_dir())
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.risk_prioritizer = RiskPrioritizer()
        self.remediation_engine = RemediationEngine()
        self.trend_analyzer = TrendAnalyzer()
        self.report_builder = CustomReportBuilder()

    def generate_report_bundle(
        self,
        target: str,
        vulnerabilities: List[Dict[str, Any]],
        scan_id: Optional[str] = None,
        industry: Optional[str] = None,
        mask_sensitive: bool = True
    ) -> Dict[str, str]:
        if not scan_id:
            scan_id = datetime.now().strftime("scan_%Y%m%d_%H%M%S")

        # Sanitize scan_id before using it as a filesystem component. An
        # attacker-influenced (or hallucinated) `scan_id` like `../../etc`
        # would escape `self.output_dir`. Whitelist: `[A-Za-z0-9._-]+`; empty
        # or all-special names fall back to a timestamped id.
        import re as _re_sid
        safe_scan_id = _re_sid.sub(r"[^A-Za-z0-9._-]+", "_", str(scan_id))
        safe_scan_id = safe_scan_id.strip("._") or datetime.now().strftime("scan_%Y%m%d_%H%M%S")
        if safe_scan_id != scan_id:
            logger.warning(
                "[ReportingEngine] scan_id %r sanitized to %r for filesystem safety",
                scan_id, safe_scan_id)
            scan_id = safe_scan_id

        # Resolve boundary — refuse to write outside self.output_dir.
        _out_root = self.output_dir.resolve()
        target_dir = (self.output_dir / scan_id).resolve()
        try:
            target_dir.relative_to(_out_root)
        except ValueError:
            raise ValueError(
                f"scan_id {scan_id!r} resolves outside output_dir {self.output_dir}")
        target_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"[ReportingEngine] Starting Phase 5 reporting for target '{target}' (Scan ID: {scan_id})")

        # 1. ANALYZE: Remediation enrichment & Patch Effort
        enriched_vulns = []
        for v in vulnerabilities:
            item = self.remediation_engine.enrich_finding_remediation(v, industry=industry)
            enriched_vulns.append(item)

        # 2. ANALYZE: Risk Prioritization & Tiering
        prioritized_vulns = self.risk_prioritizer.prioritize_findings(enriched_vulns)
        risk_tiers = self.risk_prioritizer.group_by_risk_tiers(prioritized_vulns)
        roadmap = self.risk_prioritizer.generate_prioritized_roadmap(prioritized_vulns)

        # 3. ANALYZE: Trend Analysis
        summary_result = self.trend_analyzer.record_scan_summary(
            scan_id=scan_id,
            target_name=target,
            vulnerabilities=prioritized_vulns
        )
        mttd_info = self.trend_analyzer.compute_mttd_and_remediation_rate(target)
        predictive_trend = self.trend_analyzer.predict_future_trends(target)

        # 4. RENDER & EXPORT MULTI-FORMAT REPORTS

        # HTML
        html_content = self.report_builder.export_html_interactive(
            scan_id=scan_id,
            target=target,
            vulnerabilities=prioritized_vulns,
            trend_info=predictive_trend,
            mask_sensitive=mask_sensitive
        )
        html_path = target_dir / "report.html"
        html_path.write_text(html_content, encoding="utf-8")

        # JSON
        json_content = self.report_builder.export_json(
            scan_id=scan_id,
            target=target,
            vulnerabilities=prioritized_vulns,
            mask_sensitive=mask_sensitive
        )
        json_path = target_dir / "report.json"
        json_path.write_text(json_content, encoding="utf-8")

        # Markdown
        md_content = self.report_builder.export_markdown(
            scan_id=scan_id,
            target=target,
            vulnerabilities=prioritized_vulns,
            roadmap=roadmap,
            mask_sensitive=mask_sensitive
        )
        md_path = target_dir / "report.md"
        md_path.write_text(md_content, encoding="utf-8")

        # PDF
        pdf_path = target_dir / "report.pdf"
        self.report_builder.export_pdf(
            scan_id=scan_id,
            target=target,
            vulnerabilities=prioritized_vulns,
            mask_sensitive=mask_sensitive,
            output_path=str(pdf_path)
        )

        # 5. EXPORT: report_summary.txt
        total_hours = self.remediation_engine.calculate_total_remediation_hours(prioritized_vulns)
        summary_text = (
            f"================================================================================\n"
            f"ANTIGRAVITY REPORTING ENGINE — PHASE 5 SUMMARY\n"
            f"================================================================================\n"
            f"Target: {target}\n"
            f"Scan ID: {scan_id}\n"
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"FINDING METRICS:\n"
            f"  - Total Findings: {len(prioritized_vulns)}\n"
            f"  - Critical Risk Tiers (score >= 8.0): {len(risk_tiers['CRITICAL_RISK'])}\n"
            f"  - High Risk Tiers (score 5.0–7.9):  {len(risk_tiers['HIGH_RISK'])}\n"
            f"  - Medium Risk Tiers (score 3.0–4.9): {len(risk_tiers['MEDIUM_RISK'])}\n"
            f"  - Low Risk Tiers (score < 3.0):     {len(risk_tiers['LOW_RISK'])}\n\n"
            f"REMEDIATION & TREND METRICS:\n"
            f"  - Total Estimated Patch Effort: {total_hours} hours\n"
            f"  - MTTD (Mean Time To Detect): {mttd_info['mttd_days']} days\n"
            f"  - Remediation Rate: {mttd_info['remediation_rate_percent']}%\n"
            f"  - Predictive Trend: {predictive_trend['prediction']}\n\n"
            f"GENERATED REPORT ARTIFACTS:\n"
            f"  - Interactive HTML Report: {html_path.resolve()}\n"
            f"  - PDF Printable Report:   {pdf_path.resolve()}\n"
            f"  - Raw Machine JSON Data:   {json_path.resolve()}\n"
            f"  - Version Control Markdown:{md_path.resolve()}\n"
            f"================================================================================\n"
        )
        summary_file = target_dir / "report_summary.txt"
        summary_file.write_text(summary_text, encoding="utf-8")

        logger.info(f"[ReportingEngine] Successfully exported Phase 5 report bundle to: {target_dir}")

        return {
            "scan_id": scan_id,
            "target_dir": str(target_dir),
            "html": str(html_path),
            "pdf": str(pdf_path),
            "json": str(json_path),
            "markdown": str(md_path),
            "summary": str(summary_file)
        }
