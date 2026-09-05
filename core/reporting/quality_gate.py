"""
Quality Gate Master Orchestrator (Phase 4 Master Engine).
Wraps CentralBrain execution flow after Phase 3 LLM analysis.
Sequential pipeline: Filter (ML & signatures) -> Retest (idempotent probes) -> Baseline (noise filtering) -> Calibrate (confidence scoring & auto-accept).
"""

import logging
from typing import Dict, List, Any

from core.reporting.fp_filter import FalsePositiveFilter
from core.reporting.retest_engine import RetestEngine
from core.reporting.baseline import BaselineManager
from core.validation.confidence import ConfidenceCalibrator

logger = logging.getLogger(__name__)


class QualityGate:
    """Phase 4 Master Quality Assurance & Detection Validation Pipeline."""

    def __init__(self, db_path: str = "quality_gate.sqlite"):
        self.fp_filter = FalsePositiveFilter()
        self.retest_engine = RetestEngine()
        self.baseline_manager = BaselineManager(db_path=db_path)
        self.calibrator = ConfidenceCalibrator(db_path=db_path)

    def process_findings(
        self,
        scan_id: str,
        target: str,
        raw_findings: List[Dict[str, Any]],
        first_scan_mode: bool = False
    ) -> Dict[str, Any]:
        """
        Orchestrates:
          1. Filter: Pass all raw findings through fp_filter -> removes false positives.
          2. Retest: Run retest_engine.process_finding_retest() on surviving findings -> updates confidence & reproducibility.
          3. Baseline: Run baseline_manager.filter_noise_and_detect_drift() -> removes baseline noise & whitelist matches.
          4. Calibrate: Run calibrator.calibrate() -> assigns final scores & auto-accept/manual review flags.
        """
        logger.info(f"[QualityGate] Processing {len(raw_findings)} raw findings for target '{target}' (Scan ID: {scan_id})")

        # 1. False Positive Reduction
        surviving_fp_findings = []
        rejected_fp_count = 0
        for f in raw_findings:
            should_rep, reason = self.fp_filter.should_report_finding(f)
            if should_rep:
                surviving_fp_findings.append(f)
            else:
                rejected_fp_count += 1
                logger.info(f"[QualityGate] Finding '{f.get('cve_id') or f.get('title')}' filtered out by FP rules: {reason}")

        # 2. Automated Retesting (Idempotent Probes)
        retested_findings = []
        for f in surviving_fp_findings:
            retested_f = self.retest_engine.process_finding_retest(f)
            retested_findings.append(retested_f)

        # 3. Baseline Normalization
        if first_scan_mode:
            self.baseline_manager.capture_baseline(scan_id, target, retested_findings)
            clean_findings = retested_findings
            baseline_stats = {"mode": "first_scan_baseline_captured", "total_captured": len(retested_findings)}
        else:
            clean_findings, baseline_stats = self.baseline_manager.filter_noise_and_detect_drift(target, retested_findings)

        # 4. Confidence Calibration
        final_calibrated_findings = []
        auto_accepted_count = 0
        manual_review_count = 0

        for f in clean_findings:
            calibrated = self.calibrator.calibrate(f)
            final_calibrated_findings.append(calibrated)

            if calibrated.get("auto_accepted"):
                auto_accepted_count += 1
            else:
                manual_review_count += 1

        summary = {
            "scan_id": scan_id,
            "target": target,
            "raw_findings_count": len(raw_findings),
            "fp_rejected_count": rejected_fp_count,
            "baseline_stats": baseline_stats,
            "auto_accepted_count": auto_accepted_count,
            "manual_review_count": manual_review_count,
            "final_findings": final_calibrated_findings
        }

        logger.info(f"[QualityGate] Complete. Final Reportable Findings: {len(final_calibrated_findings)} (Auto-accepted: {auto_accepted_count}, Manual Review: {manual_review_count})")
        return summary
