"""
Finding confidence scoring & calibration module (Phase 4 Module 4.4).
Empirical base confidence matrix, dynamic contextual adjustment factors (WAF, Exploit, Retest, Baseline),
historical FP verdict learning, and auto-validation thresholds.
"""

from __future__ import annotations

import logging
from core.memory.database import DatabaseManager
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

W_VERSION_MATCH = 40
W_REACHABLE = 30
W_EPSS = 15
W_KEV = 15

EPSS_THRESHOLD = 0.1
HIGH_THRESHOLD = 70
MEDIUM_THRESHOLD = 40

AUTO_ACCEPT_THRESHOLD = 0.85

BASE_CONFIDENCE_MATRIX = {
    "SQLI_ERROR_BASED": 0.95,
    "SQLI_TIME_BASED": 0.70,
    "SQLI_BLIND_BOOLEAN": 0.55,
    "XSS_REFLECTED": 0.60,
    "XSS_STORED": 0.80,
    "LFI": 0.75,
    "RCE": 0.90,
    "PATH_TRAVERSAL": 0.65,
    "INFO_DISCLOSURE": 0.50,
    "MISCONFIGURATION": 0.60
}


@dataclass
class ConfidenceVerdict:
    level: str  # HIGH | MEDIUM | LOW
    score: int
    evidence: List[str] = field(default_factory=list)
    needs_review: bool = False  # True when level == LOW

    def to_dict(self) -> Dict:
        return {
            "level": self.level,
            "score": self.score,
            "evidence": self.evidence,
            "needs_review": self.needs_review
        }


def assess(*, version_match_exact: bool = False, reachable: bool = False, epss: float = 0.0, kev_match: bool = False) -> ConfidenceVerdict:
    """Compute a confidence verdict from evidence signals."""
    score = 0
    evidence: List[str] = []

    if version_match_exact:
        score += W_VERSION_MATCH
        evidence.append(f"exact version match (+{W_VERSION_MATCH})")
    else:
        evidence.append("no exact version match (+0)")

    if reachable:
        score += W_REACHABLE
        evidence.append(f"vulnerable symbol reachable from entry point (+{W_REACHABLE})")
    else:
        evidence.append("reachability not confirmed (+0)")

    if (epss or 0.0) > EPSS_THRESHOLD:
        score += W_EPSS
        evidence.append(f"EPSS {epss:.3f} > {EPSS_THRESHOLD} (+{W_EPSS})")
    else:
        evidence.append(f"EPSS {float(epss or 0.0):.3f} <= {EPSS_THRESHOLD} (+0)")

    if kev_match:
        score += W_KEV
        evidence.append(f"listed in CISA KEV (+{W_KEV})")
    else:
        evidence.append("not in CISA KEV (+0)")

    level = HIGH if score >= HIGH_THRESHOLD else MEDIUM if score >= MEDIUM_THRESHOLD else LOW
    return ConfidenceVerdict(level=level, score=score, evidence=evidence, needs_review=(level == LOW))


def _is_directly_confirmed(finding: Dict) -> bool:
    if finding.get("confirmed") or finding.get("from_llm_final"):
        return True
    proof = str(finding.get("proof", "")).strip()
    if proof:
        return True
    data = finding.get("data") or {}
    return bool(isinstance(data, dict) and data.get("confirmed"))


def assess_finding(finding: Dict, reachable_status: Optional[str] = None) -> ConfidenceVerdict:
    if _is_directly_confirmed(finding):
        return ConfidenceVerdict(
            level=HIGH, score=100,
            evidence=["confirmed by active exploitation / concrete proof (+100)"],
            needs_review=False)

    reachable = bool(finding.get("reachable"))
    status = reachable_status or finding.get("reachable_status")
    if status == "reachable":
        reachable = True

    return assess(
        version_match_exact=bool(finding.get("version_match_exact") or finding.get("exact_version_match")),
        reachable=reachable,
        epss=float(finding.get("epss", finding.get("epss_percentile", 0.0)) or 0.0),
        kev_match=bool(finding.get("kev_match")),
    )


def gate(findings: List[Dict]) -> Dict[str, List[Dict]]:
    report, review = [], []
    for f in findings:
        verdict = assess_finding(f)
        f["_confidence"] = verdict.to_dict()
        if verdict.needs_review:
            review.append(f)
        else:
            report.append(f)

    is_misconfigured = False
    if not report and not review:
        logger.warning(
            "[confidence] SCANNER_MISCONFIGURATION_WARNING: Assessment finished with zero findings. "
            "Verify tool execution parameters, scope targets, and network reachability."
        )
        is_misconfigured = True

    logger.info(f"[confidence] {len(report)} reportable, {len(review)} need review")
    return {
        "report": report,
        "needs_review": review,
        "scanner_misconfiguration_warning": is_misconfigured
    }


class ConfidenceCalibrator:
    """Confidence calibration engine with empirical matrix, dynamic modifiers, and FP history learning."""

    def __init__(self):
        self._init_db()

    def _init_db(self):
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS fp_history (
                            id SERIAL PRIMARY KEY,
                            finding_type TEXT,
                            confidence_at_time REAL,
                            user_verdict TEXT,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    conn.commit()
        except Exception as e:
            logger.error(f"[ConfidenceCalibrator] DB init error: {e}")

    def record_fp_verdict(self, finding_type: str, confidence_score: float, verdict: str):
        """Record user feedback verdict (FP or TP) for offline confidence learning."""
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO fp_history (finding_type, confidence_at_time, user_verdict)
                        VALUES (%s, %s, %s)
                    """, (finding_type.strip().upper(), confidence_score, verdict.strip().upper()))
                    conn.commit()
        except Exception as e:
            logger.debug(f"[ConfidenceCalibrator] Record verdict error: {e}")

    def get_historical_fp_penalty(self, finding_type: str) -> float:
        """If a specific finding_type consistently gets flagged as FP by users (>=80% FP), apply penalty -0.15."""
        f_clean = finding_type.strip().upper()
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT user_verdict FROM fp_history WHERE finding_type=%s", (f_clean,))
                    rows = cur.fetchall()
                    if len(rows) >= 5:
                        fp_count = sum(1 for r in rows if r[0] == "FP")
                        if (fp_count / float(len(rows))) >= 0.80:
                            logger.info(f"[ConfidenceCalibrator] Applying permanent FP penalty (-0.15) for '{f_clean}'")
                            return -0.15
        except Exception as e:
            logger.debug(f"[ConfidenceCalibrator] FP penalty query error: {e}")
        return 0.0

    def calibrate(self, finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Calibrate finding confidence using BASE_CONFIDENCE_MATRIX, contextual modifiers, and FP learning.
        Formula: adjusted_confidence = base * (1 + sum(modifiers)), capped at [0.10, 0.99].
        """
        context = context or {}
        vuln_type = str(finding.get("type") or finding.get("vuln_type") or finding.get("title") or "MISCONFIGURATION").upper()

        # Extract base value
        base_score = 0.60
        for k, v in BASE_CONFIDENCE_MATRIX.items():
            if k in vuln_type or vuln_type in k:
                base_score = v
                break

        modifiers = []
        if context.get("waf_detected", finding.get("waf_detected", False)):
            modifiers.append(-0.20)  # WAF detected -> reduce 20%
        if context.get("public_exploit_available", finding.get("public_exploit_available", False)):
            modifiers.append(0.10)   # Public exploit available -> increase 10%
        if context.get("reproducible", finding.get("reproducibility_status") == "REPRODUCIBLE"):
            modifiers.append(0.05)   # Reproducible -> increase 5%
        if context.get("baseline_match", finding.get("baseline_match", False)):
            modifiers.append(-0.05)  # Baseline match -> decrease 5%

        # Historical FP Penalty
        penalty = self.get_historical_fp_penalty(vuln_type)
        if penalty != 0.0:
            modifiers.append(penalty)

        sum_modifiers = sum(modifiers)
        adj_confidence = base_score * (1.0 + sum_modifiers)
        adj_confidence = round(min(max(adj_confidence, 0.10), 0.99), 2)

        finding["confidence_score"] = adj_confidence

        if adj_confidence >= AUTO_ACCEPT_THRESHOLD:
            finding["auto_accepted"] = True
            finding["review_recommendation"] = "Auto-accepted for final report"
        else:
            finding["auto_accepted"] = False
            finding["review_recommendation"] = "Manual review recommended"

        return finding
