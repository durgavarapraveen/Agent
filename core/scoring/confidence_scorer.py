"""
Confidence Scoring — Auto-Calculate from Response Patterns (Strix Pattern #4).

Replaces manual "need review" tagging with auto-calculated confidence (0-100%)
based on response consistency, timing, evidence quality, reproducibility, and
payload specificity.

Inspired by Strix's required confidence with mandatory rationale.
"""
from __future__ import annotations

import logging
import statistics
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class EvidenceType(str, Enum):
    DATABASE_ERROR = "database_error"
    DATA_EXFILTRATED = "data_exfiltrated"
    CODE_EXECUTION = "code_execution"
    TIMING_DELAY = "timing_delay"
    RESPONSE_DIFF = "response_diff"
    STATUS_CODE_CHANGE = "status_code_change"
    HEADER_CHANGE = "header_change"
    REFLECTION = "reflection"
    NONE = "none"


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


EVIDENCE_QUALITY_SCORES: Dict[EvidenceType, float] = {
    EvidenceType.DATABASE_ERROR: 0.95,
    EvidenceType.DATA_EXFILTRATED: 0.95,
    EvidenceType.CODE_EXECUTION: 0.98,
    EvidenceType.TIMING_DELAY: 0.70,
    EvidenceType.RESPONSE_DIFF: 0.50,
    EvidenceType.STATUS_CODE_CHANGE: 0.45,
    EvidenceType.HEADER_CHANGE: 0.40,
    EvidenceType.REFLECTION: 0.60,
    EvidenceType.NONE: 0.10,
}

SEVERITY_THRESHOLDS = {
    "critical": 60,
    "high": 70,
    "medium": 80,
    "low": 90,
}


@dataclass
class ResponseSample:
    status_code: int = 0
    response_length: int = 0
    response_time_ms: float = 0.0
    body_hash: str = ""
    contains_error: bool = False
    payload_used: str = ""


@dataclass
class ConfidenceResult:
    score: float = 0.0
    level: ConfidenceLevel = ConfidenceLevel.LOW
    breakdown: Dict[str, float] = field(default_factory=dict)
    rationale: str = ""
    is_reportable: bool = False
    needs_review: bool = True
    severity: str = "medium"

    @property
    def score_pct(self) -> int:
        return int(round(self.score * 100))


class ConfidenceScorer:

    WEIGHTS = {
        "response_consistency": 0.20,
        "timing_variance": 0.25,
        "evidence_quality": 0.35,
        "reproducibility": 0.15,
        "payload_specificity": 0.05,
    }

    def score(
        self,
        samples: List[ResponseSample],
        evidence_type: EvidenceType = EvidenceType.NONE,
        severity: str = "medium",
        payload: str = "",
        expected_timing_ms: float = 0.0,
        counterevidence: str = "",
    ) -> ConfidenceResult:

        if not samples:
            return ConfidenceResult(
                score=0.0, level=ConfidenceLevel.LOW,
                rationale="No response samples available",
                severity=severity,
            )

        c_response = self._score_response_consistency(samples)
        c_timing = self._score_timing_variance(samples, expected_timing_ms)
        c_evidence = EVIDENCE_QUALITY_SCORES.get(evidence_type, 0.10)
        c_repro = self._score_reproducibility(samples)
        c_payload = self._score_payload_specificity(payload)

        raw_score = (
            c_response * self.WEIGHTS["response_consistency"]
            + c_timing * self.WEIGHTS["timing_variance"]
            + c_evidence * self.WEIGHTS["evidence_quality"]
            + c_repro * self.WEIGHTS["reproducibility"]
            + c_payload * self.WEIGHTS["payload_specificity"]
        )

        # Counterevidence penalty
        if counterevidence:
            raw_score *= 0.85

        score = max(0.0, min(1.0, raw_score))
        threshold = SEVERITY_THRESHOLDS.get(severity, 80)
        is_reportable = (score * 100) >= threshold
        needs_review = not is_reportable and (score * 100) >= (threshold - 15)

        if score >= 0.8:
            level = ConfidenceLevel.HIGH
        elif score >= 0.5:
            level = ConfidenceLevel.MEDIUM
        else:
            level = ConfidenceLevel.LOW

        rationale = self._build_rationale(
            c_response, c_timing, c_evidence, c_repro, c_payload,
            evidence_type, len(samples), score, severity, counterevidence,
        )

        return ConfidenceResult(
            score=score,
            level=level,
            breakdown={
                "response_consistency": round(c_response, 3),
                "timing_variance": round(c_timing, 3),
                "evidence_quality": round(c_evidence, 3),
                "reproducibility": round(c_repro, 3),
                "payload_specificity": round(c_payload, 3),
            },
            rationale=rationale,
            is_reportable=is_reportable,
            needs_review=needs_review,
            severity=severity,
        )

    @staticmethod
    def _score_response_consistency(samples: List[ResponseSample]) -> float:
        if len(samples) < 2:
            return 0.5
        status_codes = [s.status_code for s in samples]
        most_common = max(set(status_codes), key=status_codes.count)
        consistency = status_codes.count(most_common) / len(status_codes)
        return consistency * 0.8 + 0.2

    @staticmethod
    def _score_timing_variance(samples: List[ResponseSample],
                                expected_ms: float = 0.0) -> float:
        if len(samples) < 2:
            return 0.5
        times = [s.response_time_ms for s in samples if s.response_time_ms > 0]
        if not times:
            return 0.5

        if expected_ms > 0:
            close_count = sum(1 for t in times if abs(t - expected_ms) < expected_ms * 0.3)
            return close_count / len(times)

        if len(times) < 2:
            return 0.5
        stdev = statistics.stdev(times)
        mean = statistics.mean(times)
        if mean == 0:
            return 0.5
        cv = stdev / mean
        if cv < 0.1:
            return 0.95
        elif cv < 0.3:
            return 0.75
        elif cv < 0.5:
            return 0.50
        else:
            return 0.25

    @staticmethod
    def _score_reproducibility(samples: List[ResponseSample]) -> float:
        if not samples:
            return 0.0
        success = sum(1 for s in samples if s.contains_error or s.status_code in (200, 500))
        return success / len(samples)

    @staticmethod
    def _score_payload_specificity(payload: str) -> float:
        if not payload:
            return 0.3

        specific_markers = [
            "UNION SELECT", "SLEEP(", "WAITFOR DELAY", "pg_sleep",
            "BENCHMARK(", "@@version", "information_schema",
            "LOAD_FILE", "INTO OUTFILE", "xp_cmdshell",
            "onerror=", "onload=", "onfocus=", "ontoggle=",
        ]
        generic_markers = [
            "OR '1'='1", "OR 1=1", "<script>alert",
            "../../", "../etc/passwd",
        ]

        payload_upper = payload.upper()
        for m in specific_markers:
            if m.upper() in payload_upper:
                return 0.85

        for m in generic_markers:
            if m.upper() in payload_upper:
                return 0.50

        return 0.30

    @staticmethod
    def _build_rationale(
        c_resp: float, c_timing: float, c_evidence: float,
        c_repro: float, c_payload: float,
        evidence_type: EvidenceType, sample_count: int,
        final_score: float, severity: str, counterevidence: str,
    ) -> str:
        parts = []
        if c_evidence >= 0.9:
            parts.append(f"{evidence_type.value} evidence (strong proof)")
        elif c_evidence >= 0.6:
            parts.append(f"{evidence_type.value} evidence (moderate)")
        else:
            parts.append(f"{evidence_type.value} evidence (weak)")

        if sample_count >= 3 and c_repro >= 0.8:
            parts.append(f"reproducible in {int(c_repro * sample_count)}/{sample_count} attempts")
        elif sample_count < 3:
            parts.append(f"only {sample_count} sample(s)")

        if c_timing >= 0.8:
            parts.append("consistent timing")
        elif c_timing < 0.4:
            parts.append("inconsistent timing (possible FP)")

        if counterevidence:
            parts.append(f"counterevidence noted")

        return "; ".join(parts)

    def classify_evidence_type(self, response_body: str, payload: str = "",
                                response_headers: Optional[Dict[str, str]] = None) -> EvidenceType:
        body_lower = response_body.lower() if response_body else ""

        sql_errors = [
            "sql syntax", "mysql", "postgresql", "ora-", "sqlite",
            "unclosed quotation", "syntax error", "pg::syntaxerror",
        ]
        if any(e in body_lower for e in sql_errors):
            return EvidenceType.DATABASE_ERROR

        if "alert(1)" in body_lower or "alert(document" in body_lower:
            if payload and ("<script" in payload.lower() or "onerror" in payload.lower()):
                return EvidenceType.REFLECTION

        if "root:x:0:0" in response_body or "uid=0(root)" in response_body:
            return EvidenceType.CODE_EXECUTION

        if "table_name" in body_lower and "information_schema" in body_lower:
            return EvidenceType.DATA_EXFILTRATED

        return EvidenceType.NONE

    def gate_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Split findings into reportable, needs_review, and rejected."""
        reportable = []
        needs_review = []
        rejected = []

        for f in findings:
            conf = f.get("confidence_result")
            if not conf:
                needs_review.append(f)
                continue

            if isinstance(conf, ConfidenceResult):
                if conf.is_reportable:
                    reportable.append(f)
                elif conf.needs_review:
                    needs_review.append(f)
                else:
                    rejected.append(f)
            elif isinstance(conf, dict):
                score = conf.get("score", 0)
                severity = f.get("severity", "medium")
                threshold = SEVERITY_THRESHOLDS.get(severity, 80)
                if score * 100 >= threshold:
                    reportable.append(f)
                elif score * 100 >= threshold - 15:
                    needs_review.append(f)
                else:
                    rejected.append(f)
            else:
                needs_review.append(f)

        logger.info(
            f"CONFIDENCE_GATE reportable={len(reportable)} "
            f"needs_review={len(needs_review)} rejected={len(rejected)}"
        )
        return reportable, needs_review, rejected
