"""
Finding confidence scoring.

Turns raw evidence signals into a confidence level so that low-quality (often
false-positive) findings don't pollute the main report.

Scoring (additive, 0-100):
  version_match_exact -> +40   (the installed version is definitively affected)
  reachable           -> +30   (vulnerable symbol reachable from an entry point)
  epss > 0.1          -> +15   (non-trivial real-world exploitation probability)
  kev_match           -> +15   (known exploited in the wild)

Thresholds:
  >= 70 -> HIGH
  40-69 -> MEDIUM
  <  40 -> LOW

LOW-confidence findings are routed to a `needs_review` queue rather than the
main report. Every verdict carries an evidence array explaining each factor.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

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


@dataclass
class ConfidenceVerdict:
    level: str                       # HIGH | MEDIUM | LOW
    score: int
    evidence: List[str] = field(default_factory=list)
    needs_review: bool = False       # True when level == LOW

    def to_dict(self) -> Dict:
        return {"level": self.level, "score": self.score,
                "evidence": self.evidence, "needs_review": self.needs_review}


def assess(*, version_match_exact: bool = False, reachable: bool = False,
           epss: float = 0.0, kev_match: bool = False) -> ConfidenceVerdict:
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
    return ConfidenceVerdict(level=level, score=score, evidence=evidence,
                             needs_review=(level == LOW))


def _is_directly_confirmed(finding: Dict) -> bool:
    """A finding demonstrated in practice (successful exploit / concrete proof)
    is the strongest possible evidence — stronger than static reachability."""
    if finding.get("confirmed") or finding.get("from_llm_final"):
        return True
    proof = str(finding.get("proof", "")).strip()
    if proof:
        return True
    data = finding.get("data") or {}
    return bool(isinstance(data, dict) and data.get("confirmed"))


def assess_finding(finding: Dict,
                   reachable_status: Optional[str] = None) -> ConfidenceVerdict:
    """Assess a finding dict. Understands common signal keys.

    Recognized keys: version_match_exact/exact_version_match, reachable
    (bool) or reachable_status ('reachable'), epss/epss_percentile, kev_match.
    A finding that was directly confirmed by active exploitation short-circuits
    to HIGH confidence (a demonstrated exploit is the strongest evidence there is).
    """
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
        version_match_exact=bool(finding.get("version_match_exact")
                                 or finding.get("exact_version_match")),
        reachable=reachable,
        epss=float(finding.get("epss", finding.get("epss_percentile", 0.0)) or 0.0),
        kev_match=bool(finding.get("kev_match")),
    )


def gate(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """Split findings into report-worthy vs. needs_review by confidence.

    Each finding gets a '_confidence' dict attached. LOW confidence -> needs_review.
    Returns {'report': [...], 'needs_review': [...]}.
    """
    report, review = [], []
    for f in findings:
        verdict = assess_finding(f)
        f["_confidence"] = verdict.to_dict()
        if verdict.needs_review:
            review.append(f)
        else:
            report.append(f)
    logger.info(f"[confidence] {len(report)} reportable, {len(review)} need review")
    return {"report": report, "needs_review": review}
