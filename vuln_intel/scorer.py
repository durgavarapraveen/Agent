"""
Composite risk scoring.

Blends three independent signals into a single 0-100 risk score:
  - CVSS base score   (severity of the flaw)        weight 0.3
  - EPSS probability  (likelihood of exploitation)  weight 0.4
  - CISA KEV flag     (known exploited in the wild) weight 0.3

CVSS is normalized from its native 0-10 scale to 0-1 before weighting so all
three signals share a common range; the weighted sum is scaled to 0-100.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# Weights (must sum to 1.0)
W_CVSS = 0.3
W_EPSS = 0.4
W_KEV = 0.3


@dataclass
class RiskVerdict:
    """Structured composite-risk output for a single CVE."""
    cve_id: str
    score: float                 # 0-100 composite
    severity_label: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    epss_percentile: float       # 0-1
    kev_match: bool
    cvss_vector: str = ""
    cvss_base: float = 0.0
    components: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id, "score": self.score,
            "severity_label": self.severity_label,
            "epss_percentile": self.epss_percentile, "kev_match": self.kev_match,
            "cvss_vector": self.cvss_vector, "cvss_base": self.cvss_base,
            "components": self.components,
        }


def severity_from_score(score: float) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 10:
        return "LOW"
    return "INFO"


def compute_score(cvss_base: float, epss: float, kev: bool) -> float:
    """Composite 0-100 score from the three normalized signals."""
    cvss_n = max(0.0, min(10.0, float(cvss_base or 0.0))) / 10.0
    epss_n = max(0.0, min(1.0, float(epss or 0.0)))
    kev_n = 1.0 if kev else 0.0
    weighted = (cvss_n * W_CVSS) + (epss_n * W_EPSS) + (kev_n * W_KEV)
    return round(weighted * 100.0, 1)


def score_cve(cve_id: str, cvss_base: float = 0.0, epss: float = 0.0,
              kev: bool = False, cvss_vector: str = "") -> RiskVerdict:
    """Build a RiskVerdict from raw CVE signals."""
    score = compute_score(cvss_base, epss, kev)
    return RiskVerdict(
        cve_id=cve_id,
        score=score,
        severity_label=severity_from_score(score),
        epss_percentile=round(max(0.0, min(1.0, float(epss or 0.0))), 4),
        kev_match=bool(kev),
        cvss_vector=cvss_vector,
        cvss_base=round(float(cvss_base or 0.0), 1),
        components={
            "cvss_weighted": round((min(10.0, cvss_base) / 10.0) * W_CVSS * 100, 1),
            "epss_weighted": round(min(1.0, epss) * W_EPSS * 100, 1),
            "kev_weighted": round((1.0 if kev else 0.0) * W_KEV * 100, 1),
        },
    )


def rank(verdicts: List[RiskVerdict]) -> List[RiskVerdict]:
    """Sort verdicts by composite score, highest first."""
    return sorted(verdicts, key=lambda v: v.score, reverse=True)
