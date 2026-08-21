"""
vuln_intel — Live vulnerability-intelligence pipeline.

Public interface:
  FeedClient     — async NVD/EPSS/KEV fetchers with SQLite cache + retry.
  CVEMatcher     — package@version -> scored CVEs (OSV.dev + EPSS + KEV).
  PackageMatch   — matcher result container.
  RiskVerdict    — composite-risk output.
  score_cve / compute_score / severity_from_score — scoring helpers.
"""

from .feeds import FeedClient, FeedResult, CacheDB
from .matcher import CVEMatcher, PackageMatch, cvss31_base_from_vector
from .scorer import (RiskVerdict, score_cve, compute_score,
                     severity_from_score, rank)

__all__ = [
    "FeedClient", "FeedResult", "CacheDB",
    "CVEMatcher", "PackageMatch", "cvss31_base_from_vector",
    "RiskVerdict", "score_cve", "compute_score", "severity_from_score", "rank",
]
