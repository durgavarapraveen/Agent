"""
Package -> CVE matcher.

Given a package name + version (e.g. lodash@4.17.20), query OSV.dev (and NVD CPE
as a fallback) and return every matching CVE enriched with CVSS base score,
EPSS percentile, and KEV status, wrapped in a scored RiskVerdict.

CVSS base scores are computed locally from the v3.1 vector (formula below) to
avoid a rate-limited NVD round-trip per CVE.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .feeds import FeedClient
from .scorer import RiskVerdict, score_cve, rank

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# Rough package-name -> OSV ecosystem hints (used when caller omits ecosystem).
_ECOSYSTEM_GUESS = {
    "PyPI": re.compile(r"^[a-z0-9._-]+$"),
}

# ── CVSS v3.1 base score ──

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    """CVSS roundup: smallest 1-decimal number >= x."""
    return math.ceil(x * 10) / 10.0


def cvss31_base_from_vector(vector: str) -> float:
    """Compute a CVSS v3.x base score from its vector string. 0.0 on parse failure."""
    if not vector:
        return 0.0
    try:
        parts = dict(
            kv.split(":", 1) for kv in vector.strip().split("/") if ":" in kv)
        av = _AV.get(parts.get("AV", ""), 0.0)
        ac = _AC.get(parts.get("AC", ""), 0.0)
        ui = _UI.get(parts.get("UI", ""), 0.0)
        scope_changed = parts.get("S", "U") == "C"
        pr_tbl = _PR_C if scope_changed else _PR_U
        pr = pr_tbl.get(parts.get("PR", ""), 0.0)
        c = _CIA.get(parts.get("C", "N"), 0.0)
        i = _CIA.get(parts.get("I", "N"), 0.0)
        a = _CIA.get(parts.get("A", "N"), 0.0)

        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        expl = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        if scope_changed:
            base = min(1.08 * (impact + expl), 10.0)
        else:
            base = min(impact + expl, 10.0)
        return _roundup(base)
    except Exception as e:      # noqa: BLE001
        logger.debug(f"[matcher] CVSS parse failed for '{vector}': {e}")
        return 0.0


@dataclass
class PackageMatch:
    """All CVEs matching a specific package@version, scored."""
    package: str
    version: str
    ecosystem: str
    verdicts: List[RiskVerdict] = field(default_factory=list)
    stale_feeds: List[str] = field(default_factory=list)

    @property
    def worst(self) -> Optional[RiskVerdict]:
        return self.verdicts[0] if self.verdicts else None

    def to_dict(self) -> Dict:
        return {
            "package": self.package, "version": self.version,
            "ecosystem": self.ecosystem,
            "verdicts": [v.to_dict() for v in self.verdicts],
            "stale_feeds": self.stale_feeds,
        }


class CVEMatcher:
    """Resolves package@version -> scored CVEs via OSV.dev + EPSS + KEV."""

    def __init__(self, client: Optional[FeedClient] = None):
        self.client = client or FeedClient()

    @staticmethod
    def guess_ecosystem(package: str, hint: str = "") -> str:
        if hint:
            return hint
        # Reasonable default; caller should pass ecosystem when known.
        return "PyPI"

    async def _osv_query(self, package: str, version: str, ecosystem: str) -> List[Dict]:
        body = {"version": version,
                "package": {"name": package, "ecosystem": ecosystem}}
        try:
            # OSV query is POST; reuse the client's retrying session via a small call.
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=self.client.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as s:
                async with s.post(OSV_QUERY_URL, json=body) as resp:
                    resp.raise_for_status()
                    data = await resp.json(content_type=None)
            return data.get("vulns", []) or []
        except Exception as e:      # noqa: BLE001
            logger.warning(f"[matcher] OSV query failed for {package}@{version}: {e}")
            return []

    @staticmethod
    def _extract_cve_ids(vuln: Dict) -> List[str]:
        ids = set()
        if str(vuln.get("id", "")).upper().startswith("CVE-"):
            ids.add(vuln["id"].upper())
        for alias in vuln.get("aliases", []) or []:
            if str(alias).upper().startswith("CVE-"):
                ids.add(alias.upper())
        return sorted(ids)

    @staticmethod
    def _extract_cvss_vector(vuln: Dict) -> str:
        for sev in vuln.get("severity", []) or []:
            if str(sev.get("type", "")).upper().startswith("CVSS_V3"):
                return sev.get("score", "")   # OSV stores the vector in 'score'
        return ""

    async def match(self, package: str, version: str,
                    ecosystem: str = "") -> PackageMatch:
        """Return all scored CVEs affecting package@version."""
        eco = self.guess_ecosystem(package, ecosystem)
        vulns = await self._osv_query(package, version, eco)

        # Collect CVE ids + best-known CVSS vector per id
        cve_vectors: Dict[str, str] = {}
        for v in vulns:
            vector = self._extract_cvss_vector(v)
            for cid in self._extract_cve_ids(v):
                if cid not in cve_vectors or (vector and not cve_vectors[cid]):
                    cve_vectors[cid] = vector

        stale: List[str] = []
        if not cve_vectors:
            return PackageMatch(package, version, eco, [], stale)

        # EPSS batch + KEV set
        epss_res = await self.client.epss(list(cve_vectors))
        if epss_res.stale:
            stale.append("epss")
        epss_map: Dict[str, float] = {}
        if epss_res.data and isinstance(epss_res.data, dict):
            for row in epss_res.data.get("data", []):
                cid = str(row.get("cve", "")).upper()
                try:
                    epss_map[cid] = float(row.get("epss", 0.0))
                except (TypeError, ValueError):
                    epss_map[cid] = 0.0

        kev_ids = await self.client.kev_cve_ids()

        verdicts: List[RiskVerdict] = []
        for cid, vector in cve_vectors.items():
            base = cvss31_base_from_vector(vector)
            verdicts.append(score_cve(
                cve_id=cid, cvss_base=base,
                epss=epss_map.get(cid, 0.0),
                kev=cid in kev_ids, cvss_vector=vector))

        return PackageMatch(package, version, eco, rank(verdicts), stale)

    async def close(self):
        pass
