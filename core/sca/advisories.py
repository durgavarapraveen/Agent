"""Vulnerability advisory sources (spec §5, §37).

An advisory names a vulnerable package, its ecosystem, affected version ranges,
severity and identifiers. ``StaticAdvisorySource`` serves a supplied advisory
set (offline analysis + deterministic tests). ``OsvSource`` is the live
integration point: it queries the OSV.dev API and returns [] when offline or
the ``requests`` dependency is absent — it never invents advisories.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@dataclass
class Range:
    introduced: str = "0"   # inclusive lower bound
    fixed: str = ""          # exclusive upper bound ("" = never fixed / all above)


@dataclass
class Advisory:
    id: str
    ecosystem: str
    package: str
    ranges: List[Range] = field(default_factory=list)
    severity: str = "HIGH"
    summary: str = ""
    cve: str = ""
    cwe: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Advisory":
        ranges = [Range(introduced=str(r.get("introduced", "0")),
                        fixed=str(r.get("fixed", "")))
                  for r in (d.get("ranges") or [])]
        if not ranges and (d.get("introduced") is not None or d.get("fixed") is not None):
            ranges = [Range(introduced=str(d.get("introduced", "0")),
                            fixed=str(d.get("fixed", "")))]
        adv_id = d.get("id", d.get("cve", "ADVISORY"))
        cve = d.get("cve", "")
        if not cve and str(adv_id).upper().startswith("CVE-"):
            cve = adv_id  # the advisory id is itself a CVE
        return cls(
            id=adv_id,
            ecosystem=d.get("ecosystem", ""),
            package=d.get("package", ""),
            ranges=ranges,
            severity=str(d.get("severity", "HIGH")).upper(),
            summary=d.get("summary", ""),
            cve=cve,
            cwe=list(d.get("cwe", []) or []),
        )


@runtime_checkable
class AdvisorySource(Protocol):
    def get(self, ecosystem: str, package: str) -> List[Advisory]:
        ...


class StaticAdvisorySource:
    """Index a supplied advisory list by (ecosystem, package-lowercased)."""

    def __init__(self, advisories: List[Any] = None):
        self._index: Dict[tuple, List[Advisory]] = {}
        for a in advisories or []:
            adv = a if isinstance(a, Advisory) else Advisory.from_dict(a)
            self._index.setdefault(
                (adv.ecosystem, adv.package.lower()), []).append(adv)

    def get(self, ecosystem: str, package: str) -> List[Advisory]:
        return self._index.get((ecosystem, package.lower()), [])


class OsvSource:
    """Live OSV.dev advisory source (integration point).

    Best-effort: returns [] if ``requests`` is unavailable or the query fails,
    so offline runs degrade to "no advisories" rather than error.
    """

    ENDPOINT = "https://api.osv.dev/v1/query"

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    def get(self, ecosystem: str, package: str) -> List[Advisory]:
        try:
            import requests  # lazy soft dependency
        except Exception:
            logger.debug("[sca] requests not installed — OSV lookup skipped")
            return []
        try:
            resp = requests.post(
                self.ENDPOINT,
                json={"package": {"ecosystem": ecosystem, "name": package}},
                timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.debug("[sca] OSV query %s/%s failed: %s", ecosystem, package, e)
            return []
        return [self._from_osv(v, ecosystem, package)
                for v in (data.get("vulns") or [])]

    @staticmethod
    def _from_osv(v: Dict[str, Any], ecosystem: str, package: str) -> Advisory:
        ranges: List[Range] = []
        for aff in v.get("affected", []) or []:
            for r in aff.get("ranges", []) or []:
                cur = Range()
                for ev in r.get("events", []) or []:
                    if "introduced" in ev:
                        cur = Range(introduced=str(ev["introduced"]))
                    if "fixed" in ev:
                        cur.fixed = str(ev["fixed"])
                        ranges.append(cur)
                        cur = Range()
        sev = "HIGH"
        for s in v.get("severity", []) or []:
            if s.get("type") == "CVSS_V3":
                sev = "CRITICAL"  # coarse; refine downstream if needed
        return Advisory(
            id=v.get("id", "OSV"), ecosystem=ecosystem, package=package,
            ranges=ranges, severity=sev, summary=v.get("summary", ""),
            cve=next((a for a in v.get("aliases", []) if a.startswith("CVE-")), ""),
        )
