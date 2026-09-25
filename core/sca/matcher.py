"""Version-range vulnerability matching (spec §5).

Compares a parsed package's version against advisory ranges. Uses
``packaging.version`` when the version is PEP 440 / semver-parseable and falls
back to a tolerant numeric-tuple compare otherwise, so it works across
ecosystems without an ecosystem-specific version library.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

from core.sca.advisories import Advisory, AdvisorySource, Range
from core.sca.parsers import Package

logger = logging.getLogger(__name__)

try:
    from packaging.version import Version, InvalidVersion  # type: ignore
except Exception:  # pragma: no cover
    Version = None
    InvalidVersion = Exception


def _tuple(v: str):
    parts = re.split(r"[.\-+_]", v.strip().lstrip("vV"))
    out = []
    for p in parts:
        m = re.match(r"^(\d+)", p)
        out.append(int(m.group(1)) if m else 0)
    return tuple(out) or (0,)


def _cmp(a: str, b: str) -> int:
    """Return -1/0/1 for a<b / a==b / a>b."""
    if Version is not None:
        try:
            va, vb = Version(a), Version(b)
            return (va > vb) - (va < vb)
        except InvalidVersion:
            pass
    ta, tb = _tuple(a), _tuple(b)
    return (ta > tb) - (ta < tb)


def version_in_range(version: str, r: Range) -> bool:
    """introduced <= version < fixed (fixed empty = unbounded above)."""
    if not version:
        return False
    if r.introduced and r.introduced not in ("0", ""):
        if _cmp(version, r.introduced) < 0:
            return False
    if r.fixed:
        if _cmp(version, r.fixed) >= 0:
            return False
    return True


def is_vulnerable(version: str, adv: Advisory) -> bool:
    if not adv.ranges:
        return False  # no range → cannot assert vulnerability (fail closed)
    return any(version_in_range(version, r) for r in adv.ranges)


def match(packages: List[Package], source: AdvisorySource) -> List[Dict[str, Any]]:
    """Return one finding per (package, matching advisory)."""
    findings: List[Dict[str, Any]] = []
    for pkg in packages:
        for adv in source.get(pkg.ecosystem, pkg.name):
            if not is_vulnerable(pkg.version, adv):
                continue
            fixed = next((r.fixed for r in adv.ranges if r.fixed), "")
            findings.append({
                "type": "VULNERABLE_DEPENDENCY",
                "title": f"Vulnerable dependency: {pkg.name} {pkg.version}"
                         f" ({adv.cve or adv.id})",
                "severity": adv.severity,
                "location": pkg.path or f"{pkg.ecosystem}:{pkg.name}",
                "proof": f"{pkg.ecosystem} {pkg.name}=={pkg.version} affected by "
                         f"{adv.id}"
                         + (f" (fixed in {fixed})" if fixed else " (no fix available)"),
                "tool": "sca",
                "source": "sca",
                "confidence_score": 0.9,
                "package": pkg.name,
                "installed_version": pkg.version,
                "fixed_version": fixed,
                "advisory_id": adv.id,
                "cve": adv.cve,
                "cwe": adv.cwe,
                "ecosystem": pkg.ecosystem,
                "summary": adv.summary,
            })
    return findings
