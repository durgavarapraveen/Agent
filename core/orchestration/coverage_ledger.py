"""Coverage ledger — turns "did we test it?" into an enumerable artifact.

The scanner's coverage was a single percentage (which historically exploded or
collapsed). This makes coverage a *matrix*: for every applicable
``(surface, vuln_class)`` pair the scanner emits exactly one verdict —

    CONFIRMED   a confirmed finding exists for that surface+class
    REFUTED     the class's family ran against that surface, found nothing
    ERROR       the probe raised (surface tested, result unknown)
    NOT_RUN     nothing tested it — the silent-miss case we care about

The applicable side is free: ``SurfaceClassifier`` already tags every Surface
with ``applicable_classes`` (OracleEngine keys). We reconcile that against
``ctx.vulnerabilities`` (per-(location,class) precision) and the family-level
run ledger (``brain._coverage_ran``) to resolve ran-vs-never-ran.

Granularity is ``(surface.url|method, vuln_class)``. Run-ness is resolved at
*family* granularity (a class's family ran) because probes report findings, not
per-point negatives — so REFUTED means "tested, nothing found", NOT_RUN means
"no probe for this class's family executed on this surface". The NOT_RUN list is
the deliverable: it fails loud instead of a scan silently skipping a class.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class Verdict:
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    ERROR = "ERROR"
    NOT_RUN = "NOT_RUN"


# OracleEngine vuln-class key -> the TestFamily whose probes cover it. Used only
# to resolve "did a probe for this class run on this surface". Kept central and
# small; unknown classes fall back to API (always scheduled) so they are never
# spuriously reported NOT_RUN.
_CLASS_FAMILY = {
    "SQLI": "injection", "NOSQLI": "injection", "XSS": "injection",
    "SSTI": "injection", "RCE": "injection", "COMMAND_INJECTION": "injection",
    "LFI": "injection", "PATH_TRAVERSAL": "injection", "XXE": "injection",
    "LDAP": "injection", "XPATH": "injection", "EMAIL_INJECTION": "injection",
    "CRLF": "injection", "SSI": "injection", "DESERIALIZATION": "injection",
    "PROTOTYPE_POLLUTION": "injection", "SECOND_ORDER": "injection",
    "OPEN_REDIRECT": "api", "SSRF": "api", "MASS_ASSIGNMENT": "api",
    "HPP": "api", "CORS": "api", "GRAPHQL": "api", "IDOR": "authz_idor",
    "BOLA": "authz_idor", "BROKEN_ACCESS_CONTROL": "authz_idor",
    "JWT": "auth_session", "SESSION": "auth_session", "CSRF": "auth_session",
    "AUTH_BYPASS": "auth_session", "FILE_UPLOAD": "file_upload",
    "RACE": "race", "BUSINESS_LOGIC": "business_logic",
    "RATE_LIMIT": "rate_limit", "CACHE_POISONING": "infra_config",
    "HOST_HEADER": "infra_config", "CLICKJACKING": "infra_config",
    "SMUGGLING": "infra_config", "SECRET_EXPOSURE": "secret_disclosure",
}
_DEFAULT_FAMILY = "api"

# Classes whose HIGH-confidence confirmation needs an out-of-band callback.
# Without an active collaborator these fall back to body-regex only (reduced
# confidence) — the ledger flags that so degraded coverage is never silent.
_OOB_DEPENDENT = {"SSRF", "RCE", "COMMAND_INJECTION", "XXE", "DNS_REBINDING"}


def _oob_active() -> bool:
    try:
        from core.oob.collaborator import get_collaborator
        return bool(get_collaborator().is_active())
    except Exception:
        return False


def _class_family(vuln_class: str) -> str:
    return _CLASS_FAMILY.get((vuln_class or "").upper(), _DEFAULT_FAMILY)


def _norm_loc(loc: str) -> str:
    """Normalise a URL/location to host+path for lenient matching."""
    s = (loc or "").strip().lower()
    if not s:
        return ""
    try:
        import urllib.parse as _u
        p = _u.urlsplit(s if "://" in s else "//" + s)
        return f"{p.netloc}{p.path}".rstrip("/") or p.path
    except Exception:
        return s.split("?", 1)[0].rstrip("/")


@dataclass
class Cell:
    surface: str          # host+path|method
    vuln_class: str
    verdict: str = Verdict.NOT_RUN
    detail: str = ""


@dataclass
class CoverageLedger:
    cells: Dict[str, Cell] = field(default_factory=dict)
    families_ran: Set[str] = field(default_factory=set)

    @staticmethod
    def _key(surface: str, vuln_class: str) -> str:
        return f"{surface}##{vuln_class.upper()}"

    def _applicable(self, ctx) -> None:
        """Seed one NOT_RUN cell per (surface, applicable_class)."""
        try:
            from core.recon.surface_classifier import get_surface_classifier
            surfaces = get_surface_classifier().classify(ctx) or []
        except Exception as e:
            logger.debug("[CoverageLedger] classify failed: %s", e)
            surfaces = []
        for s in surfaces:
            skey = f"{_norm_loc(getattr(s, 'url', ''))}|{getattr(s, 'method', 'GET')}"
            for cls in (getattr(s, "applicable_classes", None) or []):
                k = self._key(skey, cls)
                self.cells.setdefault(k, Cell(skey, str(cls).upper()))

    def _reconcile_findings(self, ctx) -> None:
        """Upgrade cells from ctx.vulnerabilities: CONFIRMED status wins; an
        unconfirmed finding marks REFUTED (tested, not proven)."""
        vulns = getattr(ctx, "vulnerabilities", None) or []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            vloc = _norm_loc(v.get("location") or v.get("target") or v.get("url") or "")
            vclass = (v.get("type") or "").upper()
            if not vclass:
                continue
            confirmed = str(v.get("status") or "").upper() == "CONFIRMED"
            # Match any applicable cell whose surface shares the finding's path.
            for k, cell in self.cells.items():
                if cell.vuln_class != vclass:
                    continue
                cpath = cell.surface.split("|", 1)[0]
                if not (vloc and cpath and (vloc == cpath or vloc.endswith(cpath)
                                            or cpath.endswith(vloc))):
                    continue
                if confirmed:
                    cell.verdict = Verdict.CONFIRMED
                    cell.detail = (v.get("title") or vclass)[:120]
                elif cell.verdict == Verdict.NOT_RUN:
                    cell.verdict = Verdict.REFUTED
                    cell.detail = "finding present, unconfirmed"

    def _reconcile_ran(self, coverage_ran: Optional[Set[str]]) -> None:
        """Any cell still NOT_RUN whose class-family ran becomes REFUTED
        (family executed, produced no finding for this surface+class)."""
        fams = set()
        for u in (coverage_ran or set()):
            # ledger keys look like 'active_scanning:injection' / 'recon:web'
            fams.add(str(u).split(":", 1)[-1])
        self.families_ran = fams
        if not fams:
            return
        for cell in self.cells.values():
            if cell.verdict != Verdict.NOT_RUN:
                continue
            if _class_family(cell.vuln_class) in fams:
                cell.verdict = Verdict.REFUTED
                cell.detail = "family ran, no finding"

    def build(self, ctx, coverage_ran: Optional[Set[str]] = None) -> "CoverageLedger":
        self._applicable(ctx)
        self._reconcile_findings(ctx)
        self._reconcile_ran(coverage_ran)
        return self

    # ── reporting ────────────────────────────────────────────────────────────
    def summary(self) -> Dict[str, int]:
        out = {Verdict.CONFIRMED: 0, Verdict.REFUTED: 0,
               Verdict.ERROR: 0, Verdict.NOT_RUN: 0}
        for c in self.cells.values():
            out[c.verdict] = out.get(c.verdict, 0) + 1
        out["total"] = len(self.cells)
        return out

    def not_run(self) -> List[Dict[str, str]]:
        return [{"surface": c.surface, "class": c.vuln_class}
                for c in self.cells.values() if c.verdict == Verdict.NOT_RUN]

    def to_report(self) -> Dict[str, Any]:
        return {
            "summary": self.summary(),
            "families_ran": sorted(self.families_ran),
            "not_run": self.not_run(),
            "cells": [{"surface": c.surface, "class": c.vuln_class,
                       "verdict": c.verdict, "detail": c.detail}
                      for c in sorted(self.cells.values(),
                                      key=lambda x: (x.surface, x.vuln_class))],
        }


def build_and_log(ctx, coverage_ran: Optional[Set[str]] = None) -> Dict[str, Any]:
    """Build the ledger, attach it to ctx.coverage_ledger, and log loud on any
    NOT_RUN cell. Never raises. Returns the report dict."""
    try:
        ledger = CoverageLedger().build(ctx, coverage_ran)
        report = ledger.to_report()
    except Exception as e:
        logger.warning("[CoverageLedger] build failed (non-fatal): %s", e)
        return {}

    # OOB confidence status — mark blind classes degraded when no collaborator.
    oob_active = _oob_active()
    report["oob_active"] = oob_active
    if not oob_active:
        present = sorted({c["class"] for c in report.get("cells", [])
                          if c["class"] in _OOB_DEPENDENT})
        report["oob_degraded_classes"] = present
        if present:
            logger.warning("[CoverageLedger] OOB collaborator INACTIVE — %s confirmed "
                           "by body-signal only (blind cases missed). Set "
                           "OOB_COLLABORATOR_URL + OOB_DOMAIN for full confidence.",
                           ", ".join(present))
    # Authorization coverage gaps (missing identities) — surfaced loud, not silent.
    azu = getattr(ctx, "authz_coverage_unknown", None)
    if isinstance(azu, list) and azu:
        report["authz_coverage_unknown"] = azu[:50]
        eps = sorted({str(x.get("endpoint", "")) for x in azu if isinstance(x, dict)})
        logger.warning("[CoverageLedger] authorization coverage UNKNOWN on %d endpoint(s) "
                       "(missing identities) — enable AUTH_SELF_REGISTER or supply >=2 "
                       "identities: %s", len(eps), ", ".join(eps[:10]))
    try:
        setattr(ctx, "coverage_ledger", report)
    except Exception:
        pass
    s = report.get("summary", {})
    nr = report.get("not_run", [])
    if nr:
        logger.warning("[CoverageLedger] %d/%d (surface,class) pairs NOT_RUN — "
                       "coverage gaps: %s%s",
                       len(nr), s.get("total", 0),
                       ", ".join(sorted({r["class"] for r in nr})[:15]),
                       " …" if len(nr) > 15 else "")
    else:
        logger.info("[CoverageLedger] all %d applicable (surface,class) pairs tested "
                    "(%d confirmed, %d refuted)", s.get("total", 0),
                    s.get(Verdict.CONFIRMED, 0), s.get(Verdict.REFUTED, 0))
    return report
