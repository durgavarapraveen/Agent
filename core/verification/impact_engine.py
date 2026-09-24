"""Impact validation (spec Phase 19/23).

Turns "a scanner returned 200 / a parameter was accepted / architecture is
visible" into an explicit, evidence-graded impact level. Deterministic — the
grade is derived from the finding's own evidence, never from an LLM's opinion —
so noisy classes (open redirect, information disclosure) are not elevated to
"vulnerability" without a concrete security consequence.

Impact levels (ordered):
    NO_IMPACT_PROVEN
    LOW_IMPACT_PROVEN
    RESOURCE_ACCESS_PROVEN
    PRIVILEGE_PROVEN
    SENSITIVE_DATA_ACCESS_PROVEN

`gate_finding` stamps ``impact_level`` and caps the lifecycle of a noisy-class
finding at SUSPECTED when no impact is proven, so the report stops treating
every accepted parameter as a confirmed vulnerability.
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Any, Dict, List, Tuple

from core.domain.finding_lifecycle import FindingLifecycle, advance, infer_lifecycle


class ImpactLevel(str, Enum):
    NO_IMPACT_PROVEN = "NO_IMPACT_PROVEN"
    LOW_IMPACT_PROVEN = "LOW_IMPACT_PROVEN"
    RESOURCE_ACCESS_PROVEN = "RESOURCE_ACCESS_PROVEN"
    PRIVILEGE_PROVEN = "PRIVILEGE_PROVEN"
    SENSITIVE_DATA_ACCESS_PROVEN = "SENSITIVE_DATA_ACCESS_PROVEN"


_IMPACT_ORDER = {
    ImpactLevel.NO_IMPACT_PROVEN: 0,
    ImpactLevel.LOW_IMPACT_PROVEN: 1,
    ImpactLevel.RESOURCE_ACCESS_PROVEN: 2,
    ImpactLevel.PRIVILEGE_PROVEN: 3,
    ImpactLevel.SENSITIVE_DATA_ACCESS_PROVEN: 4,
}

# Classes that scanners over-report; require real impact evidence to elevate.
_NOISY_CLASSES = {"open_redirect", "info_disclosure", "security_header",
                  "verbose_error", "version_disclosure"}

# Sensitive-data signatures in evidence text (deterministic).
_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                       # AWS access key id
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),     # private key
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),  # JWT
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),           # slack token
    re.compile(r"(?i)\b(api[_-]?key|secret|password|passwd)\b\s*[:=]\s*\S{6,}"),
    re.compile(r"ghp_[0-9A-Za-z]{30,}"),                   # github PAT
]
_PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                  # US SSN
    re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),            # visa-like PAN
]


def _class_of(finding: Dict[str, Any]) -> str:
    raw = " ".join(str(finding.get(k, "")) for k in
                   ("type", "category", "vuln_type", "title")).lower()
    if "redirect" in raw:
        return "open_redirect"
    if "idor" in raw or "bola" in raw or "broken object" in raw:
        return "idor"
    if "sqli" in raw or ("sql" in raw and "inject" in raw):
        return "sqli"
    if "privilege" in raw or "privesc" in raw or "authoriz" in raw or "access control" in raw:
        return "authz"
    if "disclosure" in raw or "information leak" in raw or "exposure" in raw:
        return "info_disclosure"
    if "missing" in raw and "header" in raw:
        return "security_header"
    if "xss" in raw or "cross-site scripting" in raw:
        return "xss"
    if "ssrf" in raw:
        return "ssrf"
    return "other"


def _evidence_text(finding: Dict[str, Any]) -> str:
    chunks: List[str] = []
    for k in ("proof", "evidence", "response", "response_body", "body",
              "extracted_data", "detail", "details", "observation"):
        v = finding.get(k)
        if isinstance(v, str):
            chunks.append(v)
        elif isinstance(v, (list, dict)):
            chunks.append(str(v))
    return "\n".join(chunks)


def _has_sensitive(text: str) -> bool:
    return any(p.search(text) for p in _SECRET_PATTERNS) or \
        any(p.search(text) for p in _PII_PATTERNS)


def assess_impact(finding: Dict[str, Any]) -> Tuple[ImpactLevel, List[str]]:
    """Grade proven impact from the finding's evidence. Returns (level, reasons)."""
    reasons: List[str] = []
    cls = _class_of(finding)
    text = _evidence_text(finding)

    # Explicit proof flags win.
    if finding.get("sensitive_data_accessed"):
        return ImpactLevel.SENSITIVE_DATA_ACCESS_PROVEN, ["sensitive_data_accessed flag"]
    if finding.get("privilege_gained") or finding.get("cross_identity_access"):
        return ImpactLevel.PRIVILEGE_PROVEN, ["privilege/cross-identity proof flag"]

    if _has_sensitive(text):
        reasons.append("secret/PII pattern present in evidence")
        return ImpactLevel.SENSITIVE_DATA_ACCESS_PROVEN, reasons

    if cls in ("sqli", "idor"):
        # Data actually returned for another object / via injection.
        if finding.get("data_returned") or finding.get("rows") or \
                finding.get("other_user_data") or "record" in text.lower():
            reasons.append(f"{cls}: data access evidence present")
            return ImpactLevel.RESOURCE_ACCESS_PROVEN, reasons
        reasons.append(f"{cls}: no data-access evidence")
        return ImpactLevel.LOW_IMPACT_PROVEN, reasons

    if cls == "authz":
        if finding.get("cross_identity_access") or finding.get("unauthorized_access"):
            return ImpactLevel.PRIVILEGE_PROVEN, ["authz: unauthorized access proven"]
        return ImpactLevel.LOW_IMPACT_PROVEN, ["authz: boundary not proven crossed"]

    if cls == "open_redirect":
        redirected = finding.get("redirect_occurred") or finding.get("redirect_location")
        off_origin = bool(finding.get("redirect_offsite") or finding.get("external_redirect"))
        touches_cred = finding.get("post_auth") or finding.get("token_in_redirect")
        if redirected and off_origin and touches_cred:
            reasons.append("redirect after auth / with token → credential-relevant")
            return ImpactLevel.RESOURCE_ACCESS_PROVEN, reasons
        if redirected and off_origin:
            reasons.append("off-site redirect occurs but no credential/auth impact")
            return ImpactLevel.LOW_IMPACT_PROVEN, reasons
        reasons.append("parameter accepted but no actual redirect proven")
        return ImpactLevel.NO_IMPACT_PROVEN, reasons

    if cls in ("info_disclosure", "security_header", "verbose_error", "version_disclosure"):
        reasons.append(f"{cls}: nothing secret/sensitive in exposed content")
        return ImpactLevel.NO_IMPACT_PROVEN, reasons

    if cls == "ssrf":
        # A demonstrated SSRF reaches an internal resource → resource access.
        if finding.get("exploited") or finding.get("executed") or finding.get("internal_reached"):
            return ImpactLevel.RESOURCE_ACCESS_PROVEN, ["ssrf: internal request demonstrated"]
        return ImpactLevel.LOW_IMPACT_PROVEN, ["ssrf: possible, not demonstrated"]

    if cls == "xss":
        # Code execution in the victim's browser is real but is EXPLOITED, not
        # proven data/privilege impact — keep it LOW so gate_finding leaves the
        # EXPLOITED lifecycle intact rather than over-advancing to IMPACT_CONFIRMED.
        return ImpactLevel.LOW_IMPACT_PROVEN, ["xss: execution class; impact depends on context"]

    return ImpactLevel.LOW_IMPACT_PROVEN, ["default: no specific impact rule matched"]


def impact_to_lifecycle(level: ImpactLevel) -> FindingLifecycle:
    if _IMPACT_ORDER[level] >= _IMPACT_ORDER[ImpactLevel.RESOURCE_ACCESS_PROVEN]:
        return FindingLifecycle.IMPACT_CONFIRMED
    return FindingLifecycle.SUSPECTED


def gate_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Stamp impact_level and reconcile lifecycle.

    - Proven impact (RESOURCE_ACCESS and above) advances the finding toward
      IMPACT_CONFIRMED.
    - A noisy-class finding with NO_IMPACT_PROVEN is capped at SUSPECTED — it is
      never allowed to read as a VALIDATED/EXPLOITED vulnerability on evidence of
      "the parameter was accepted".
    Deterministic and non-destructive; returns the same dict.
    """
    level, reasons = assess_impact(finding)
    finding["impact_level"] = level.value
    finding["impact_reasons"] = reasons

    current = infer_lifecycle(finding)
    cls = _class_of(finding)

    if _IMPACT_ORDER[level] >= _IMPACT_ORDER[ImpactLevel.RESOURCE_ACCESS_PROVEN]:
        finding["lifecycle"] = advance(current, FindingLifecycle.IMPACT_CONFIRMED).value
    elif cls in _NOISY_CLASSES and level == ImpactLevel.NO_IMPACT_PROVEN:
        # Cap noisy no-impact findings; never let them present as confirmed.
        finding["lifecycle"] = FindingLifecycle.SUSPECTED.value
        finding.setdefault("confidence_label", "INCONCLUSIVE")
    return finding
