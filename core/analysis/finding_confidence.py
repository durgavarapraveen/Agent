from __future__ import annotations

import re
from enum import Enum
from typing import Dict

_STATUS_NOISE = {500, 502, 503, 504, 406}
_IMPACT_KW = (
    "returned", "extracted", "dumped", "leaked", "token", "password", "admin",
    "unauthor", "bypass", "access to", "record", "row", "user id", "arbitrary",
    "executed", "rce", "reflected in", "alert(", "disclosed", "read file",
    "other user", "another user", "credential", "session",
)


class FindingConfidence(str, Enum):
    SUSPECTED = "SUSPECTED"
    LIKELY = "LIKELY"
    CONFIRMED = "CONFIRMED"
    NEGATIVE = "NEGATIVE"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"


def _only_status_evidence(vuln: Dict) -> bool:
    proof = str(vuln.get("proof") or vuln.get("details") or "")
    codes = {int(x) for x in re.findall(r"\bHTTP\s*[/]?[0-9.]*\s*(\d{3})\b", proof)}
    for k in ("http_status", "status_code", "status"):
        v = vuln.get(k)
        try:
            iv = int(v)
            if 100 <= iv <= 599:
                codes.add(iv)
        except (TypeError, ValueError):
            pass
    if not codes:
        return False
    has_impact = any(k in proof.lower() for k in _IMPACT_KW)
    return codes.issubset(_STATUS_NOISE) and not has_impact


def classify(vuln: Dict) -> str:
    st = str(vuln.get("status", "")).upper()
    rep = str(vuln.get("reproducibility_status", "")).upper()

    if st in ("NEGATIVE", "FALSE_POSITIVE", "NOT_VULNERABLE"):
        return FindingConfidence.NEGATIVE.value
    if st in ("BLOCKED", "WAF_BLOCKED"):
        return FindingConfidence.BLOCKED.value

    explicit_confirmed = (vuln.get("confirmed") is True
                          or st == "CONFIRMED" or rep == "CONFIRMED")
    if explicit_confirmed:
        # A "confirmation" resting only on a noisy status is not real proof.
        return (FindingConfidence.INCONCLUSIVE.value if _only_status_evidence(vuln)
                else FindingConfidence.CONFIRMED.value)

    cs = vuln.get("confidence_score")
    if isinstance(cs, (int, float)):
        c = cs if cs <= 1.0 else cs / 100.0
        if c >= 0.85:
            return FindingConfidence.LIKELY.value
        if c <= 0.2:
            return FindingConfidence.INCONCLUSIVE.value

    if _only_status_evidence(vuln):
        return FindingConfidence.INCONCLUSIVE.value
    return FindingConfidence.SUSPECTED.value
