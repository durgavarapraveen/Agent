from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional


class TakeoverStage(str, Enum):
    DEAD_HOST = "DEAD_HOST"
    INDICATOR = "TAKEOVER_INDICATOR"
    VALIDATING = "VALIDATING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"


# Provider-specific body fingerprints (subset — grow as we see more).
PROVIDER_FINGERPRINTS = [
    (re.compile(r"nosuchbucket|the specified bucket does not exist", re.I), "s3"),
    (re.compile(r"there isn't a github pages site here", re.I), "github_pages"),
    (re.compile(r"project not found|application error|no such app", re.I), "heroku"),
    (re.compile(r"no such app|domain not configured", re.I), "vercel"),
    (re.compile(r"unrecognized|this domain is successfully pointed", re.I), "shopify"),
    (re.compile(r"do not have access|not found: requested route", re.I), "cloudfoundry"),
    (re.compile(r"repository not found", re.I), "bitbucket"),
    (re.compile(r"page not found|website not found", re.I), "azure_web"),
]


@dataclass
class TakeoverCandidate:
    fqdn: str
    status_code: int = 0
    body_sample: str = ""
    cname_target: str = ""
    provider: str = ""
    stage: TakeoverStage = TakeoverStage.DEAD_HOST
    reason: str = ""

    def as_dict(self) -> Dict:
        return {
            "fqdn": self.fqdn, "status_code": self.status_code,
            "provider": self.provider, "stage": self.stage.value,
            "reason": self.reason, "cname_target": self.cname_target,
        }


def resolve_cname(fqdn: str) -> str:
    try:
        # dnspython would be nicer, but socket.gethostbyname_ex returns aliases.
        _, aliases, _ = socket.gethostbyname_ex(fqdn)
        return (aliases[0] if aliases else "").lower()
    except Exception:
        return ""


def detect_indicator(fqdn: str, status_code: int, body: str) -> Optional[TakeoverCandidate]:
    cand = TakeoverCandidate(fqdn=fqdn, status_code=int(status_code or 0),
                             body_sample=(body or "")[:2048])
    for pat, prov in PROVIDER_FINGERPRINTS:
        if pat.search(cand.body_sample):
            cand.provider = prov
            cand.stage = TakeoverStage.INDICATOR
            cand.reason = f"provider fingerprint matched: {prov}"
            return cand
    if status_code in (0, 502, 503, 504):
        cand.stage = TakeoverStage.DEAD_HOST
        cand.reason = f"unreachable/error status {status_code}"
        return cand
    return None


def validate(candidate: TakeoverCandidate) -> TakeoverCandidate:
    if candidate.stage not in (TakeoverStage.INDICATOR, TakeoverStage.DEAD_HOST):
        return candidate
    candidate.stage = TakeoverStage.VALIDATING
    cname = resolve_cname(candidate.fqdn)
    candidate.cname_target = cname
    if candidate.provider:
        # Provider fingerprint + host resolves to a provider domain we don't own.
        provider_hosts = {
            "s3": "amazonaws.com", "github_pages": "github.io",
            "heroku": "herokuapp.com", "vercel": "vercel-dns.com",
            "shopify": "myshopify.com", "azure_web": "azurewebsites.net",
            "cloudfoundry": "cfapps.io", "bitbucket": "bitbucket.io",
        }
        needle = provider_hosts.get(candidate.provider, "")
        if cname and needle and needle in cname:
            candidate.stage = TakeoverStage.CONFIRMED
            candidate.reason = f"fingerprint {candidate.provider} + CNAME->{cname}"
            return candidate
    # No corroborating DNS evidence — reject rather than false-positive.
    candidate.stage = TakeoverStage.REJECTED
    candidate.reason = candidate.reason + " (no DNS corroboration)"
    return candidate
