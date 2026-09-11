from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List


class AssetClass(str, Enum):
    LIVE_APP = "LIVE_APP"
    API = "API"
    STATIC_SITE = "STATIC_SITE"
    DOCUMENTATION = "DOCUMENTATION"
    REDIRECTOR = "REDIRECTOR"
    DEAD_HOST = "DEAD_HOST"
    TAKEOVER_CANDIDATE = "TAKEOVER_CANDIDATE"
    UNKNOWN = "UNKNOWN"


# Routing table: which capability set is appropriate per class.
WORKFLOW_BY_CLASS: Dict[AssetClass, List[str]] = {
    AssetClass.LIVE_APP: [
        "authentication_testing", "access_control", "sql_injection",
        "xss_scanning", "ssrf", "idor", "csrf", "business_logic",
    ],
    AssetClass.API: [
        "authentication_testing", "access_control", "sql_injection",
        "graphql_introspection", "mass_assignment", "rate_limiting",
    ],
    AssetClass.STATIC_SITE: [
        "exposure_check", "header_analysis", "tls_analysis",
    ],
    AssetClass.DOCUMENTATION: [
        "header_analysis", "tls_analysis",
    ],
    AssetClass.REDIRECTOR: [
        "open_redirect_check", "header_analysis",
    ],
    AssetClass.DEAD_HOST: [
        "takeover_validation",
    ],
    AssetClass.TAKEOVER_CANDIDATE: [
        "takeover_validation",
    ],
    AssetClass.UNKNOWN: [
        "technology_fingerprinting", "waf_detection",
    ],
}


@dataclass
class AssetProfile:
    host: str
    status_code: int = 0
    server: str = ""
    content_type: str = ""
    body_sample: str = ""
    title: str = ""
    is_redirect: bool = False
    redirect_target: str = ""
    is_login_present: bool = False
    is_api_shape: bool = False
    provider_indicators: List[str] = None


def classify(profile: AssetProfile) -> AssetClass:
    sc = int(profile.status_code or 0)
    body = (profile.body_sample or "").lower()
    ct = (profile.content_type or "").lower()
    title = (profile.title or "").lower()
    server = (profile.server or "").lower()
    providers = [p.lower() for p in (profile.provider_indicators or [])]

    # Dead hosts / provider default pages -> takeover candidates.
    if sc in (0, 502, 503, 504):
        for hint in ("nosuchbucket", "no such app", "there isn't a github pages site here",
                     "project not found", "domain not configured"):
            if hint in body:
                return AssetClass.TAKEOVER_CANDIDATE
        return AssetClass.DEAD_HOST

    if profile.is_redirect and sc in (301, 302, 307, 308):
        return AssetClass.REDIRECTOR

    if profile.is_api_shape or "application/json" in ct or "application/xml" in ct:
        return AssetClass.API

    if any(marker in title for marker in ("docs", "documentation", "api reference", "swagger")):
        return AssetClass.DOCUMENTATION
    if any(marker in body for marker in ("readthedocs", "gitbook", "mkdocs")):
        return AssetClass.DOCUMENTATION

    if 200 <= sc < 300:
        if profile.is_login_present or any(
            m in body for m in ("<form", "login", "sign in", "password")
        ):
            return AssetClass.LIVE_APP
        # Static hosting providers
        if any(p in providers for p in ("cloudfront", "netlify", "vercel", "github-pages")):
            return AssetClass.STATIC_SITE
        if "text/html" in ct and len(body) < 2048:
            return AssetClass.STATIC_SITE
        if "text/html" in ct:
            return AssetClass.LIVE_APP

    return AssetClass.UNKNOWN


def workflow_for(cls: AssetClass) -> List[str]:
    return WORKFLOW_BY_CLASS.get(cls, WORKFLOW_BY_CLASS[AssetClass.UNKNOWN])
