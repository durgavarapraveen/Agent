"""
P0-3: separate observations from vulnerabilities.

Lifecycle: OBSERVATION -> INDICATOR -> HYPOTHESIS -> VALIDATION -> CONFIRMED_FINDING

Callers must NOT create a `Finding` directly from a raw HTTP 200 or a
discovered path. They record an `Observation` first, promote it to an
`Indicator`, generate a `Hypothesis`, and only after validation does it
become a real `Finding` via `promote_to_finding()`.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class KnowledgeType(str, Enum):
    ASSET = "asset"
    ENDPOINT = "endpoint"
    TECHNOLOGY = "technology"
    BEHAVIOR = "behavior"
    OBSERVATION = "observation"
    INDICATOR = "indicator"


class LifecycleStage(str, Enum):
    OBSERVATION = "observation"
    INDICATOR = "indicator"
    HYPOTHESIS = "hypothesis"
    VALIDATING = "validating"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


@dataclass
class Observation:
    """A raw, neutral fact captured from tool output. NOT a vulnerability."""
    obs_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    source_tool: str = ""
    kind: str = ""              # e.g. "http_200", "directory_listing", "header_missing"
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    stage: str = LifecycleStage.OBSERVATION.value
    confidence: float = 0.5
    created_at: datetime = field(default_factory=datetime.now)

    def promote(self, stage: LifecycleStage) -> None:
        self.stage = stage.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "obs_id": self.obs_id, "target": self.target,
            "source_tool": self.source_tool, "kind": self.kind,
            "description": self.description, "evidence": self.evidence,
            "stage": self.stage, "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class Hypothesis:
    """A candidate vulnerability that needs validation before becoming a Finding."""
    hyp_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    vuln_class: str = ""        # e.g. "IDOR", "SQLi", "SUBDOMAIN_TAKEOVER"
    target: str = ""
    endpoint: str = ""
    parameter: str = ""
    rationale: str = ""
    supporting_obs: List[str] = field(default_factory=list)
    validation_plan: str = ""
    stage: str = LifecycleStage.HYPOTHESIS.value
    priority: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hyp_id": self.hyp_id, "vuln_class": self.vuln_class,
            "target": self.target, "endpoint": self.endpoint,
            "parameter": self.parameter, "rationale": self.rationale,
            "supporting_obs": list(self.supporting_obs),
            "validation_plan": self.validation_plan,
            "stage": self.stage, "priority": self.priority,
        }


# Observation kinds that are NEVER on their own a vulnerability. The
# `promote_to_finding` gate refuses to convert these directly — they need
# an intervening indicator + validation.
_NON_VULN_OBSERVATIONS = {
    "http_200", "robots_txt_present", "sitemap_present", "api_reachable",
    "technology_detected", "banner_grabbed", "path_discovered",
    "header_present", "cors_permissive_header",
}

# Header-missing observations are indicators, not confirmed vulns — they
# only reach CONFIRMED after an exploit context (e.g. missing HSTS +
# insecure cookie + real login page).
_INDICATOR_ONLY = {
    "header_missing", "cookie_missing_secure", "cookie_missing_httponly",
    "directory_listing", "file_exposed", "verbose_error",
}


def is_confirmable_without_validation(kind: str) -> bool:
    """P0-3 gate: only allow direct promotion for pre-validated tool outputs
    (e.g. Nuclei matched a signed template) — everything else needs a
    hypothesis + evidence step first.
    """
    kind = (kind or "").lower()
    if kind in _NON_VULN_OBSERVATIONS or kind in _INDICATOR_ONLY:
        return False
    return kind in {"nuclei_confirmed", "sqlmap_confirmed", "exploit_verified"}


def promote_to_finding(obs: Observation, hypothesis: Optional[Hypothesis] = None,
                       validation_proof: str = "") -> Optional[Dict[str, Any]]:
    """Return a Finding-shaped dict if the promotion is legitimate.

    Rejects promotion when the observation kind isn't confirmable and no
    validation proof is supplied. This is the P0-3 firewall between
    "we saw something" and "we found a bug".
    """
    kind = (obs.kind or "").lower()
    if not is_confirmable_without_validation(kind) and not validation_proof:
        return None
    return {
        "title": (hypothesis.vuln_class + " on " + obs.target).strip() if hypothesis else obs.description,
        "type": (hypothesis.vuln_class if hypothesis else obs.kind).upper(),
        "target": obs.target,
        "location": (hypothesis.endpoint if hypothesis else obs.evidence.get("url", "")),
        "parameter": (hypothesis.parameter if hypothesis else ""),
        "details": obs.description,
        "proof": validation_proof or str(obs.evidence),
        "confidence_score": max(obs.confidence, 0.75 if validation_proof else 0.5),
        "status": "CONFIRMED" if validation_proof else "UNCONFIRMED",
        "source": obs.source_tool,
        "state": LifecycleStage.CONFIRMED.value if validation_proof else LifecycleStage.VALIDATING.value,
    }
