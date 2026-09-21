from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


def payload_id_for(vuln_class: str, payload_text: str) -> str:
    """Deterministic payload id (stable across processes)."""
    return hashlib.sha256(f"{vuln_class}|{payload_text}".encode()).hexdigest()[:16]


@dataclass
class Payload:
    """A single test payload — DATA, not code (P1 adaptive pipeline)."""
    vuln_class: str
    payload_text: str
    subclass: str = ""
    context: str = "url"              # html_body, html_attr, js, url, header, json_body
    encoding: str = "none"           # none, url, double_url, unicode, hex, base64
    evasion_tags: List[str] = field(default_factory=list)
    source: str = "custom"           # nuclei, payloadsallthethings, custom, llm_generated
    effectiveness_score: float = 0.5
    false_positive_rate: float = 0.0
    waf_bypass_for: List[str] = field(default_factory=list)
    confirm_patterns: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    times_used: int = 0
    times_confirmed: int = 0
    last_updated: str = ""
    payload_id: str = ""
    # ── §11 provenance (payload = auto-synced DATA, treated as hostile input) ──
    source_ref: str = ""             # commit hash / template id the payload came from
    source_url: str = ""             # upstream location for audit
    risk: str = "poc"                # observe | poc | elevated | destructive
    requires_oob: bool = False       # needs an out-of-band callback to confirm
    requires_write: bool = False     # state-changing (gated by impact ceiling)
    stage: str = "production"        # staging | canary | production

    def __post_init__(self):
        if not self.payload_id:
            self.payload_id = payload_id_for(self.vuln_class, self.payload_text)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Payload":
        allowed = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**allowed)


@dataclass
class InjectionContext:
    """Where/how a payload gets placed for one test."""
    endpoint: str
    parameter: str = ""
    context: str = "url"             # matches Payload.context
    detected_tech: List[str] = field(default_factory=list)
    detected_waf: Optional[str] = None
    method: str = "GET"


@dataclass
class PayloadSet:
    """A complete test plan for one (endpoint, parameter, vuln_class)."""
    endpoint: str
    parameter: str
    vuln_class: str
    payloads: List[Payload]
    budget: int = 20
    mutation_enabled: bool = False
    context: Optional[InjectionContext] = None
