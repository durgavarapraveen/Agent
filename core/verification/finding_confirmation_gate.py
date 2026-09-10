from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ConfirmationStage(str, Enum):
    CANDIDATE = "candidate"
    SUPPORTED = "supported"
    REPRODUCED = "reproduced"
    IMPACT_VERIFIED = "impact_verified"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class EvidenceType(str, Enum):
    HTTP_RESPONSE_DIFF = "http_response_diff"
    BODY_CONTAINS_MARKER = "body_contains_marker"
    REFLECTED_PAYLOAD = "reflected_payload"
    ERROR_MESSAGE_LEAK = "error_message_leak"
    DATA_EXFILTRATION = "data_exfiltration"
    AUTH_BYPASS_PROOF = "auth_bypass_proof"
    CROSS_IDENTITY_ACCESS = "cross_identity_access"
    COMMAND_OUTPUT = "command_output"
    FILE_CONTENT_LEAK = "file_content_leak"
    TIME_BASED_DIFF = "time_based_diff"
    DNS_INTERACTION = "dns_interaction"
    STATUS_CODE_CHANGE = "status_code_change"
    REDIRECT_TO_ATTACKER = "redirect_to_attacker"
    DESERIALIZATION_PROOF = "deserialization_proof"
    REPRODUCTION_MATCH = "reproduction_match"


@dataclass(frozen=True)
class EvidenceRequirement:
    evidence_type: EvidenceType
    description: str
    required: bool = True


@dataclass(frozen=True)
class VulnClassRequirements:
    vuln_class: str
    support_evidence: FrozenSet[EvidenceRequirement]
    reproduction_evidence: FrozenSet[EvidenceRequirement]
    impact_evidence: FrozenSet[EvidenceRequirement]
    min_support_count: int = 1
    min_reproduction_count: int = 1
    min_impact_count: int = 1


_STATUS_CODE_ONLY = frozenset()

VULN_REQUIREMENTS: Dict[str, VulnClassRequirements] = {
    "SQLI": VulnClassRequirements(
        vuln_class="SQLI",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.ERROR_MESSAGE_LEAK,
                                "SQL error in response body"),
            EvidenceRequirement(EvidenceType.TIME_BASED_DIFF,
                                "measurable time delay from injected sleep", required=False),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "same payload reproduces same behavior"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.DATA_EXFILTRATION,
                                "data extracted via UNION/blind/error-based"),
        }),
        min_support_count=1,
    ),
    "XSS": VulnClassRequirements(
        vuln_class="XSS",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REFLECTED_PAYLOAD,
                                "payload reflected unescaped in response"),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "reflected payload reproduces on retry"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.BODY_CONTAINS_MARKER,
                                "payload executes (alert/DOM mutation/event)"),
        }),
    ),
    "IDOR": VulnClassRequirements(
        vuln_class="IDOR",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.CROSS_IDENTITY_ACCESS,
                                "identity B accesses resource owned by identity A"),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "cross-identity access reproduces"),
            EvidenceRequirement(EvidenceType.HTTP_RESPONSE_DIFF,
                                "baseline vs cross-identity response differs from 403/401"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.DATA_EXFILTRATION,
                                "identity B reads/mutates A's data"),
        }),
        min_reproduction_count=2,
    ),
    "SSRF": VulnClassRequirements(
        vuln_class="SSRF",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.DNS_INTERACTION,
                                "server-side DNS lookup to attacker-controlled domain"),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "SSRF callback reproduces"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.DATA_EXFILTRATION,
                                "internal data retrieved via SSRF", required=False),
            EvidenceRequirement(EvidenceType.FILE_CONTENT_LEAK,
                                "internal file read via SSRF", required=False),
        }),
        min_impact_count=0,
    ),
    "RCE": VulnClassRequirements(
        vuln_class="RCE",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.COMMAND_OUTPUT,
                                "unique marker in command output"),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "command execution reproduces with different marker"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.COMMAND_OUTPUT,
                                "arbitrary command executes (id/whoami/hostname)"),
        }),
    ),
    "PATH_TRAVERSAL": VulnClassRequirements(
        vuln_class="PATH_TRAVERSAL",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.FILE_CONTENT_LEAK,
                                "known file content returned (e.g. /etc/passwd)"),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "file read reproduces"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.FILE_CONTENT_LEAK,
                                "file outside webroot is readable"),
        }),
    ),
    "AUTH_BYPASS": VulnClassRequirements(
        vuln_class="AUTH_BYPASS",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.AUTH_BYPASS_PROOF,
                                "protected resource accessible without valid auth"),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "bypass reproduces"),
            EvidenceRequirement(EvidenceType.HTTP_RESPONSE_DIFF,
                                "authed vs unauthed response shows protected content"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.DATA_EXFILTRATION,
                                "protected data accessible without auth"),
        }),
    ),
    "OPEN_REDIRECT": VulnClassRequirements(
        vuln_class="OPEN_REDIRECT",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REDIRECT_TO_ATTACKER,
                                "server redirects to attacker-controlled URL"),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "redirect reproduces"),
        }),
        impact_evidence=frozenset(),
        min_impact_count=0,
    ),
    "XXE": VulnClassRequirements(
        vuln_class="XXE",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.FILE_CONTENT_LEAK,
                                "external entity resolves and returns data"),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "XXE payload reproduces"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.FILE_CONTENT_LEAK,
                                "file or SSRF via XXE"),
        }),
    ),
    "CSRF": VulnClassRequirements(
        vuln_class="CSRF",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.AUTH_BYPASS_PROOF,
                                "state-changing request succeeds without CSRF token"),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "cross-origin forged request reproduces"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.HTTP_RESPONSE_DIFF,
                                "state mutation confirmed via response diff"),
        }),
    ),
    "SSTI": VulnClassRequirements(
        vuln_class="SSTI",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REFLECTED_PAYLOAD,
                                "template expression evaluated in response"),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "template injection reproduces with different expression"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.COMMAND_OUTPUT,
                                "RCE achieved via template engine"),
        }),
    ),
    "LFI": VulnClassRequirements(
        vuln_class="LFI",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.FILE_CONTENT_LEAK,
                                "local file content returned via inclusion"),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "file inclusion reproduces"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.FILE_CONTENT_LEAK,
                                "sensitive file readable via inclusion"),
        }),
    ),
    "GRAPHQL_INJECTION": VulnClassRequirements(
        vuln_class="GRAPHQL_INJECTION",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.ERROR_MESSAGE_LEAK,
                                "GraphQL error leaks schema or query structure"),
            EvidenceRequirement(EvidenceType.DATA_EXFILTRATION,
                                "introspection or unauthorized field access", required=False),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "GraphQL injection reproduces"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.DATA_EXFILTRATION,
                                "unauthorized data accessed via GraphQL"),
        }),
    ),
    "CRLF": VulnClassRequirements(
        vuln_class="CRLF",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REFLECTED_PAYLOAD,
                                "CRLF characters reflected in HTTP headers"),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "header injection reproduces"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.BODY_CONTAINS_MARKER,
                                "injected header present in response"),
        }),
    ),
    "CORS_MISCONFIGURATION": VulnClassRequirements(
        vuln_class="CORS_MISCONFIGURATION",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.HTTP_RESPONSE_DIFF,
                                "Access-Control-Allow-Origin reflects arbitrary origin"),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "CORS misconfiguration reproduces"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.DATA_EXFILTRATION,
                                "cross-origin data exfiltration possible"),
        }),
    ),
    "BUSINESS_LOGIC": VulnClassRequirements(
        vuln_class="BUSINESS_LOGIC",
        support_evidence=frozenset({
            EvidenceRequirement(EvidenceType.HTTP_RESPONSE_DIFF,
                                "unexpected state transition or privilege obtained"),
        }),
        reproduction_evidence=frozenset({
            EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                                "business logic flaw reproduces"),
        }),
        impact_evidence=frozenset({
            EvidenceRequirement(EvidenceType.DATA_EXFILTRATION,
                                "demonstrable business impact"),
        }),
    ),
}

_DEFAULT_REQUIREMENTS = VulnClassRequirements(
    vuln_class="GENERIC",
    support_evidence=frozenset({
        EvidenceRequirement(EvidenceType.BODY_CONTAINS_MARKER,
                            "concrete indicator in response beyond status code"),
    }),
    reproduction_evidence=frozenset({
        EvidenceRequirement(EvidenceType.REPRODUCTION_MATCH,
                            "behavior reproduces independently"),
    }),
    impact_evidence=frozenset({
        EvidenceRequirement(EvidenceType.DATA_EXFILTRATION,
                            "demonstrable security impact"),
    }),
    min_impact_count=1,
)


@dataclass
class EvidenceItem:
    evidence_type: EvidenceType
    source_tool: str
    detail: str
    raw_data: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_type": self.evidence_type.value,
            "source_tool": self.source_tool,
            "detail": self.detail,
        }


@dataclass
class ConfirmationState:
    finding_id: str
    vuln_class: str
    stage: ConfirmationStage = ConfirmationStage.CANDIDATE
    support_evidence: List[EvidenceItem] = field(default_factory=list)
    reproduction_evidence: List[EvidenceItem] = field(default_factory=list)
    impact_evidence: List[EvidenceItem] = field(default_factory=list)
    rejection_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vuln_class": self.vuln_class,
            "stage": self.stage.value,
            "support_evidence": [e.to_dict() for e in self.support_evidence],
            "reproduction_evidence": [e.to_dict() for e in self.reproduction_evidence],
            "impact_evidence": [e.to_dict() for e in self.impact_evidence],
            "rejection_reason": self.rejection_reason,
        }


_LLM_TRUST_KEYWORDS = {
    "confirmed", "verified", "exploitable", "vulnerable", "vulnerability",
    "successful", "proven", "demonstrated", "validated", "found", "detected",
    "identified", "present", "exists", "discovered", "observed", "noted",
    "appears", "exploit", "attack", "injection", "payload", "test",
}

_LLM_FILLER_WORDS = {
    "the", "is", "was", "a", "an", "this", "that", "it", "has", "been",
    "be", "to", "of", "in", "for", "and", "or", "with", "are", "were",
    "not", "no", "yes", "very", "highly", "likely", "possibly", "also",
    "can", "could", "should", "would", "may", "might", "will",
}

_STATUS_ONLY_CODES = {200, 201, 202, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503}


def _is_llm_wording_only(evidence: Dict[str, Any]) -> bool:
    text = str(evidence.get("proof") or evidence.get("detail") or "").lower()
    if not text:
        return True
    words = set(re.findall(r"[a-z]+", text))
    meaningful = words - _LLM_FILLER_WORDS
    if not meaningful or meaningful.issubset(_LLM_TRUST_KEYWORDS):
        return True
    return False


def _is_status_code_only(evidence: Dict[str, Any]) -> bool:
    proof = str(evidence.get("proof") or evidence.get("detail") or "")
    stripped = re.sub(r"(HTTP\s*/?)\s*\d[\d.]*", "", proof, flags=re.IGNORECASE).strip()
    stripped = re.sub(r"(status|code|response|returned)\s*[:=]?\s*\d+", "", stripped, flags=re.IGNORECASE).strip()
    stripped = re.sub(r"\b\d{3}\b", "", stripped).strip()
    remaining_words = set(re.findall(r"[a-z]+", stripped.lower()))
    remaining_words -= _LLM_FILLER_WORDS | {"http", "status", "code", "response", "ok", "error"}
    return len(remaining_words) < 3


class FindingConfirmationGate:

    def __init__(self):
        self._states: Dict[str, ConfirmationState] = {}

    def _get_requirements(self, vuln_class: str) -> VulnClassRequirements:
        vc = vuln_class.upper().replace("-", "_").replace(" ", "_")
        return VULN_REQUIREMENTS.get(vc, _DEFAULT_REQUIREMENTS)

    def register(self, finding_id: str, vuln_class: str) -> ConfirmationState:
        state = ConfirmationState(finding_id=finding_id, vuln_class=vuln_class)
        self._states[finding_id] = state
        return state

    def add_support_evidence(self, finding_id: str,
                             evidence: EvidenceItem) -> None:
        state = self._states.get(finding_id)
        if state:
            state.support_evidence.append(evidence)

    def add_reproduction_evidence(self, finding_id: str,
                                  evidence: EvidenceItem) -> None:
        state = self._states.get(finding_id)
        if state:
            state.reproduction_evidence.append(evidence)

    def add_impact_evidence(self, finding_id: str,
                            evidence: EvidenceItem) -> None:
        state = self._states.get(finding_id)
        if state:
            state.impact_evidence.append(evidence)

    def evaluate(self, finding_id: str,
                 raw_finding: Optional[Dict[str, Any]] = None) -> Tuple[ConfirmationStage, str]:
        state = self._states.get(finding_id)
        if state is None:
            return ConfirmationStage.REJECTED, "no confirmation state registered"

        reqs = self._get_requirements(state.vuln_class)

        if raw_finding:
            if raw_finding.get("confirmed") is True:
                logger.debug("[P0.6] ignoring upstream confirmed=True for %s", finding_id)
            if _is_llm_wording_only(raw_finding):
                state.stage = ConfirmationStage.REJECTED
                state.rejection_reason = "evidence is LLM wording only"
                return state.stage, state.rejection_reason
            if _is_status_code_only(raw_finding):
                state.stage = ConfirmationStage.REJECTED
                state.rejection_reason = "evidence is HTTP status code only"
                return state.stage, state.rejection_reason

        required_support = [r for r in reqs.support_evidence if r.required]
        if len(state.support_evidence) < max(reqs.min_support_count, len(required_support)):
            state.stage = ConfirmationStage.CANDIDATE
            return state.stage, f"need {reqs.min_support_count} support evidence, have {len(state.support_evidence)}"

        state.stage = ConfirmationStage.SUPPORTED

        required_repro = [r for r in reqs.reproduction_evidence if r.required]
        if len(state.reproduction_evidence) < max(reqs.min_reproduction_count, len(required_repro)):
            return state.stage, f"need {reqs.min_reproduction_count} reproduction evidence, have {len(state.reproduction_evidence)}"

        state.stage = ConfirmationStage.REPRODUCED

        required_impact = [r for r in reqs.impact_evidence if r.required]
        min_impact = max(reqs.min_impact_count, len(required_impact))
        if min_impact > 0 and len(state.impact_evidence) < min_impact:
            return state.stage, f"need {min_impact} impact evidence, have {len(state.impact_evidence)}"

        state.stage = ConfirmationStage.IMPACT_VERIFIED
        state.stage = ConfirmationStage.CONFIRMED
        return state.stage, "all evidence requirements met"

    def is_confirmed(self, finding_id: str) -> bool:
        state = self._states.get(finding_id)
        return state is not None and state.stage == ConfirmationStage.CONFIRMED

    def get_state(self, finding_id: str) -> Optional[ConfirmationState]:
        return self._states.get(finding_id)

    def reject(self, finding_id: str, reason: str) -> None:
        state = self._states.get(finding_id)
        if state:
            state.stage = ConfirmationStage.REJECTED
            state.rejection_reason = reason
