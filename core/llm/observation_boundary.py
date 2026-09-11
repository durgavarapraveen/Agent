"""Phase 16.1 — Untrusted-observation boundary.

Formally separates trusted system policy, planner state, tool schemas from
untrusted target content. Content labels prevent web content from masquerading
as instructions. Prompt-injection defenses treat suspicious instruction-like
content as data.
"""
from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ContentTrust(str, Enum):
    SYSTEM_POLICY = "system_policy"
    PLANNER_STATE = "planner_state"
    TOOL_SCHEMA = "tool_schema"
    USER_INPUT = "user_input"
    TARGET_RESPONSE = "target_response"
    EXTERNAL_DATA = "external_data"


TRUSTED_LEVELS: FrozenSet[ContentTrust] = frozenset({
    ContentTrust.SYSTEM_POLICY,
    ContentTrust.PLANNER_STATE,
    ContentTrust.TOOL_SCHEMA,
})

UNTRUSTED_LEVELS: FrozenSet[ContentTrust] = frozenset({
    ContentTrust.TARGET_RESPONSE,
    ContentTrust.EXTERNAL_DATA,
})

_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+(instructions?|prompts?)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"<\|im_(start|end)\|>", re.IGNORECASE),
    re.compile(r"###\s*system", re.IGNORECASE),
    re.compile(r"```\s*system", re.IGNORECASE),
    re.compile(r"act\s+as\s+(a\s+)?", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"override\s+(all\s+)?rules", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all)", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"</?s>", re.IGNORECASE),
]

DEFAULT_BOUNDARY_CONFIG: Dict[str, Any] = {
    "max_untrusted_chars": 20_000,
    "max_untrusted_sections": 50,
    "neutralize_markers": True,
    "injection_threshold": 1,
    "label_format": "xml",
}

_ZWSP = "​"


@dataclass
class LabeledContent:
    content_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    trust_level: ContentTrust = ContentTrust.EXTERNAL_DATA
    raw: str = ""
    sanitized: str = ""
    source: str = ""
    injection_score: int = 0
    injection_matches: List[str] = field(default_factory=list)
    truncated: bool = False
    timestamp: float = field(default_factory=time.time)

    def is_trusted(self) -> bool:
        return self.trust_level in TRUSTED_LEVELS

    def is_suspicious(self) -> bool:
        return self.injection_score > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.content_id,
            "trust": self.trust_level.value,
            "source": self.source,
            "injection_score": self.injection_score,
            "truncated": self.truncated,
            "length": len(self.sanitized),
        }


@dataclass
class PromptSection:
    label: str
    trust_level: ContentTrust
    content: str

    def render_xml(self) -> str:
        trust = self.trust_level.value
        return f'<section label="{self.label}" trust="{trust}">\n{self.content}\n</section>'


class ObservationBoundary:
    """Enforces trust boundaries between system and target content."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = {**DEFAULT_BOUNDARY_CONFIG, **(config or {})}
        self._lock = threading.RLock()
        self._labeled: Dict[str, LabeledContent] = {}
        self._injection_log: List[Dict[str, Any]] = []
        self._stats = {"total_labeled": 0, "injections_detected": 0, "truncations": 0}

    def label_content(self, raw: str, trust_level: ContentTrust,
                      source: str = "") -> LabeledContent:
        sanitized = raw
        truncated = False
        injection_score = 0
        injection_matches: List[str] = []

        if trust_level in UNTRUSTED_LEVELS:
            max_chars = self._config["max_untrusted_chars"]
            if len(sanitized) > max_chars:
                sanitized = sanitized[:max_chars]
                truncated = True

            injection_score, injection_matches = self._scan_injections(sanitized)

            if self._config["neutralize_markers"]:
                sanitized = self._neutralize(sanitized)

        labeled = LabeledContent(
            trust_level=trust_level, raw=raw, sanitized=sanitized,
            source=source, injection_score=injection_score,
            injection_matches=injection_matches, truncated=truncated,
        )

        with self._lock:
            self._labeled[labeled.content_id] = labeled
            self._stats["total_labeled"] += 1
            if truncated:
                self._stats["truncations"] += 1
            if injection_score >= self._config["injection_threshold"]:
                self._stats["injections_detected"] += 1
                self._injection_log.append({
                    "content_id": labeled.content_id,
                    "source": source,
                    "score": injection_score,
                    "matches": injection_matches,
                    "timestamp": labeled.timestamp,
                })

        return labeled

    def build_prompt(self, sections: List[PromptSection]) -> str:
        for section in sections:
            if section.trust_level in UNTRUSTED_LEVELS:
                labeled = self.label_content(
                    section.content, section.trust_level, label=section.label,
                )
                section.content = labeled.sanitized

        return "\n\n".join(s.render_xml() for s in sections)

    def validate_no_privilege_escalation(self, sections: List[PromptSection]) -> Tuple[bool, List[str]]:
        violations: List[str] = []
        for section in sections:
            if section.trust_level in UNTRUSTED_LEVELS:
                score, matches = self._scan_injections(section.content)
                if score >= self._config["injection_threshold"]:
                    violations.append(
                        f"Section '{section.label}': {score} injection patterns ({', '.join(matches)})"
                    )
        return len(violations) == 0, violations

    def get_injection_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._injection_log[-limit:])

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats)

    def _neutralize(self, text: str) -> str:
        for pattern in _INJECTION_PATTERNS:
            text = pattern.sub(lambda m: _ZWSP.join(m.group()), text)
        return text

    def _scan_injections(self, text: str) -> Tuple[int, List[str]]:
        score = 0
        matches: List[str] = []
        for pattern in _INJECTION_PATTERNS:
            found = pattern.findall(text)
            if found:
                score += len(found)
                matches.append(pattern.pattern[:60])
        return score, matches
