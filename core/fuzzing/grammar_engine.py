"""Phase 13.1 — Grammar/context-aware input engine.

Replaces static payload lists with context-aware transformations driven by
inferred input type, encoding, parser, serialization format, reflection
behavior, and application response transformations. Every generated input has
provenance. Resource limits prevent combinatorial explosion.
"""
from __future__ import annotations

import hashlib
import logging
import threading
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

DEFAULT_LIMITS: Dict[str, int] = {
    "max_mutations_per_input": 100,
    "max_total_inputs": 10000,
    "max_depth": 5,
    "max_grammar_rules": 500,
}


class InputType(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    JSON = "json"
    XML = "xml"
    HTML = "html"
    SQL = "sql"
    URL = "url"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"
    MULTIPART = "multipart"
    GRAPHQL = "graphql"
    COMMAND = "command"


class EncodingType(str, Enum):
    NONE = "none"
    URL_ENCODE = "url_encode"
    BASE64 = "base64"
    HTML_ENTITY = "html_entity"
    UNICODE = "unicode"
    DOUBLE_URL = "double_url"
    HEX = "hex"


@dataclass
class GrammarRule:
    rule_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    input_type: InputType = InputType.STRING
    pattern: str = ""
    transformer: Optional[Callable[[str], List[str]]] = None
    encoding: EncodingType = EncodingType.NONE
    context: str = ""
    priority: int = 0


@dataclass
class GeneratedInput:
    input_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    value: str = ""
    input_type: InputType = InputType.STRING
    encoding: EncodingType = EncodingType.NONE
    provenance: str = ""
    rule_id: str = ""
    parent_id: str = ""
    depth: int = 0
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_id": self.input_id, "value": self.value,
            "type": self.input_type.value, "encoding": self.encoding.value,
            "provenance": self.provenance, "depth": self.depth,
        }


class GrammarInputEngine:
    """Context-aware input generation with grammar rules and provenance tracking."""

    def __init__(self, limits: Optional[Dict[str, int]] = None):
        self._limits = {**DEFAULT_LIMITS, **(limits or {})}
        self._lock = threading.RLock()
        self._rules: Dict[str, GrammarRule] = {}
        self._generated: List[GeneratedInput] = []
        self._total_count = 0
        self._encoders: Dict[EncodingType, Callable[[str], str]] = {
            EncodingType.NONE: lambda x: x,
            EncodingType.URL_ENCODE: self._url_encode,
            EncodingType.BASE64: self._base64_encode,
            EncodingType.HTML_ENTITY: self._html_entity_encode,
            EncodingType.DOUBLE_URL: self._double_url_encode,
            EncodingType.HEX: self._hex_encode,
            EncodingType.UNICODE: self._unicode_encode,
        }

    def add_rule(self, rule: GrammarRule) -> bool:
        with self._lock:
            if len(self._rules) >= self._limits["max_grammar_rules"]:
                return False
            self._rules[rule.rule_id] = rule
        return True

    def generate(self, base_value: str, input_type: InputType,
                 context: Optional[Dict[str, Any]] = None,
                 max_count: Optional[int] = None) -> List[GeneratedInput]:
        limit = min(max_count or self._limits["max_mutations_per_input"],
                    self._limits["max_mutations_per_input"])
        applicable = self._get_applicable_rules(input_type)
        results: List[GeneratedInput] = []
        for rule in applicable:
            if len(results) >= limit:
                break
            if self._total_count >= self._limits["max_total_inputs"]:
                break
            mutations = self._apply_rule(rule, base_value)
            for val in mutations:
                if len(results) >= limit:
                    break
                encoded = self._encode(val, rule.encoding)
                gi = GeneratedInput(
                    value=encoded, input_type=input_type, encoding=rule.encoding,
                    provenance=f"rule:{rule.rule_id}:{rule.pattern}",
                    rule_id=rule.rule_id, context=context or {},
                )
                results.append(gi)
                self._total_count += 1
        with self._lock:
            self._generated.extend(results)
        return results

    def generate_with_depth(self, base_value: str, input_type: InputType,
                            depth: int = 0) -> List[GeneratedInput]:
        if depth >= self._limits["max_depth"]:
            return []
        first_gen = self.generate(base_value, input_type)
        if depth + 1 < self._limits["max_depth"]:
            for gi in list(first_gen):
                children = self.generate(gi.value, input_type)
                for c in children:
                    c.parent_id = gi.input_id
                    c.depth = depth + 1
                first_gen.extend(children)
        return first_gen

    def get_provenance(self, input_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            for gi in self._generated:
                if gi.input_id == input_id:
                    chain = [gi.to_dict()]
                    parent = gi.parent_id
                    while parent:
                        for p in self._generated:
                            if p.input_id == parent:
                                chain.append(p.to_dict())
                                parent = p.parent_id
                                break
                        else:
                            break
                    return {"chain": chain}
        return None

    def stats(self) -> Dict[str, int]:
        return {
            "rules": len(self._rules),
            "generated": self._total_count,
            "limit": self._limits["max_total_inputs"],
        }

    def _get_applicable_rules(self, input_type: InputType) -> List[GrammarRule]:
        with self._lock:
            rules = [r for r in self._rules.values()
                     if r.input_type == input_type or r.input_type == InputType.STRING]
        rules.sort(key=lambda r: r.priority, reverse=True)
        return rules

    def _apply_rule(self, rule: GrammarRule, value: str) -> List[str]:
        if rule.transformer:
            try:
                return rule.transformer(value)
            except Exception:
                return []
        if rule.pattern:
            return [rule.pattern.replace("{input}", value)]
        return [value]

    def _encode(self, value: str, encoding: EncodingType) -> str:
        encoder = self._encoders.get(encoding, lambda x: x)
        return encoder(value)

    @staticmethod
    def _url_encode(v: str) -> str:
        from urllib.parse import quote
        return quote(v, safe="")

    @staticmethod
    def _base64_encode(v: str) -> str:
        import base64
        return base64.b64encode(v.encode()).decode()

    @staticmethod
    def _html_entity_encode(v: str) -> str:
        return "".join(f"&#{ord(c)};" for c in v)

    @staticmethod
    def _double_url_encode(v: str) -> str:
        from urllib.parse import quote
        return quote(quote(v, safe=""), safe="")

    @staticmethod
    def _hex_encode(v: str) -> str:
        return "".join(f"\\x{ord(c):02x}" for c in v)

    @staticmethod
    def _unicode_encode(v: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in v)
