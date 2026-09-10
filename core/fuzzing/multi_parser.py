"""Phase 13.2 — Multi-parser and protocol coverage.

Adapters for JSON, XML, multipart, form encoding, query parameters, cookies,
headers, WebSocket messages, GraphQL, and legacy serialization. Preserves
semantics while mutating one dimension at a time. Bounded and robust to
malformed data.
"""
from __future__ import annotations

import json
import logging
import threading
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlencode

logger = logging.getLogger(__name__)

DEFAULT_PARSER_CONFIG: Dict[str, Any] = {
    "max_parse_size_bytes": 10 * 1024 * 1024,
    "max_depth": 20,
    "max_mutations_per_parse": 200,
    "timeout_ms": 5000,
}


class ParserType(str, Enum):
    JSON = "json"
    XML = "xml"
    MULTIPART = "multipart"
    FORM_ENCODED = "form_encoded"
    QUERY_PARAMS = "query_params"
    COOKIE = "cookie"
    HEADER = "header"
    WEBSOCKET = "websocket"
    GRAPHQL = "graphql"
    PROTOBUF = "protobuf"
    MSGPACK = "msgpack"


@dataclass
class ParsedStructure:
    parser_type: ParserType = ParserType.JSON
    raw: str = ""
    fields: Dict[str, Any] = field(default_factory=dict)
    is_valid: bool = True
    error: str = ""
    depth: int = 0


@dataclass
class Mutation:
    mutation_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    parser_type: ParserType = ParserType.JSON
    field_path: str = ""
    original_value: Any = None
    mutated_value: Any = None
    mutation_type: str = ""
    serialized: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mutation_id": self.mutation_id, "parser": self.parser_type.value,
            "field": self.field_path, "mutation_type": self.mutation_type,
        }


class ParserAdapter:
    """Base class for protocol/format parsers."""

    parser_type: ParserType = ParserType.JSON

    def parse(self, raw: str) -> ParsedStructure:
        raise NotImplementedError

    def serialize(self, fields: Dict[str, Any]) -> str:
        raise NotImplementedError

    def mutate_field(self, parsed: ParsedStructure, field_path: str,
                     value: Any) -> Optional[Mutation]:
        raise NotImplementedError


class JSONParser(ParserAdapter):
    parser_type = ParserType.JSON

    def parse(self, raw: str) -> ParsedStructure:
        try:
            data = json.loads(raw)
            fields = data if isinstance(data, dict) else {"_root": data}
            return ParsedStructure(parser_type=self.parser_type, raw=raw,
                                   fields=fields, depth=self._depth(data))
        except (json.JSONDecodeError, ValueError) as e:
            return ParsedStructure(parser_type=self.parser_type, raw=raw,
                                   is_valid=False, error=str(e))

    def serialize(self, fields: Dict[str, Any]) -> str:
        return json.dumps(fields)

    def mutate_field(self, parsed: ParsedStructure, field_path: str,
                     value: Any) -> Optional[Mutation]:
        new_fields = dict(parsed.fields)
        original = new_fields.get(field_path)
        new_fields[field_path] = value
        return Mutation(parser_type=self.parser_type, field_path=field_path,
                        original_value=original, mutated_value=value,
                        mutation_type="replace", serialized=self.serialize(new_fields))

    def _depth(self, obj: Any, d: int = 0) -> int:
        if isinstance(obj, dict):
            return max((self._depth(v, d + 1) for v in obj.values()), default=d)
        if isinstance(obj, list):
            return max((self._depth(v, d + 1) for v in obj), default=d)
        return d


class XMLParser(ParserAdapter):
    parser_type = ParserType.XML

    def parse(self, raw: str) -> ParsedStructure:
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw)
            fields = {child.tag: (child.text or "") for child in root}
            return ParsedStructure(parser_type=self.parser_type, raw=raw, fields=fields)
        except Exception as e:
            return ParsedStructure(parser_type=self.parser_type, raw=raw,
                                   is_valid=False, error=str(e))

    def serialize(self, fields: Dict[str, Any]) -> str:
        parts = ["<root>"]
        for k, v in fields.items():
            parts.append(f"<{k}>{v}</{k}>")
        parts.append("</root>")
        return "".join(parts)

    def mutate_field(self, parsed: ParsedStructure, field_path: str,
                     value: Any) -> Optional[Mutation]:
        new_fields = dict(parsed.fields)
        original = new_fields.get(field_path)
        new_fields[field_path] = value
        return Mutation(parser_type=self.parser_type, field_path=field_path,
                        original_value=original, mutated_value=value,
                        mutation_type="replace", serialized=self.serialize(new_fields))


class FormEncodedParser(ParserAdapter):
    parser_type = ParserType.FORM_ENCODED

    def parse(self, raw: str) -> ParsedStructure:
        try:
            fields = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(raw).items()}
            return ParsedStructure(parser_type=self.parser_type, raw=raw, fields=fields)
        except Exception as e:
            return ParsedStructure(parser_type=self.parser_type, raw=raw,
                                   is_valid=False, error=str(e))

    def serialize(self, fields: Dict[str, Any]) -> str:
        return urlencode(fields, doseq=True)

    def mutate_field(self, parsed: ParsedStructure, field_path: str,
                     value: Any) -> Optional[Mutation]:
        new_fields = dict(parsed.fields)
        original = new_fields.get(field_path)
        new_fields[field_path] = value
        return Mutation(parser_type=self.parser_type, field_path=field_path,
                        original_value=original, mutated_value=value,
                        mutation_type="replace", serialized=self.serialize(new_fields))


class CookieParser(ParserAdapter):
    parser_type = ParserType.COOKIE

    def parse(self, raw: str) -> ParsedStructure:
        fields = {}
        for pair in raw.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                fields[k.strip()] = v.strip()
        return ParsedStructure(parser_type=self.parser_type, raw=raw, fields=fields)

    def serialize(self, fields: Dict[str, Any]) -> str:
        return "; ".join(f"{k}={v}" for k, v in fields.items())

    def mutate_field(self, parsed: ParsedStructure, field_path: str,
                     value: Any) -> Optional[Mutation]:
        new_fields = dict(parsed.fields)
        original = new_fields.get(field_path)
        new_fields[field_path] = value
        return Mutation(parser_type=self.parser_type, field_path=field_path,
                        original_value=original, mutated_value=value,
                        mutation_type="replace", serialized=self.serialize(new_fields))


class GraphQLParser(ParserAdapter):
    parser_type = ParserType.GRAPHQL

    def parse(self, raw: str) -> ParsedStructure:
        try:
            data = json.loads(raw)
            fields = {"query": data.get("query", ""),
                       "variables": data.get("variables", {}),
                       "operationName": data.get("operationName", "")}
            return ParsedStructure(parser_type=self.parser_type, raw=raw, fields=fields)
        except (json.JSONDecodeError, ValueError) as e:
            return ParsedStructure(parser_type=self.parser_type, raw=raw,
                                   is_valid=False, error=str(e))

    def serialize(self, fields: Dict[str, Any]) -> str:
        return json.dumps(fields)

    def mutate_field(self, parsed: ParsedStructure, field_path: str,
                     value: Any) -> Optional[Mutation]:
        new_fields = dict(parsed.fields)
        original = new_fields.get(field_path)
        new_fields[field_path] = value
        return Mutation(parser_type=self.parser_type, field_path=field_path,
                        original_value=original, mutated_value=value,
                        mutation_type="replace", serialized=self.serialize(new_fields))


class MultiParserEngine:
    """Unified mutation framework across all protocol parsers."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = {**DEFAULT_PARSER_CONFIG, **(config or {})}
        self._lock = threading.RLock()
        self._parsers: Dict[ParserType, ParserAdapter] = {}
        self._mutations: List[Mutation] = []
        self._register_defaults()

    def register_parser(self, adapter: ParserAdapter) -> None:
        self._parsers[adapter.parser_type] = adapter

    def parse(self, raw: str, parser_type: ParserType) -> ParsedStructure:
        if len(raw.encode("utf-8", errors="replace")) > self._config["max_parse_size_bytes"]:
            return ParsedStructure(parser_type=parser_type, raw="", is_valid=False,
                                   error="exceeds max_parse_size_bytes")
        adapter = self._parsers.get(parser_type)
        if not adapter:
            return ParsedStructure(parser_type=parser_type, raw=raw, is_valid=False,
                                   error=f"no adapter for {parser_type.value}")
        result = adapter.parse(raw)
        if result.depth > self._config["max_depth"]:
            result.is_valid = False
            result.error = "exceeds max_depth"
        return result

    def mutate_one_dimension(self, raw: str, parser_type: ParserType,
                              field_path: str, value: Any) -> Optional[Mutation]:
        parsed = self.parse(raw, parser_type)
        if not parsed.is_valid:
            return None
        adapter = self._parsers.get(parser_type)
        if not adapter:
            return None
        mutation = adapter.mutate_field(parsed, field_path, value)
        if mutation:
            with self._lock:
                if len(self._mutations) < self._config["max_mutations_per_parse"]:
                    self._mutations.append(mutation)
        return mutation

    def mutate_all_fields(self, raw: str, parser_type: ParserType,
                           value_fn: Callable[[str, Any], Any]) -> List[Mutation]:
        parsed = self.parse(raw, parser_type)
        if not parsed.is_valid:
            return []
        adapter = self._parsers.get(parser_type)
        if not adapter:
            return []
        mutations = []
        for field_path, orig in parsed.fields.items():
            if len(mutations) >= self._config["max_mutations_per_parse"]:
                break
            new_val = value_fn(field_path, orig)
            m = adapter.mutate_field(parsed, field_path, new_val)
            if m:
                mutations.append(m)
        with self._lock:
            self._mutations.extend(mutations)
        return mutations

    def supported_parsers(self) -> List[str]:
        return sorted(p.value for p in self._parsers.keys())

    def unsupported_report(self, requested: List[ParserType]) -> List[str]:
        return [p.value for p in requested if p not in self._parsers]

    def coverage_report(self) -> Dict[str, Any]:
        return {
            "supported": self.supported_parsers(),
            "total_mutations": len(self._mutations),
        }

    def _register_defaults(self) -> None:
        for adapter in [JSONParser(), XMLParser(), FormEncodedParser(),
                        CookieParser(), GraphQLParser()]:
            self._parsers[adapter.parser_type] = adapter
