"""
Built-in metamorphic relations (spec Point B / P1.6).

A metamorphic relation pairs a *semantic-preserving* input transform with an
expected relation on the outputs. Because the transforms preserve meaning, a
well-behaved server should return equivalent responses; a violation is an
anomaly (routing/normalisation/parser quirk, cache-key confusion, header
mishandling) worth a hypothesis.

All transforms here are read-only and benign.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Callable, List, Optional

from core.intelligence.differential.comparison import ResponseSnapshot, compare_snapshots
from core.intelligence.differential.representations import HttpRequest

RelationFn = Callable[[ResponseSnapshot, List[ResponseSnapshot]], Optional[str]]
BuildFn = Callable[[HttpRequest], List[HttpRequest]]
ApplicableFn = Callable[[HttpRequest], bool]


@dataclass
class MetamorphicRelation:
    name: str
    description: str
    severity: str
    applicable: ApplicableFn
    build: BuildFn
    relation: RelationFn


def _split_url(url: str):
    p = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    return p, pairs


def _rebuild(p, pairs, path: Optional[str] = None) -> str:
    query = urllib.parse.urlencode(pairs)
    return urllib.parse.urlunsplit((
        p.scheme, p.netloc, path if path is not None else p.path, query, p.fragment))


def _equivalent(source: ResponseSnapshot, followups: List[ResponseSnapshot]) -> Optional[str]:
    """Relation: every follow-up must be equivalent to the source."""
    for f in followups:
        divs = compare_snapshots(source, f)
        material = [d for d in divs if d.kind in ("status", "body", "content_type")]
        if material:
            return (f"'{f.label}' diverged from source: "
                    + "; ".join(d.detail for d in material))
    return None


# ── relation builders ──────────────────────────────────────────────────

def _build_idempotent(source: HttpRequest) -> List[HttpRequest]:
    return [source.with_label("repeat #1"), source.with_label("repeat #2")]


def _build_param_order(source: HttpRequest) -> List[HttpRequest]:
    p, pairs = _split_url(source.url)
    reordered = list(reversed(pairs))
    r = source.with_label("query reordered")
    r.url = _rebuild(p, reordered)
    return [r]


def _applicable_multi_param(source: HttpRequest) -> bool:
    _, pairs = _split_url(source.url)
    return len(pairs) >= 2 and source.method.upper() == "GET"


def _build_space_encoding(source: HttpRequest) -> List[HttpRequest]:
    # Swap '+' <-> '%20' representation of spaces in the raw query string.
    p = urllib.parse.urlsplit(source.url)
    swapped = p.query.replace("+", "%20") if "+" in p.query else p.query.replace("%20", "+")
    r = source.with_label("space re-encoded")
    r.url = urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, swapped, p.fragment))
    return [r]


def _applicable_space(source: HttpRequest) -> bool:
    p = urllib.parse.urlsplit(source.url)
    return ("+" in p.query or "%20" in p.query) and source.method.upper() == "GET"


def _build_trailing_slash(source: HttpRequest) -> List[HttpRequest]:
    p, pairs = _split_url(source.url)
    new_path = p.path.rstrip("/") if p.path.endswith("/") else p.path + "/"
    r = source.with_label("trailing slash toggled")
    r.url = _rebuild(p, pairs, path=new_path or "/")
    return [r]


def _applicable_has_path(source: HttpRequest) -> bool:
    p = urllib.parse.urlsplit(source.url)
    return bool(p.path) and p.path != "/"


def _build_header_case(source: HttpRequest) -> List[HttpRequest]:
    base_headers = dict(source.headers) if source.headers else {}
    base_headers.setdefault("Accept", "*/*")
    lowered = {k.lower(): v for k, v in base_headers.items()}
    r = source.with_label("header names lowercased")
    r.headers = lowered
    return [r]


BUILTIN_RELATIONS: List[MetamorphicRelation] = [
    MetamorphicRelation(
        "idempotent_get",
        "Repeating a safe GET yields an equivalent response (stability oracle).",
        "info", lambda s: s.method.upper() == "GET", _build_idempotent, _equivalent),
    MetamorphicRelation(
        "query_param_order",
        "Reordering query parameters must not change the response.",
        "low", _applicable_multi_param, _build_param_order, _equivalent),
    MetamorphicRelation(
        "space_encoding_equivalence",
        "'+' and '%20' encode the same space and must be equivalent.",
        "low", _applicable_space, _build_space_encoding, _equivalent),
    MetamorphicRelation(
        "trailing_slash_equivalence",
        "A trailing slash should not change the resource served.",
        "info", _applicable_has_path, _build_trailing_slash, _equivalent),
    MetamorphicRelation(
        "header_name_case_insensitivity",
        "HTTP header names are case-insensitive; lowercasing them must not change the response.",
        "medium", lambda s: True, _build_header_case, _equivalent),
]
