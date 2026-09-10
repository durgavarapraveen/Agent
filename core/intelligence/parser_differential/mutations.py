from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass
from typing import Dict, List, Optional

from core.intelligence.differential.representations import HttpRequest

_UA = {"User-Agent": "AntiGravity-ParserDiff/1.0"}


@dataclass
class ParserProbe:
    technique: str
    request: HttpRequest
    expected: str
    note: str = ""


def _pct(value: str) -> str:
    return "".join(f"%{ord(c):02x}" for c in value)


def build_parser_probes(
    base_url: str,
    param: str,
    marker_a: str,
    marker_b: str,
    *,
    auth_headers: Optional[Dict[str, str]] = None,
) -> List[ParserProbe]:
    headers = dict(_UA)
    if auth_headers:
        headers.update(auth_headers)
    form_headers = dict(headers)
    form_headers["Content-Type"] = "application/x-www-form-urlencoded"
    json_headers = dict(headers)
    json_headers["Content-Type"] = "application/json"

    sep = "&" if urllib.parse.urlparse(base_url).query else "?"
    probes: List[ParserProbe] = []

    # 1. Duplicate query parameter, A first. First-wins parsers -> A, last-wins -> B.
    probes.append(ParserProbe(
        "dup_query_a_first",
        HttpRequest("dup query (A,B)", f"{base_url}{sep}{param}={marker_a}&{param}={marker_b}",
                    headers=dict(headers)),
        expected="either",
        note="duplicate query param; first-wins=>A, last-wins=>B",
    ))
    # 2. Duplicate query parameter, B first (mirror, to pin down the rule).
    probes.append(ParserProbe(
        "dup_query_b_first",
        HttpRequest("dup query (B,A)", f"{base_url}{sep}{param}={marker_b}&{param}={marker_a}",
                    headers=dict(headers)),
        expected="either",
        note="mirror of dup_query_a_first",
    ))
    # 3. Same name in query (A) and form body (B). Body should not override query.
    probes.append(ParserProbe(
        "query_vs_body",
        HttpRequest("query A + body B", f"{base_url}{sep}{param}={marker_a}",
                    method="POST", headers=dict(form_headers),
                    body=urllib.parse.urlencode({param: marker_b}).encode()),
        expected="A",
        note="query param present; a body value winning indicates precedence confusion",
    ))
    # 4. Case-variant parameter name (param=A & PARAM=B). Case-insensitive
    #    frameworks may collapse these; A should win for case-sensitive parsers.
    probes.append(ParserProbe(
        "case_variant_name",
        HttpRequest("case variant name", f"{base_url}{sep}{param}={marker_a}&{param.upper()}={marker_b}",
                    headers=dict(headers)),
        expected="A",
        note="param vs PARAM; B winning implies case-insensitive name handling",
    ))
    # 5. Leading whitespace in the second name (%20param=B). Trimming parsers
    #    treat it as the same key; strict parsers keep A.
    probes.append(ParserProbe(
        "whitespace_name",
        HttpRequest("whitespace name", f"{base_url}{sep}{param}={marker_a}&%20{param}={marker_b}",
                    headers=dict(headers)),
        expected="A",
        note="' param' vs 'param'; B winning implies whitespace trimming of keys",
    ))
    # 6. Double URL-encoded value. A single-decode server reflects the literal
    #    single-encoded string; a double-decoding server reflects marker_b.
    probes.append(ParserProbe(
        "double_encoding",
        HttpRequest("double-encoded value", f"{base_url}{sep}{param}={_pct(_pct(marker_b))}",
                    headers=dict(headers)),
        expected="A",  # neither raw marker should appear; B appearing = double decode
        note="value is double-percent-encoded B; B appearing implies double URL-decoding",
    ))
    # 7. JSON duplicate keys ({"p":"A","p":"B"}). RFC-lenient parsers pick one;
    #    which one is implementation-defined and worth knowing.
    probes.append(ParserProbe(
        "json_dup_key",
        HttpRequest("json dup key", base_url, method="POST", headers=dict(json_headers),
                    body=f'{{"{param}":"{marker_a}","{param}":"{marker_b}"}}'.encode()),
        expected="either",
        note="duplicate JSON keys; last-wins is common but not universal",
    ))
    # 8. Array vs scalar (param[]=A & param=B). Framework-dependent coercion.
    probes.append(ParserProbe(
        "array_vs_scalar",
        HttpRequest("array vs scalar", f"{base_url}{sep}{param}[]={marker_a}&{param}={marker_b}",
                    headers=dict(headers)),
        expected="either",
        note="param[] vs param; coercion is framework-specific",
    ))
    return probes


def json_probe_control(base_url: str, param: str, marker: str,
                       auth_headers: Optional[Dict[str, str]] = None) -> HttpRequest:
    headers = dict(_UA)
    if auth_headers:
        headers.update(auth_headers)
    headers["Content-Type"] = "application/json"
    return HttpRequest("json control", base_url, method="POST", headers=headers,
                       body=json.dumps({param: marker}).encode())
