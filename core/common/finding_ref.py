"""Canonical extraction of a finding's HTTP location.

Findings carry their target under different keys (location / url / endpoint /
target) depending on the probe that produced them. This is the one place that
picks the first usable absolute URL, so callers stop re-implementing the
``f.get("location") or f.get("url") or ...`` chain. Returns "" when none is a
real URL.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict
from urllib.parse import urlsplit, parse_qsl

_LOCATION_KEYS = ("location", "url", "endpoint", "target")


def finding_location(f: Dict[str, Any]) -> str:
    """First absolute-URL location on the finding (fragment stripped), or ""."""
    if not isinstance(f, dict):
        return ""
    for k in _LOCATION_KEYS:
        v = f.get(k)
        if v and isinstance(v, str) and "://" in v:
            return v.split("#", 1)[0]
    # Fall back to any non-empty location-ish value (e.g. a host or path).
    for k in _LOCATION_KEYS:
        v = f.get(k)
        if v and isinstance(v, str):
            return v.split("#", 1)[0]
    return ""


def canonical_location(loc: str) -> str:
    """scheme://host/path + sorted query-param NAMES (values dropped), lowercased.

    So /x?id=1 and /x?id=2 collapse, while /x?id and /x?token stay distinct.
    Non-URL strings fall back to their lowercased selves.
    """
    loc = (loc or "").split("#", 1)[0].strip()
    try:
        s = urlsplit(loc)
        if not s.scheme:
            return loc.lower()
        names = sorted({k for k, _ in parse_qsl(s.query, keep_blank_values=True)})
        base = f"{s.scheme}://{s.netloc}{s.path}".lower().rstrip("/")
        return base + ("?" + ",".join(names) if names else "")
    except Exception:
        return loc.lower()


def _vuln_type(f: Dict[str, Any]) -> str:
    for k in ("type", "category", "attack_type", "vuln_type", "sub_type"):
        v = f.get(k)
        if v:
            return str(v).strip().upper()
    return "UNCATEGORIZED"


def _parameter(f: Dict[str, Any]) -> str:
    for k in ("parameter", "param", "injection_point", "field"):
        v = f.get(k)
        if v:
            return str(v).strip().lower()
    return ""


def _auth_context(f: Dict[str, Any]) -> str:
    for k in ("auth_context", "identity", "identity_id", "role", "principal"):
        v = f.get(k)
        if v:
            return str(v).strip().lower()
    return "anon"


def finding_fingerprint(f: Dict[str, Any]) -> str:
    """Deterministic canonical identity for a finding (spec Phase 21).

    Keyed on the STRUCTURAL facts — canonical asset/endpoint, vulnerability
    class, parameter and auth context — never on the free-text title (which the
    LLM phrases differently each run and which caused one logical vuln to persist
    as many). Two reports of the same bug share a fingerprint; genuinely distinct
    parameters / classes / identities do not collapse.
    """
    if not isinstance(f, dict):
        return ""
    param = _parameter(f)
    # When there is no parameter, the vulnerability class alone is too coarse to
    # separate, e.g., "missing X-Frame-Options" from "missing CSP" on one host —
    # there the title carries the specifics, so fold a normalized title token in.
    # When a parameter IS present it is the discriminator and the (LLM-variable)
    # title is deliberately excluded.
    discriminator = param or _title_token(f)
    parts = [
        canonical_location(finding_location(f)),
        _vuln_type(f),
        discriminator,
        _auth_context(f),
    ]
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _title_token(f: Dict[str, Any]) -> str:
    """Stable lowercase alnum token from the title (first ~6 words), for
    host-level findings whose only distinguisher is the title."""
    title = str(f.get("title") or "").lower()
    words = [w for w in "".join(c if c.isalnum() else " " for c in title).split()]
    return " ".join(words[:6])
