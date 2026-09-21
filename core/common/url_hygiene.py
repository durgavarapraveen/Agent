"""Canonical URL hygiene — one place that turns any endpoint-ish string into a
clean absolute http(s) URL, or rejects it.

WHY: endpoint records store ids as "{method}:{scheme}://host/path" (see
core/domain/endpoint.py). When such an id is fed back into URL builders as if it
were a path, it produces stacked-scheme corruption like
"https://host/#/get:get://https://host/rest/user" — which then (a) fails scope
checks, (b) is sent as a malformed request target, (c) inflates coverage
denominators, (d) over-counts findings. JS-source extraction also leaks template
artifacts ("$1.routeConfig", "/**", "${x}") into the endpoint set.

This normaliser fixes both: it un-stacks METHOD:/scheme:// prefixes, recovers a
real URL embedded in an SPA "/#/" fragment, and rejects template/garbage tokens.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

_METHODS = ("get", "post", "put", "delete", "patch", "head", "options",
            "connect", "trace")
_METHOD_RE = re.compile(r'^(?:' + "|".join(_METHODS) + r'):', re.IGNORECASE)
_SCHEME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://')
# Tokens that mean "this is not a real URL" — un-rendered JS templates, glob
# wildcards, regex backrefs, angle brackets, whitespace, boolean operators.
_GARBAGE = ("${", "{{", "}}", "`", "$1", "$2", "**", "<", ">", " ", "||", "&&",
            "\\", "\n", "\t")
_HOST_RE = re.compile(r'^[A-Za-z0-9.\-]+$')


def _strip_stacked_prefixes(s: str) -> str:
    prev = None
    while s and s != prev:
        prev = s
        # A pseudo-scheme ("get://", "post://") that is NOT the real http(s).
        m = _SCHEME_RE.match(s)
        if m and not s.lower().startswith(("http://", "https://")):
            s = s[m.end():]
            continue
        # A bare "METHOD:" prefix ("get:", "post:").
        m = _METHOD_RE.match(s)
        if m:
            s = s[m.end():]
            continue
    return s


def canonical_http_url(raw: str, base: str = "") -> str:
    """Return a clean absolute http(s) URL for `raw`, or "" if it isn't one.

    - Recovers a real URL embedded in an SPA "/#/" fragment (the corruption case).
    - Un-stacks METHOD:/scheme:// artifacts.
    - Joins a bare path onto `base` (the scan target) when there's no scheme.
    - Rejects JS-template / glob / regex garbage.
    """
    if not raw:
        return ""
    s = str(raw).strip()
    if not s:
        return ""
    # SPA-fragment-embedded real URL: "<base>/#/<junk>https://realhost/…".
    # Only unwrap when the fragment itself carries a scheme, so a legitimate
    # client-side route like "https://host/#/login" is left untouched.
    if "/#/" in s:
        _head, _frag = s.split("/#/", 1)
        if "://" in _frag:
            s = _frag
    s = _strip_stacked_prefixes(s)
    # Reject obvious non-URLs / template artifacts.
    low = s.lower()
    if any(t in s for t in _GARBAGE):
        return ""
    # Ensure absolute http(s).
    if not low.startswith(("http://", "https://")):
        if not base:
            return ""
        b = base if base.lower().startswith(("http://", "https://")) else "https://" + base
        if not s.startswith("/"):
            s = "/" + s
        s = b.rstrip("/") + s
    # Validate host.
    try:
        p = urlparse(s)
    except Exception:
        return ""
    host = p.hostname or ""
    if p.scheme in ("http", "https") and host and _HOST_RE.match(host):
        return s
    return ""


def looks_like_real_endpoint(raw: str, base: str = "") -> bool:
    """True if `raw` canonicalises to a usable http(s) endpoint."""
    return bool(canonical_http_url(raw, base))
