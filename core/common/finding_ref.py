"""Canonical extraction of a finding's HTTP location.

Findings carry their target under different keys (location / url / endpoint /
target) depending on the probe that produced them. This is the one place that
picks the first usable absolute URL, so callers stop re-implementing the
``f.get("location") or f.get("url") or ...`` chain. Returns "" when none is a
real URL.
"""
from __future__ import annotations

from typing import Any, Dict

_LOCATION_KEYS = ("location", "url", "endpoint", "target")


def finding_location(f: Dict[str, Any]) -> str:
    """First absolute-URL location on the finding (fragment stripped), or ""."""
    if not isinstance(f, dict):
        return ""
    for k in _LOCATION_KEYS:
        v = f.get(k)
        if v and isinstance(v, str) and "://" in v:
            return v.split("#", 1)[0]
    return ""
