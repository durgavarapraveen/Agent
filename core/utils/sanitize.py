"""Shared DB-write hygiene + generic HTTP-status helpers.

Product-generic (no target-specific assumptions). Used everywhere the agent
writes to Postgres or classifies an HTTP response.

Two problem classes this module fixes centrally:

  1. NUL (0x00) / control bytes reaching Postgres.
     - Raw ``\\x00`` in a *text* column → psycopg raises
       ``ValueError: A string literal cannot contain NUL (0x00) characters``.
     - ``\\u0000`` in a *jsonb* value → Postgres raises
       ``unsupported Unicode escape sequence ... \\u0000 cannot be converted to text``.
     Binary tool output (TLS handshakes, raw sockets, gzip) routinely carries
     these bytes. ``clean_text`` / ``clean_json`` / ``safe_json_dumps`` strip
     them before any write.

  2. HTTP success detection hardcoded to ``== 200``.
     Valid outcomes also arrive as 201/202/204/206 (created/accepted/no-content/
     partial) and redirects as 3xx. ``is_http_success`` / ``is_http_redirect``
     make oracles generic instead of 200-only.
"""
from __future__ import annotations

import json
import re
from typing import Any

# Strip C0 control chars that Postgres rejects, but keep tab/newline/CR which are
# legal in text and jsonb. 0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, plus DEL (0x7F).
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value: Any) -> Any:
    """Strip DB-hostile control bytes from a string; pass non-strings through."""
    if not isinstance(value, str):
        return value
    if "\x00" in value or _CTRL_RE.search(value):
        return _CTRL_RE.sub("", value)
    return value


def clean_json(obj: Any) -> Any:
    """Recursively strip control bytes from every string in a JSON-like object.

    Cleans dict keys and values, list/tuple items, at any depth. Non-string
    scalars are returned unchanged. Applying this *before* ``json.dumps`` means
    the serialized text never contains a ``\\u0000`` escape, so jsonb columns
    accept it.
    """
    if isinstance(obj, str):
        return clean_text(obj)
    if isinstance(obj, dict):
        return {
            (clean_text(k) if isinstance(k, str) else k): clean_json(v)
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [clean_json(x) for x in obj]
    return obj


def safe_json_dumps(obj: Any, **kwargs) -> str:
    """``json.dumps`` with control bytes stripped first. Defaults ``default=str``."""
    kwargs.setdefault("default", str)
    return json.dumps(clean_json(obj), **kwargs)


def is_http_success(status: Any) -> bool:
    """True for any 2xx status (200/201/202/204/206/...), not just 200."""
    try:
        s = int(status or 0)
    except (TypeError, ValueError):
        return False
    return 200 <= s < 300


def is_http_redirect(status: Any) -> bool:
    """True for any 3xx redirect status."""
    try:
        s = int(status or 0)
    except (TypeError, ValueError):
        return False
    return 300 <= s < 400
