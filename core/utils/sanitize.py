from __future__ import annotations

import json
import re
from typing import Any

# Strip C0 control chars that Postgres rejects, but keep tab/newline/CR which are
# legal in text and jsonb. 0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, plus DEL (0x7F).
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if "\x00" in value or _CTRL_RE.search(value):
        return _CTRL_RE.sub("", value)
    return value


def clean_json(obj: Any) -> Any:
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
    kwargs.setdefault("default", str)
    return json.dumps(clean_json(obj), **kwargs)


def is_http_success(status: Any) -> bool:
    try:
        s = int(status or 0)
    except (TypeError, ValueError):
        return False
    return 200 <= s < 300


def is_http_redirect(status: Any) -> bool:
    try:
        s = int(status or 0)
    except (TypeError, ValueError):
        return False
    return 300 <= s < 400
