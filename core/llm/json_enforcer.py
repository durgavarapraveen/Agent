"""Phase 10.2 — structured output enforcement for local models.

Small local models (8B-14B) emit invalid JSON ~15-20% of the time: markdown
fences, trailing commas, unquoted keys, single quotes, Python literals, or JSON
buried in prose. This repairs and extracts JSON deterministically, retries with
a simpler prompt when needed, and falls back to a default — so executors don't
fail or burn retries.

The harness ``generate_json`` already strips fences + regex-extracts; this is a
stronger, standalone, testable version it (and executors) can call. JSON-parse
failure rate is tracked per model for metrics.
"""
from __future__ import annotations

import json
import logging
import re
from collections import Counter
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_FENCE = re.compile(r"```(?:json)?\s*|\s*```")
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")
_UNQUOTED_KEY = re.compile(r"([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*:)")
_PY_LITERALS = [("True", "true"), ("False", "false"), ("None", "null")]


def strip_fences(text: str) -> str:
    return _FENCE.sub("", text or "").strip()


def extract_json(text: str) -> Optional[str]:
    """Return the first balanced {...} or [...] region in `text`, or None."""
    if not text:
        return None
    start = None
    opener = None
    for i, ch in enumerate(text):
        if ch in "{[":
            start, opener = i, ch
            break
    if start is None:
        return None
    closer = "}" if opener == "{" else "]"
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _repair(text: str) -> str:
    s = strip_fences(text)
    for a, b in _PY_LITERALS:
        s = re.sub(rf"\b{a}\b", b, s)
    s = _TRAILING_COMMA.sub(r"\1", s)
    s = _UNQUOTED_KEY.sub(r'\1"\2"\3', s)
    return s


def parse_with_repair(text: str) -> Tuple[Optional[Any], str]:
    """Try increasingly aggressive strategies. Returns (parsed, method)."""
    if not text:
        return None, "empty"
    # 1. Direct.
    try:
        return json.loads(text), "direct"
    except (ValueError, TypeError):
        pass
    # 2. Strip fences.
    stripped = strip_fences(text)
    try:
        return json.loads(stripped), "fences"
    except (ValueError, TypeError):
        pass
    # 3. Extract balanced region.
    extracted = extract_json(stripped) or extract_json(text)
    if extracted:
        try:
            return json.loads(extracted), "extract"
        except (ValueError, TypeError):
            pass
        # 4. Repair the extracted region.
        try:
            return json.loads(_repair(extracted)), "repair"
        except (ValueError, TypeError):
            pass
    # 5. Repair the whole thing (single quotes as last resort).
    try:
        return json.loads(_repair(text).replace("'", '"')), "repair_quotes"
    except (ValueError, TypeError):
        return None, "failed"


class JSONEnforcer:

    def __init__(self, max_retries: int = 2):
        self.max_retries = max_retries
        self._attempts = Counter()   # model -> total
        self._failures = Counter()   # model -> parse failures

    def enforce(self, text: str, model: str = "unknown") -> Optional[Any]:
        self._attempts[model] += 1
        parsed, method = parse_with_repair(text)
        if parsed is None:
            self._failures[model] += 1
            logger.warning("json_enforcer: unrecoverable JSON from %s: %s",
                           model, (text or "")[:120])
        elif method != "direct":
            logger.debug("json_enforcer: recovered JSON via '%s' from %s", method, model)
        return parsed

    async def enforce_with_retry(
        self,
        producer: Callable[[bool], Awaitable[str]],
        model: str = "unknown",
        default: Optional[Any] = None,
    ) -> Any:
        """Call `producer(simplify)` for text, parse; on failure retry with a
        simpler prompt (simplify=True) up to max_retries, then return `default`."""
        for attempt in range(self.max_retries + 1):
            text = await producer(attempt > 0)
            parsed = self.enforce(text, model)
            if parsed is not None:
                return parsed
        logger.warning("json_enforcer: exhausted %d retries for %s → default",
                       self.max_retries, model)
        return default

    def failure_rate(self, model: Optional[str] = None) -> float:
        if model:
            a = self._attempts.get(model, 0)
            return round(self._failures.get(model, 0) / a, 3) if a else 0.0
        total = sum(self._attempts.values())
        return round(sum(self._failures.values()) / total, 3) if total else 0.0

    def stats(self) -> Dict[str, Any]:
        return {"attempts": dict(self._attempts), "failures": dict(self._failures),
                "overall_failure_rate": self.failure_rate()}
