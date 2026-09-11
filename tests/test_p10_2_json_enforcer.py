"""Phase 10.2 — structured output enforcement (JSON repair)."""
from __future__ import annotations

from core.llm.json_enforcer import (
    JSONEnforcer,
    extract_json,
    parse_with_repair,
    strip_fences,
)


def test_direct_valid_json():
    parsed, method = parse_with_repair('{"a": 1}')
    assert parsed == {"a": 1} and method == "direct"


def test_strip_fences():
    parsed, method = parse_with_repair('```json\n{"a": 1}\n```')
    assert parsed == {"a": 1} and method in ("fences", "extract")


def test_extract_from_prose():
    text = 'Sure! Here is the result: {"vuln": true, "sev": "high"} — hope that helps.'
    parsed, method = parse_with_repair(text)
    assert parsed == {"vuln": True, "sev": "high"}
    assert method in ("extract", "repair")


def test_repair_trailing_comma_and_unquoted_keys():
    parsed, _ = parse_with_repair('{ name: "x", vals: [1, 2,], }')
    assert parsed == {"name": "x", "vals": [1, 2]}


def test_repair_python_literals():
    parsed, _ = parse_with_repair('{"ok": True, "bad": False, "n": None}')
    assert parsed == {"ok": True, "bad": False, "n": None}


def test_repair_single_quotes_last_resort():
    parsed, _ = parse_with_repair("{'a': 'b'}")
    assert parsed == {"a": "b"}


def test_unrecoverable_returns_none():
    parsed, method = parse_with_repair("this is not json at all")
    assert parsed is None and method == "failed"


def test_extract_json_balanced():
    assert extract_json('noise {"a": {"b": 1}} more') == '{"a": {"b": 1}}'
    assert extract_json("[1, 2, 3]") == "[1, 2, 3]"
    assert extract_json("nothing here") is None


def test_enforcer_tracks_failure_rate():
    enf = JSONEnforcer()
    assert enf.enforce('{"a":1}', model="qwen:8b") == {"a": 1}
    assert enf.enforce("garbage", model="qwen:8b") is None
    assert enf.failure_rate("qwen:8b") == 0.5
    assert enf.stats()["attempts"]["qwen:8b"] == 2


async def test_enforce_with_retry_recovers():
    outputs = iter(["not json", '{"ok": 1}'])

    async def producer(simplify):
        return next(outputs)

    enf = JSONEnforcer(max_retries=2)
    result = await enf.enforce_with_retry(producer, model="local")
    assert result == {"ok": 1}


async def test_enforce_with_retry_falls_back_to_default():
    async def producer(simplify):
        return "never valid"

    enf = JSONEnforcer(max_retries=1)
    result = await enf.enforce_with_retry(producer, model="local", default={"fallback": True})
    assert result == {"fallback": True}
