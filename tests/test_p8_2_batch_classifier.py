"""Phase 8.2 — batch endpoint classification."""
from __future__ import annotations

from core.llm.batch_classifier import (
    BatchClassifier,
    build_batch_prompt,
    group_by_pattern,
    parse_batch_classification,
)


def _endpoints(n=60):
    # 3 distinct patterns instantiated many times.
    eps = []
    for i in range(n):
        eps.append({"url": f"https://x/api/products/{i}", "method": "GET"})
        eps.append({"url": f"https://x/api/users/{i}/orders", "method": "GET"})
        eps.append({"url": f"https://x/login", "method": "POST"})
    return eps


def test_group_by_pattern_collapses_instances():
    groups = group_by_pattern(_endpoints(50))
    assert "GET /api/products/{id}" in groups
    assert "GET /api/users/{id}/orders" in groups
    assert "POST /login" in groups
    assert len(groups) == 3   # 150 endpoints → 3 patterns


def test_parse_batch_classification():
    patterns = ["GET /api/products/{id}", "POST /login"]
    resp = {"classifications": [
        {"pattern": "GET /api/products/{id}", "risk": "medium", "vuln_classes": ["idor"]},
        {"pattern": "POST /login", "risk": "high", "vuln_classes": ["sqli", "brute_force"]},
    ]}
    parsed = parse_batch_classification(resp, patterns)
    assert parsed["POST /login"]["risk"] == "high"
    assert "idor" in parsed["GET /api/products/{id}"]["vuln_classes"]


def test_parse_defaults_missing_patterns():
    parsed = parse_batch_classification({"classifications": []}, ["GET /a"])
    assert parsed["GET /a"]["risk"] == "medium"


def test_build_batch_prompt():
    prompt = build_batch_prompt(["GET /a", "POST /b"])
    assert "GET /a" in prompt and "POST /b" in prompt
    assert "JSON" in prompt


def test_estimated_call_savings():
    bc = BatchClassifier(batch_size=25)
    savings = bc.estimated_call_savings(_endpoints(50))  # 150 endpoints, 3 patterns
    assert savings["patterns"] == 3
    assert savings["endpoints"] == 150       # 50 × 3 instances
    assert savings["batched_calls"] == 1     # 3 patterns fit in one batch
    assert savings["calls_saved"] == 149     # 150 per-endpoint calls → 1 batched


async def test_classify_batches_with_fake_llm():
    class _LLM:
        def __init__(self):
            self.calls = 0

        async def generate_json(self, prompt, **kw):
            self.calls += 1
            # echo back medium for every pattern in the prompt
            return {"classifications": []}

    llm = _LLM()
    bc = BatchClassifier(llm=llm, batch_size=25)
    result = await bc.classify(_endpoints(50))  # 3 patterns → 1 batch call
    assert llm.calls == 1
    assert len(result) == 3
    assert all(v["risk"] == "medium" for v in result.values())
