"""PHASE 5 — differential testing engine + comparison primitives (offline)."""
from core.intelligence.differential import (
    DifferentialEngine,
    ResponseSnapshot,
    body_similarity,
    compare_snapshots,
    normalize_body,
    representation_variants,
)


def _snap(label, status, body, headers=None, ms=1.0):
    return ResponseSnapshot(label=label, status=status, body=body,
                            headers=headers or {}, elapsed_ms=ms)


def test_normalize_scrubs_volatile_tokens():
    a = 'user created id=550e8400-e29b-41d4-a716-446655440000 at 2024-01-01T10:00:00Z'
    b = 'user created id=111e8400-e29b-41d4-a716-446655440999 at 2025-06-02T11:22:33Z'
    assert normalize_body(a) == normalize_body(b)
    assert body_similarity(normalize_body(a), normalize_body(b)) == 1.0


def test_identical_responses_no_divergence():
    a = _snap("a", 200, '{"ok":true}', {"Content-Type": "application/json"})
    b = _snap("b", 200, '{"ok":true}', {"Content-Type": "application/json"})
    assert compare_snapshots(a, b) == []


def test_status_class_crossing_is_medium():
    a = _snap("anon", 403, "denied")
    b = _snap("auth", 200, "denied")
    divs = compare_snapshots(a, b)
    status_divs = [d for d in divs if d.kind == "status"]
    assert status_divs and status_divs[0].severity == "medium"


def test_security_header_divergence_flagged():
    a = _snap("a", 200, "x", {"Content-Security-Policy": "default-src 'self'"})
    b = _snap("b", 200, "x", {})
    kinds = {d.kind for d in compare_snapshots(a, b)}
    assert "header" in kinds


def test_representation_variants_shapes():
    variants = representation_variants("https://t.example/api/user", {"id": "1"})
    labels = [v.label for v in variants]
    assert "GET query-string" in labels
    assert "POST form-urlencoded" in labels
    assert "POST json" in labels
    json_v = next(v for v in variants if v.label == "POST json")
    assert json_v.headers["Content-Type"] == "application/json"
    assert b'"id"' in json_v.body


def test_engine_flags_json_vs_query_divergence():
    """Server that authorises via JSON body but not query string => divergence."""
    def probe(url, method="GET", headers=None, data=None):
        ct = (headers or {}).get("Content-Type", "")
        if method == "POST" and "json" in ct:
            return 200, '{"role":"admin"}', {"Content-Type": "application/json"}
        return 200, '{"role":"guest"}', {"Content-Type": "application/json"}

    result = DifferentialEngine(probe).run_equivalence(
        "https://t.example/api/whoami", {"id": "1"})
    assert result.diverged
    assert any(d.kind == "body" for d in result.divergences)


def test_engine_equivalent_representations_no_divergence():
    def probe(url, method="GET", headers=None, data=None):
        return 200, '{"role":"guest"}', {"Content-Type": "application/json"}

    result = DifferentialEngine(probe).run_equivalence(
        "https://t.example/api/whoami", {"id": "1"})
    assert not result.diverged


def test_unreachable_responses_filtered():
    calls = {"n": 0}

    def probe(url, method="GET", headers=None, data=None):
        calls["n"] += 1
        # Only the first variant "reaches"; rest are network failures (status 0).
        return (200, "ok", {}) if calls["n"] == 1 else (0, "", {})

    result = DifferentialEngine(probe).run_equivalence("https://t.example/x", {"a": "1"})
    assert not result.diverged  # <2 live responses => no false positive
