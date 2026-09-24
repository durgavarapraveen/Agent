"""Forward attack-path engine (spec Phase 8/32)."""
import pytest

from core.attack_surface.attack_path_engine import AttackPathEngine


def _f(**kw):
    kw.setdefault("location", "https://a.example/x")
    return kw


def test_same_host_chain_initial_to_target():
    findings = [
        _f(type="SQL Injection", title="sqli in id", parameter="id",
           lifecycle="VALIDATED", location="https://a.example/u?id=1"),
        _f(type="IDOR", title="idor", parameter="oid",
           impact_level="RESOURCE_ACCESS_PROVEN", location="https://a.example/o"),
    ]
    paths = AttackPathEngine(findings).generate()
    multi = [p for p in paths if len(p["steps"]) >= 2]
    assert multi, "expected a multi-step same-host path"
    p = multi[0]
    assert p["starting_position"] == "internet"
    assert "sqli" in p["techniques"] and "idor" in p["techniques"]


def test_cross_host_credential_pivot():
    findings = [
        _f(type="Information Disclosure", title="aws key leaked",
           impact_level="SENSITIVE_DATA_ACCESS_PROVEN",
           location="https://a.example/config"),
        _f(type="Broken Access Control", title="authz bypass",
           cross_identity_access=True, location="https://b.example/admin"),
    ]
    paths = AttackPathEngine(findings).generate()
    pivot = [p for p in paths
             if any(s["action"] == "info_disclosure" for s in p["steps"])
             and any(s["action"] == "authz" for s in p["steps"])]
    assert pivot, "expected a cross-host credential→privesc pivot"


def test_factors_are_transparent_and_stored():
    findings = [_f(type="IDOR", impact_level="RESOURCE_ACCESS_PROVEN",
                   parameter="id", proof="returned other user's record")]
    p = AttackPathEngine(findings).generate()[0]
    for k in ("reachability", "validation", "impact", "privilege_gain",
              "evidence_quality", "cost_efficiency"):
        assert k in p["factors"] and 0.0 <= p["factors"][k] <= 1.0
    assert 0.0 <= p["score"] <= 1.0


def test_ranked_high_impact_first():
    findings = [
        _f(type="IDOR", title="low", impact_level="LOW_IMPACT_PROVEN",
           location="https://a.example/1"),
        _f(type="IDOR", title="high", impact_level="SENSITIVE_DATA_ACCESS_PROVEN",
           parameter="id", proof="ssn exposed", location="https://a.example/2"),
    ]
    paths = AttackPathEngine(findings).generate()
    assert paths[0]["factors"]["impact"] >= paths[-1]["factors"]["impact"]


def test_status_reflects_evidence_not_optimism():
    # unproven findings → hypothesized, never exploited
    findings = [_f(type="Open Redirect", title="maybe",
                   impact_level="NO_IMPACT_PROVEN", location="https://a.example/r")]
    paths = AttackPathEngine(findings).generate()
    assert all(p["status"] == "hypothesized" for p in paths)


def test_exploited_steps_yield_exploited_status():
    findings = [_f(type="SQL Injection", exploited=True, parameter="id",
                   impact_level="RESOURCE_ACCESS_PROVEN",
                   location="https://a.example/u")]
    p = AttackPathEngine(findings).generate()[0]
    assert p["status"] in ("exploited", "impact_confirmed")


def test_no_findings_no_paths():
    assert AttackPathEngine([]).generate() == []


def test_dedupe_identical_paths():
    f = _f(type="IDOR", impact_level="RESOURCE_ACCESS_PROVEN", parameter="id",
           location="https://a.example/o")
    paths = AttackPathEngine([f, dict(f)]).generate()
    keys = [(p["starting_position"], p["target"],
             tuple(s["action"] for s in p["steps"])) for p in paths]
    assert len(keys) == len(set(keys))


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
