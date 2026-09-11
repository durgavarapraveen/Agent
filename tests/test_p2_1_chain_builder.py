"""Phase 2.1 — exploit chain synthesis: re-scoring + narrative."""
from __future__ import annotations

from core.exploitation.chain_builder import (
    ChainBuilder,
    end_to_end_cvss,
    impact_to_severity,
)


def test_impact_to_severity_and_cvss():
    assert impact_to_severity(0.95) == "critical"
    assert impact_to_severity(0.75) == "high"
    assert impact_to_severity(0.5) == "medium"
    assert impact_to_severity(0.1) == "low"
    score, sev = end_to_end_cvss(0.95)
    assert score == 9.5 and sev == "critical"


def _findings():
    return [
        {"id": "f1", "type": "xss", "severity": "medium", "location": "/search"},
        {"id": "f2", "type": "rce", "severity": "high", "location": "/upload"},
        {"id": "f3", "type": "info", "severity": "low", "location": "/version"},
    ]


def test_rescore_medium_in_critical_chain_becomes_high():
    chains = [{"chain_id": "C1", "max_impact": 0.95,
               "steps": [{"vuln_id": "f1"}, {"vuln_id": "f2"}],
               "edges": [{"relationship": "enables"}]}]
    vulns = _findings()
    report = ChainBuilder().rescore_findings_by_chain_membership(vulns, chains)

    f1 = next(v for v in vulns if v["id"] == "f1")
    assert f1["severity"] == "high"                 # medium → high (critical chain floor)
    assert f1["original_severity"] == "medium"
    assert f1["severity_upgraded_by_chain"] == "C1"
    # f2 already high — not downgraded, not in the upgrade list
    f2 = next(v for v in vulns if v["id"] == "f2")
    assert f2["severity"] == "high" and "original_severity" not in f2
    # f3 not part of any chain — untouched
    f3 = next(v for v in vulns if v["id"] == "f3")
    assert f3["severity"] == "low"
    assert report["upgraded_count"] == 1


def test_rescore_low_in_high_chain_becomes_medium():
    chains = [{"chain_id": "C2", "max_impact": 0.75, "steps": [{"vuln_id": "f3"}]}]
    vulns = _findings()
    ChainBuilder().rescore_findings_by_chain_membership(vulns, chains)
    f3 = next(v for v in vulns if v["id"] == "f3")
    assert f3["severity"] == "medium"   # low → medium (high chain floor)


def test_rescore_no_floor_for_medium_chain():
    chains = [{"chain_id": "C3", "max_impact": 0.5, "steps": [{"vuln_id": "f1"}]}]
    vulns = _findings()
    report = ChainBuilder().rescore_findings_by_chain_membership(vulns, chains)
    assert report["upgraded_count"] == 0  # medium chain confers no floor


def test_build_narrative():
    chain = {"chain_id": "C1", "max_impact": 0.95,
             "steps": [{"vuln_id": "f1"}, {"vuln_id": "f2"}],
             "edges": [{"relationship": "enables"}]}
    lookup = {v["id"]: v for v in _findings()}
    narr = ChainBuilder().build_narrative(chain, lookup)
    assert narr.severity == "critical"
    assert narr.cvss == 9.5
    assert len(narr.steps) == 2
    assert "xss" in narr.steps[0]
    text = narr.to_text()
    assert "C1" in text and "CVSS 9.5" in text


def test_build_chains_reuses_detector_without_crashing():
    # Two related vuln types (sqli enables credentials/auth_bypass). Should return
    # a list (possibly with a detected chain) and never raise.
    vulns = [
        {"id": "a", "type": "sqli", "severity": "high", "location": "/login"},
        {"id": "b", "type": "auth_bypass", "severity": "high", "location": "/login"},
    ]
    chains = ChainBuilder().build_chains(vulns)
    assert isinstance(chains, list)


def test_synthesize_pipeline():
    out = ChainBuilder().synthesize(_findings())
    assert "chain_count" in out and "rescore" in out and "narratives" in out
