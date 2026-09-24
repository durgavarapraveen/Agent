"""Attack-path evaluation harness (spec Phase 37/38/44)."""
import pytest

from core.validation.attack_path_eval import (
    GroundTruth, ExpectedFinding, ExpectedPath, evaluate, default_ground_truths,
)

B = "https://t.example"


def _gt():
    return GroundTruth(
        target=B,
        expected_findings=[
            ExpectedFinding("f_sqli", "SQLI", f"{B}/api/u", "id",
                            "RESOURCE_ACCESS_PROVEN", "EXPLOITED"),
            ExpectedFinding("f_idor", "IDOR", f"{B}/api/o", "oid",
                            "RESOURCE_ACCESS_PROVEN", "VALIDATED"),
            ExpectedFinding("f_redir", "OPEN_REDIRECT", f"{B}/go", "next",
                            "NO_IMPACT_PROVEN", "SUSPECTED"),
        ],
        expected_paths=[
            ExpectedPath("p_sqli", ["sqli"]),
            ExpectedPath("p_idor", ["idor"]),
        ],
    )


def _perfect_findings():
    return [
        {"type": "SQLI", "title": "sqli", "location": f"{B}/api/u?id=1",
         "parameter": "id", "data_returned": True, "exploited": True,
         "proof": "returned rows"},
        {"type": "IDOR", "title": "idor", "location": f"{B}/api/o",
         "parameter": "oid", "other_user_data": True, "status": "VALIDATED",
         "proof": "other user's record"},
        {"type": "OPEN_REDIRECT", "title": "open redirect", "location": f"{B}/go?next=x",
         "parameter": "next", "proof": "param accepted"},
    ]


def test_perfect_scan_full_recall_and_paths():
    res = {"vulnerabilities": _perfect_findings()}
    rep = evaluate(res, _gt())
    assert rep.finding_recall == 1.0
    assert rep.false_negatives == 0
    assert rep.finding_precision == 1.0
    # paths built from findings by the engine → both single-class paths matched
    assert rep.attack_path_discovery_rate == 1.0
    assert rep.attack_paths_discovered >= 2


def test_missing_finding_lowers_recall_and_counts_fn():
    res = {"vulnerabilities": _perfect_findings()[:1]}   # only sqli
    rep = evaluate(res, _gt())
    assert rep.matched_findings == 1
    assert rep.false_negatives == 2
    assert 0.0 < rep.finding_recall < 1.0
    assert any("f_idor" in m for m in rep.misses)


def test_false_positive_lowers_precision():
    res = {"vulnerabilities": _perfect_findings() + [
        {"type": "XSS", "title": "not expected", "location": f"{B}/x", "parameter": "z"}]}
    rep = evaluate(res, _gt())
    assert rep.false_positives == 1
    assert rep.finding_precision < 1.0


def test_impact_accuracy_and_validated_rates():
    rep = evaluate({"vulnerabilities": _perfect_findings()}, _gt())
    # sqli→RESOURCE_ACCESS(EXPLOITED), idor→RESOURCE_ACCESS, redir→NO_IMPACT all correct
    assert rep.impact_accuracy == 1.0
    assert rep.validated_vuln_rate > 0.0
    assert rep.exploit_validation_rate > 0.0        # sqli exploited
    assert rep.evidence_quality == 1.0


def test_explicit_paths_matched_and_validated():
    res = {"vulnerabilities": _perfect_findings(),
           "attack_paths": [
               {"steps": [{"action": "info_disclosure"}, {"action": "authz"}],
                "status": "exploited"},
           ]}
    gt = GroundTruth(target=B, expected_paths=[
        ExpectedPath("p_pivot", ["info_disclosure", "authz"], min_status="exploited")])
    rep = evaluate(res, gt)
    assert rep.attack_paths_discovered == 1
    assert rep.attack_path_discovery_rate == 1.0
    assert rep.validated_attack_paths == 1          # status meets min_status


def test_path_subsequence_not_matched_when_order_wrong():
    res = {"attack_paths": [{"steps": [{"action": "authz"}, {"action": "info_disclosure"}]}]}
    gt = GroundTruth(target=B, expected_paths=[
        ExpectedPath("p", ["info_disclosure", "authz"])])
    rep = evaluate(res, gt)
    assert rep.attack_path_discovery_rate == 0.0    # order matters


def test_cost_passthrough_and_report_dict():
    res = {"vulnerabilities": _perfect_findings(),
           "cost": {"tokens": 12000, "tool_calls": 40, "usd": 0.31}}
    rep = evaluate(res, _gt())
    assert rep.cost["tool_calls"] == 40
    d = rep.to_dict()
    assert "validated_attack_paths" in d and isinstance(d["finding_f1"], float)


def test_default_corpus_covers_spec_classes():
    gts = default_ground_truths()
    assert gts
    classes = {ef.vuln_class for ef in gts[0].expected_findings}
    for c in ("SQLI", "XSS", "IDOR", "SSRF", "AUTHZ", "OPEN_REDIRECT", "INFO_DISCLOSURE"):
        assert c in classes


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
