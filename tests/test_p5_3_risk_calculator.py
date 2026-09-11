"""Phase 5.3 — executive risk score in dollars."""
from __future__ import annotations

from core.reporting.risk_calculator import RiskCalculator, RiskContext


def test_severity_scales_cost():
    calc = RiskCalculator()
    crit = calc.estimate_finding_cost({"vuln_class": "sqli", "severity": "critical"})
    med = calc.estimate_finding_cost({"vuln_class": "sqli", "severity": "medium"})
    assert crit["dollars"] > med["dollars"] > 0


def test_industry_multiplier():
    calc = RiskCalculator()
    f = {"vuln_class": "data_leak", "severity": "high"}
    health = calc.estimate_finding_cost(f, RiskContext(industry="healthcare"))
    generic = calc.estimate_finding_cost(f, RiskContext(industry="generic"))
    assert health["dollars"] > generic["dollars"]
    assert health["factors"]["industry_mult"] == 1.5


def test_regulatory_premium_increases_cost():
    calc = RiskCalculator()
    f = {"vuln_class": "data_leak", "severity": "high"}
    with_gdpr = calc.estimate_finding_cost(f, RiskContext(regulations=["gdpr", "hipaa"]))
    without = calc.estimate_finding_cost(f, RiskContext(regulations=[]))
    assert with_gdpr["dollars"] > without["dollars"]
    assert with_gdpr["factors"]["regulatory_mult"] > 1.0


def test_data_types_affect_per_record_cost():
    calc = RiskCalculator()
    health = calc.estimate_finding_cost({"severity": "high", "data_types": ["health"]})
    generic = calc.estimate_finding_cost({"severity": "high", "data_types": ["generic"]})
    assert health["factors"]["per_record"] > generic["factors"]["per_record"]


def test_explicit_record_count_used():
    calc = RiskCalculator()
    est = calc.estimate_finding_cost({"vuln_class": "sqli", "severity": "low", "record_count": 5_000_000})
    assert est["factors"]["records"] == 5_000_000


def test_portfolio_risk_sums_and_ranks():
    calc = RiskCalculator()
    findings = [
        {"title": "SQLi", "vuln_class": "sqli", "severity": "critical"},
        {"title": "XSS", "vuln_class": "xss", "severity": "medium"},
    ]
    port = calc.portfolio_risk(findings, RiskContext(industry="finance"))
    assert port["finding_count"] == 2
    assert port["total_risk_usd"] > 0
    assert port["top_findings"][0]["title"] == "SQLi"  # highest cost first
    assert "critical" in port["by_severity"]


def test_trend():
    calc = RiskCalculator()
    assert calc.trend(1000.0, [])["direction"] == "baseline"
    up = calc.trend(1500.0, [1000.0])
    assert up["direction"] == "up" and up["delta_usd"] == 500.0 and up["delta_pct"] == 50.0
    down = calc.trend(800.0, [1000.0])
    assert down["direction"] == "down"


def test_dashboard_dict_with_trend():
    calc = RiskCalculator()
    findings = [{"title": "SQLi", "vuln_class": "sqli", "severity": "high"}]
    dash = calc.to_dashboard_dict(findings, RiskContext(), historical_totals=[100.0])
    assert "total_risk_usd" in dash and "trend" in dash
    assert dash["trend"]["direction"] in ("up", "down", "flat")


def test_format_usd():
    assert RiskCalculator.format_usd(1234567.89) == "$1,234,568"
