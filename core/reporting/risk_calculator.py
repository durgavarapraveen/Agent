"""Phase 5.3 — executive risk score in dollars.

Translates technical findings into a breach-cost estimate leadership can act on,
using an IBM "Cost of a Data Breach"-style per-record model modulated by
industry, the data types exposed, an estimated record count, and the regulatory
environment (GDPR / CCPA / HIPAA / PCI). Produces a dollar estimate per finding,
a total portfolio risk, and a trend vs. prior scans.

Pure and deterministic — unit-testable with no external data.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Approximate IBM Cost of a Data Breach figures (USD).
DATA_TYPE_COST_PER_RECORD = {"pii": 165.0, "financial": 175.0, "health": 180.0,
                             "credentials": 170.0, "generic": 150.0}
INDUSTRY_MULT = {"healthcare": 1.5, "finance": 1.4, "fintech": 1.4, "banking": 1.45,
                 "ecommerce": 1.1, "retail": 1.1, "saas_admin": 1.2, "technology": 1.2,
                 "education": 1.0, "generic": 1.0}
REGULATORY_MULT = {"hipaa": 0.30, "gdpr": 0.25, "ccpa": 0.15, "pci": 0.20}  # additive premiums
SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.6, "medium": 0.25, "low": 0.05, "info": 0.0}
RECORDS_BY_SEVERITY = {"critical": 100_000, "high": 10_000, "medium": 1_000, "low": 100, "info": 0}

# Vuln class → data types typically exposed, for when a finding doesn't specify.
_CLASS_DATA_TYPES = {
    "sqli": ["pii", "financial"], "data_leak": ["pii"], "idor": ["pii"],
    "bola": ["pii"], "auth_bypass": ["pii", "credentials"], "rce": ["credentials", "financial"],
    "ssrf": ["credentials"], "excessive_data_exposure": ["pii"],
}


@dataclass
class RiskContext:
    industry: str = "generic"
    regulations: List[str] = field(default_factory=list)   # e.g. ["gdpr", "hipaa"]
    record_multiplier: float = 1.0                          # scale record estimates


def _regulatory_multiplier(regulations: List[str]) -> float:
    premium = sum(REGULATORY_MULT.get(str(r).lower(), 0.0) for r in regulations or [])
    return 1.0 + min(premium, 0.75)  # cap the stacked premium


def _data_types(finding: Dict[str, Any]) -> List[str]:
    dt = finding.get("data_types")
    if isinstance(dt, list) and dt:
        return [str(t).lower() for t in dt]
    vclass = str(finding.get("vuln_class") or finding.get("type") or "").lower()
    return _CLASS_DATA_TYPES.get(vclass, ["generic"])


class RiskCalculator:

    def estimate_finding_cost(self, finding: Dict[str, Any],
                              context: Optional[RiskContext] = None) -> Dict[str, Any]:
        context = context or RiskContext()
        severity = str(finding.get("severity", "medium")).lower()
        data_types = _data_types(finding)
        per_record = max(DATA_TYPE_COST_PER_RECORD.get(t, 150.0) for t in data_types)
        records = int(finding.get("record_count")
                      or RECORDS_BY_SEVERITY.get(severity, 1_000)) * context.record_multiplier
        industry_mult = INDUSTRY_MULT.get(context.industry.lower(), 1.0)
        reg_mult = _regulatory_multiplier(context.regulations)
        sev_weight = SEVERITY_WEIGHT.get(severity, 0.25)

        dollars = per_record * records * industry_mult * reg_mult * sev_weight
        return {
            "dollars": round(dollars, 2),
            "severity": severity,
            "data_types": data_types,
            "factors": {
                "per_record": per_record, "records": int(records),
                "industry_mult": industry_mult, "regulatory_mult": round(reg_mult, 3),
                "severity_weight": sev_weight,
            },
        }

    def portfolio_risk(self, findings: List[Dict[str, Any]],
                       context: Optional[RiskContext] = None) -> Dict[str, Any]:
        context = context or RiskContext()
        total = 0.0
        by_severity: Dict[str, float] = {}
        per_finding: List[Dict[str, Any]] = []
        for f in findings:
            est = self.estimate_finding_cost(f, context)
            total += est["dollars"]
            by_severity[est["severity"]] = round(
                by_severity.get(est["severity"], 0.0) + est["dollars"], 2)
            per_finding.append({
                "title": f.get("title") or f.get("type", "finding"),
                "severity": est["severity"], "dollars": est["dollars"]})
        per_finding.sort(key=lambda x: x["dollars"], reverse=True)
        return {
            "total_risk_usd": round(total, 2),
            "by_severity": by_severity,
            "top_findings": per_finding[:10],
            "finding_count": len(findings),
            "industry": context.industry,
            "regulations": context.regulations,
        }

    def trend(self, current_total: float, historical_totals: List[float]) -> Dict[str, Any]:
        if not historical_totals:
            return {"direction": "baseline", "delta_usd": 0.0, "delta_pct": 0.0}
        prev = historical_totals[-1]
        delta = current_total - prev
        pct = (delta / prev * 100.0) if prev else 0.0
        direction = "up" if delta > 0 else ("down" if delta < 0 else "flat")
        return {"direction": direction, "delta_usd": round(delta, 2),
                "delta_pct": round(pct, 1), "previous_usd": round(prev, 2)}

    def to_dashboard_dict(self, findings: List[Dict[str, Any]],
                          context: Optional[RiskContext] = None,
                          historical_totals: Optional[List[float]] = None) -> Dict[str, Any]:
        portfolio = self.portfolio_risk(findings, context)
        portfolio["trend"] = self.trend(portfolio["total_risk_usd"], historical_totals or [])
        return portfolio

    @staticmethod
    def format_usd(amount: float) -> str:
        return f"${amount:,.0f}"
