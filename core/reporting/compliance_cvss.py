"""P8: Compliance Mapping & CVSS Scoring — maps CWE to frameworks, auto-scores findings."""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple  # noqa: F401

logger = logging.getLogger(__name__)


@dataclass
class ComplianceMapping:
    cwe: str
    owasp_top10: str = ""
    owasp_api: str = ""
    pci_dss: List[str] = field(default_factory=list)
    hipaa: List[str] = field(default_factory=list)
    soc2: List[str] = field(default_factory=list)
    nist_800_53: List[str] = field(default_factory=list)
    gdpr: List[str] = field(default_factory=list)


@dataclass
class CVSSScore:
    base_score: float = 0.0
    vector_string: str = ""
    severity_label: str = ""  # None, Low, Medium, High, Critical
    attack_vector: str = "N"  # N(etwork), A(djacent), L(ocal), P(hysical)
    attack_complexity: str = "L"  # L(ow), H(igh)
    privileges_required: str = "N"  # N(one), L(ow), H(igh)
    user_interaction: str = "N"  # N(one), R(equired)
    scope: str = "U"  # U(nchanged), C(hanged)
    confidentiality: str = "N"  # N(one), L(ow), H(igh)
    integrity: str = "N"
    availability: str = "N"


# CWE → compliance framework mappings (extensible via pattern matching)
_CWE_COMPLIANCE: Dict[str, ComplianceMapping] = {
    "CWE-79": ComplianceMapping("CWE-79", "A03:2021", "API8", ["6.5.7", "6.6"], ["§164.312(e)(1)"], ["CC6.1"], ["SI-10", "SA-11"], ["Art.32(1)(b)"]),
    "CWE-89": ComplianceMapping("CWE-89", "A03:2021", "API8", ["6.5.1", "6.6"], ["§164.312(a)(1)"], ["CC6.1"], ["SI-10", "SA-11"], ["Art.32(1)(b)"]),
    "CWE-22": ComplianceMapping("CWE-22", "A01:2021", "", ["6.5.8"], ["§164.312(a)(1)"], ["CC6.1"], ["SI-10"], ["Art.32(1)(b)"]),
    "CWE-78": ComplianceMapping("CWE-78", "A03:2021", "", ["6.5.1"], ["§164.312(a)(1)"], ["CC6.1"], ["SI-10", "SA-11"], ["Art.32(1)(b)"]),
    "CWE-200": ComplianceMapping("CWE-200", "A01:2021", "API3", ["6.5.6"], ["§164.312(e)(1)"], ["CC6.1", "CC6.5"], ["SI-11", "AC-4"], ["Art.5(1)(f)", "Art.32"]),
    "CWE-284": ComplianceMapping("CWE-284", "A01:2021", "API1", ["7.1", "7.2"], ["§164.312(a)(1)"], ["CC6.1", "CC6.2"], ["AC-3", "AC-6"], ["Art.32(1)(b)"]),
    "CWE-306": ComplianceMapping("CWE-306", "A07:2021", "API2", ["8.1", "8.2"], ["§164.312(d)"], ["CC6.1"], ["IA-2", "IA-5"], ["Art.32(1)(b)"]),
    "CWE-327": ComplianceMapping("CWE-327", "A02:2021", "", ["4.1", "6.5.3"], ["§164.312(a)(2)(iv)"], ["CC6.1"], ["SC-12", "SC-13"], ["Art.32(1)(a)"]),
    "CWE-328": ComplianceMapping("CWE-328", "A02:2021", "", ["6.5.3"], ["§164.312(a)(2)(iv)"], ["CC6.1"], ["SC-12"], ["Art.32(1)(a)"]),
    "CWE-345": ComplianceMapping("CWE-345", "A02:2021", "", ["6.5.10"], ["§164.312(e)(1)"], ["CC6.1"], ["SC-13", "SI-7"], ["Art.32(1)(a)"]),
    "CWE-352": ComplianceMapping("CWE-352", "A01:2021", "", ["6.5.9"], [], ["CC6.1"], ["SI-10"], []),
    "CWE-362": ComplianceMapping("CWE-362", "A04:2021", "", ["6.5.6"], [], ["CC6.1"], ["SI-16"], []),
    "CWE-434": ComplianceMapping("CWE-434", "A04:2021", "", ["6.5.8"], ["§164.312(a)(1)"], ["CC6.1"], ["SI-10"], ["Art.32(1)(b)"]),
    "CWE-521": ComplianceMapping("CWE-521", "A07:2021", "", ["8.2.3"], ["§164.312(d)"], ["CC6.1"], ["IA-5"], ["Art.32(1)(b)"]),
    "CWE-602": ComplianceMapping("CWE-602", "A04:2021", "", ["6.5.1"], [], ["CC6.1"], ["SI-10"], []),
    "CWE-614": ComplianceMapping("CWE-614", "A05:2021", "", ["6.5.10"], ["§164.312(e)(1)"], ["CC6.1"], ["SC-8"], ["Art.32(1)(a)"]),
    "CWE-639": ComplianceMapping("CWE-639", "A01:2021", "API1", ["7.1"], ["§164.312(a)(1)"], ["CC6.1", "CC6.2"], ["AC-3"], ["Art.32(1)(b)"]),
    "CWE-640": ComplianceMapping("CWE-640", "A07:2021", "", ["8.2"], ["§164.312(d)"], ["CC6.1"], ["IA-5"], ["Art.32(1)(b)"]),
    "CWE-798": ComplianceMapping("CWE-798", "A07:2021", "", ["6.3.1", "8.2"], ["§164.312(a)(1)"], ["CC6.1"], ["IA-5", "SC-12"], ["Art.32(1)(a)"]),
    "CWE-862": ComplianceMapping("CWE-862", "A01:2021", "API5", ["7.1", "7.2"], ["§164.312(a)(1)"], ["CC6.1"], ["AC-3"], ["Art.32(1)(b)"]),
    "CWE-863": ComplianceMapping("CWE-863", "A01:2021", "API1", ["7.1"], ["§164.312(a)(1)"], ["CC6.1"], ["AC-3"], ["Art.32(1)(b)"]),
    "CWE-916": ComplianceMapping("CWE-916", "A02:2021", "", ["8.2.1"], ["§164.312(a)(2)(iv)"], ["CC6.1"], ["IA-5"], ["Art.32(1)(a)"]),
    "CWE-918": ComplianceMapping("CWE-918", "A10:2021", "API7", ["6.5.1"], ["§164.312(a)(1)"], ["CC6.1"], ["SI-10"], ["Art.32(1)(b)"]),
    "CWE-20": ComplianceMapping("CWE-20", "A03:2021", "API8", ["6.5.1"], [], ["CC6.1"], ["SI-10"], []),
    "CWE-74": ComplianceMapping("CWE-74", "A03:2021", "", ["6.5.1"], [], ["CC6.1"], ["SI-10"], []),
    "CWE-190": ComplianceMapping("CWE-190", "A03:2021", "", ["6.5.2"], [], ["CC6.1"], ["SI-16"], []),
    "CWE-269": ComplianceMapping("CWE-269", "A01:2021", "API5", ["7.1", "7.2"], ["§164.312(a)(1)"], ["CC6.1", "CC6.2"], ["AC-6"], ["Art.32(1)(b)"]),
    "CWE-319": ComplianceMapping("CWE-319", "A02:2021", "", ["4.1"], ["§164.312(e)(1)"], ["CC6.1"], ["SC-8"], ["Art.32(1)(a)"]),
    "CWE-326": ComplianceMapping("CWE-326", "A02:2021", "", ["4.1", "6.5.3"], ["§164.312(a)(2)(iv)"], ["CC6.1"], ["SC-12", "SC-13"], ["Art.32(1)(a)"]),
    "CWE-843": ComplianceMapping("CWE-843", "A03:2021", "", ["6.5.2"], [], ["CC6.1"], ["SI-10"], []),
    "CWE-915": ComplianceMapping("CWE-915", "A08:2021", "API6", ["6.5.1"], [], ["CC6.1"], ["SI-10"], []),
}

# Pattern-based fallback for unmapped CWEs
_CWE_CATEGORY_PATTERNS = [
    (re.compile(r'CWE-(?:78|77|88|94|95|96|97)', re.IGNORECASE), "A03:2021", "Injection"),
    (re.compile(r'CWE-(?:79|80|81|82|83|84|85|86|87)', re.IGNORECASE), "A03:2021", "XSS"),
    (re.compile(r'CWE-(?:89|90|91|564|943)', re.IGNORECASE), "A03:2021", "Injection"),
    (re.compile(r'CWE-(?:284|285|286|287|288|289|290|291|306|307|308|862|863)', re.IGNORECASE), "A01:2021", "Access Control"),
    (re.compile(r'CWE-(?:310|311|312|319|320|321|326|327|328|329|330|331|338)', re.IGNORECASE), "A02:2021", "Crypto"),
    (re.compile(r'CWE-(?:200|201|209|215|256|260|312|319|532|538|548|615)', re.IGNORECASE), "A01:2021", "Information Disclosure"),
    (re.compile(r'CWE-(?:250|269|271|272|273|274|276|277|278|279|280|281|732)', re.IGNORECASE), "A01:2021", "Privilege"),
]


class ComplianceCVSSEngine:
    def __init__(self, ctx=None, llm_client=None):
        self.ctx = ctx
        self.llm_client = llm_client

    def map_compliance(self, cwe: str) -> ComplianceMapping:
        """Map a CWE to all compliance frameworks."""
        if cwe in _CWE_COMPLIANCE:
            return _CWE_COMPLIANCE[cwe]

        # Pattern-based fallback
        for pattern, owasp, _category in _CWE_CATEGORY_PATTERNS:
            if pattern.match(cwe):
                return ComplianceMapping(
                    cwe=cwe, owasp_top10=owasp,
                    pci_dss=["6.5.1"], nist_800_53=["SI-10"],
                )

        # Generic fallback
        return ComplianceMapping(cwe=cwe, owasp_top10="A09:2021", nist_800_53=["SI-10"])

    def calculate_cvss(self, finding: Dict[str, Any]) -> CVSSScore:
        """Auto-calculate CVSS 3.1 base score from finding attributes."""
        score = CVSSScore()

        severity = finding.get("severity", "MEDIUM").upper()
        vuln_type = finding.get("type", "").lower()
        attack_type = finding.get("attack_type", "").lower()

        # Attack Vector — almost always Network for web vulns
        score.attack_vector = "N"

        # Attack Complexity
        if any(kw in attack_type for kw in ("race", "timing", "chain")):
            score.attack_complexity = "H"
        else:
            score.attack_complexity = "L"

        # Privileges Required
        if any(kw in attack_type for kw in ("unauth", "no_auth", "anonymous")):
            score.privileges_required = "N"
        elif any(kw in vuln_type for kw in ("privilege", "escalat", "admin")):
            score.privileges_required = "L"
        else:
            score.privileges_required = "N"

        # User Interaction
        if any(kw in vuln_type for kw in ("xss", "csrf", "clickjack", "phishing")):
            score.user_interaction = "R"
        else:
            score.user_interaction = "N"

        # Scope
        if any(kw in vuln_type for kw in ("xss", "ssrf", "redirect")):
            score.scope = "C"
        else:
            score.scope = "U"

        # CIA Impact based on severity and type
        if severity == "CRITICAL":
            score.confidentiality = "H"
            score.integrity = "H"
            score.availability = "H" if "dos" in vuln_type or "race" in attack_type else "N"
        elif severity == "HIGH":
            score.confidentiality = "H"
            score.integrity = "L"
            score.availability = "N"
        elif severity == "MEDIUM":
            score.confidentiality = "L"
            score.integrity = "L"
            score.availability = "N"
        else:
            score.confidentiality = "L"
            score.integrity = "N"
            score.availability = "N"

        # Refine based on specific types
        if any(kw in vuln_type for kw in ("information", "disclosure", "exif", "leak")):
            score.confidentiality = "H" if severity in ("CRITICAL", "HIGH") else "L"
            score.integrity = "N"
        elif any(kw in vuln_type for kw in ("injection", "sqli", "rce", "command")):
            score.confidentiality = "H"
            score.integrity = "H"
            score.availability = "H"
        elif any(kw in vuln_type for kw in ("forgery", "jwt", "token")):
            score.confidentiality = "H"
            score.integrity = "H"

        # Calculate base score using CVSS 3.1 formula
        score.base_score = self._compute_base_score(score)
        score.severity_label = self._score_to_label(score.base_score)
        score.vector_string = self._build_vector_string(score)

        return score

    def _compute_base_score(self, s: CVSSScore) -> float:
        """Simplified CVSS 3.1 base score calculation."""
        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        ac_map = {"L": 0.77, "H": 0.44}
        pr_map_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_map_c = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_map = {"N": 0.85, "R": 0.62}
        cia_map = {"N": 0, "L": 0.22, "H": 0.56}

        pr_map = pr_map_c if s.scope == "C" else pr_map_u

        exploitability = 8.22 * av_map.get(s.attack_vector, 0.85) * \
                         ac_map.get(s.attack_complexity, 0.77) * \
                         pr_map.get(s.privileges_required, 0.85) * \
                         ui_map.get(s.user_interaction, 0.85)

        isc_base = 1 - (
            (1 - cia_map.get(s.confidentiality, 0)) *
            (1 - cia_map.get(s.integrity, 0)) *
            (1 - cia_map.get(s.availability, 0))
        )

        if s.scope == "U":
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

        if impact <= 0:
            return 0.0

        if s.scope == "U":
            base = min(exploitability + impact, 10)
        else:
            base = min(1.08 * (exploitability + impact), 10)

        return round(base * 10) / 10  # Round up to 1 decimal

    @staticmethod
    def _score_to_label(score: float) -> str:
        if score == 0:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        return "Critical"

    @staticmethod
    def _build_vector_string(s: CVSSScore) -> str:
        return (f"CVSS:3.1/AV:{s.attack_vector}/AC:{s.attack_complexity}/"
                f"PR:{s.privileges_required}/UI:{s.user_interaction}/S:{s.scope}/"
                f"C:{s.confidentiality}/I:{s.integrity}/A:{s.availability}")

    def enrich_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add CVSS scores and compliance mappings to all findings."""
        for finding in findings:
            cwe = finding.get("cwe", "")

            # CVSS
            cvss = self.calculate_cvss(finding)
            finding["cvss_score"] = cvss.base_score
            finding["cvss_vector"] = cvss.vector_string
            finding["cvss_severity"] = cvss.severity_label

            # Compliance
            if cwe:
                mapping = self.map_compliance(cwe)
                finding["compliance"] = {
                    "owasp_top10": mapping.owasp_top10,
                    "owasp_api": mapping.owasp_api,
                    "pci_dss": mapping.pci_dss,
                    "hipaa": mapping.hipaa,
                    "soc2": mapping.soc2,
                    "nist_800_53": mapping.nist_800_53,
                    "gdpr": mapping.gdpr,
                }

        logger.info(f"[ComplianceCVSS] Enriched {len(findings)} findings with CVSS + compliance")
        return findings

    def generate_executive_summary(self, findings: List[Dict[str, Any]], target: str = "") -> Dict[str, Any]:
        """Generate executive summary statistics."""
        total = len(findings)
        by_severity = {}
        by_compliance = {"pci_dss": 0, "hipaa": 0, "owasp_top10": 0, "gdpr": 0}
        top_findings = []
        cvss_scores = []

        for f in findings:
            sev = f.get("cvss_severity", f.get("severity", "MEDIUM"))
            by_severity[sev] = by_severity.get(sev, 0) + 1

            cvss = f.get("cvss_score", 0)
            if cvss:
                cvss_scores.append(cvss)

            compliance = f.get("compliance", {})
            if compliance.get("pci_dss"):
                by_compliance["pci_dss"] += 1
            if compliance.get("hipaa"):
                by_compliance["hipaa"] += 1
            if compliance.get("owasp_top10"):
                by_compliance["owasp_top10"] += 1
            if compliance.get("gdpr"):
                by_compliance["gdpr"] += 1

        # Sort by CVSS for top findings
        sorted_findings = sorted(findings, key=lambda f: f.get("cvss_score", 0), reverse=True)
        top_findings = [
            {"title": f.get("title", ""), "cvss": f.get("cvss_score", 0), "severity": f.get("cvss_severity", "")}
            for f in sorted_findings[:10]
        ]

        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        risk_score = min(100, int(avg_cvss * 10 + by_severity.get("Critical", 0) * 5))

        return {
            "target": target,
            "total_findings": total,
            "risk_score": risk_score,
            "by_severity": by_severity,
            "compliance_impact": by_compliance,
            "top_findings": top_findings,
            "avg_cvss": round(avg_cvss, 1),
            "max_cvss": max(cvss_scores) if cvss_scores else 0,
        }


async def enrich_and_summarize(ctx, findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Convenience function for central_brain: enrich findings + generate summary."""
    target = getattr(ctx, "target", "")
    engine = ComplianceCVSSEngine(ctx=ctx)
    enriched = engine.enrich_findings(findings)
    summary = engine.generate_executive_summary(enriched, target=target)
    return enriched, summary
