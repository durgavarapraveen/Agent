"""
Phase 5 Module 5.2: Risk Prioritization Engine (core/risk_prioritizer.py)

Computes exploitability scores, business impact multipliers, combined risk scores (0–10 scale),
groups findings into risk tiers, and generates ordered remediation roadmaps.
"""

import logging
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


def compute_exploitability_score(finding: Dict[str, Any]) -> float:
    """
    Compute exploitability score (0–100):
      - public_exploit_available -> +40 points
      - easy_to_chain -> +30 points
      - no_authentication_required -> +20 points
      - complex_attack_vector -> -10 points
    Cap between [0, 100].
    """
    score = 0.0

    # Public exploit check
    if (finding.get("public_exploit_available") or finding.get("has_exploit") or 
            finding.get("public_exploit") or "exploit" in str(finding.get("details", "")).lower()):
        score += 40.0

    # Chaining check
    if finding.get("easy_to_chain") or finding.get("is_chainable") or finding.get("chainable"):
        score += 30.0

    # Auth check (default True for critical/high web vulns unless explicitly marked auth_required)
    no_auth = finding.get("no_authentication_required")
    if no_auth is None:
        # Default unauthenticated if not specified
        no_auth = not bool(finding.get("auth_required") or finding.get("requires_auth"))
    if no_auth:
        score += 20.0

    # Vector complexity
    if finding.get("complex_attack_vector") or finding.get("complex_vector"):
        score -= 10.0

    # Base minimum if finding is validated
    if score == 0.0 and finding.get("severity"):
        score = 20.0

    return max(0.0, min(100.0, score))


def compute_business_impact(finding: Dict[str, Any], config_path: str = "data/business_impact_config.yaml") -> float:
    """
    Read business_impact_config.yaml and compute normalized impact score (0–1 scale).
    Formula: max(impact_multipliers) / 10.0
    """
    path = Path(config_path)
    multipliers = {
        "data_exposed": 10,
        "service_disruption": 7,
        "information_disclosure": 5,
        "reputation_damage": 8,
    }
    vuln_map = {
        "SQLI": ["data_exposed", "reputation_damage"],
        "RCE": ["service_disruption", "data_exposed"],
        "XSS": ["reputation_damage", "information_disclosure"],
        "LFI": ["information_disclosure", "data_exposed"],
        "INFO_DISCLOSURE": ["information_disclosure"],
        "MISCONFIGURATION": ["service_disruption"],
        "DOS": ["service_disruption"],
    }

    if path.exists():
        try:
            import yaml
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                if "impact_multipliers" in data:
                    multipliers.update(data["impact_multipliers"])
                if "vulnerability_impact_map" in data:
                    vuln_map.update(data["vulnerability_impact_map"])
        except Exception as e:
            logger.warning(f"[RiskPrioritizer] YAML load fallback: {e}")

    vuln_type = str(finding.get("type") or finding.get("title") or "MISCONFIGURATION").upper()
    
    # Identify matching categories
    matched_categories = []
    for key, categories in vuln_map.items():
        if key in vuln_type or vuln_type in key:
            matched_categories.extend(categories)

    if not matched_categories:
        # Default mapping based on severity
        sev = str(finding.get("severity", "MEDIUM")).upper()
        if sev == "CRITICAL":
            matched_categories = ["data_exposed", "service_disruption"]
        elif sev == "HIGH":
            matched_categories = ["reputation_damage"]
        else:
            matched_categories = ["information_disclosure"]

    matched_mults = [multipliers.get(cat, 5) for cat in matched_categories]
    max_mult = max(matched_mults) if matched_mults else 5.0
    return max(0.1, min(1.0, float(max_mult) / 10.0))


class RiskPrioritizer:
    """Prioritizes findings based on exploitability, CVSS, and business impact."""

    def __init__(self, config_path: str = "data/business_impact_config.yaml"):
        self.config_path = config_path

    def calculate_risk_score(self, finding: Dict[str, Any]) -> float:
        """
        Calculate combined risk score:
          final_risk_score = (CVSS_base_score / 10) * (exploitability_score / 100) * business_impact * 10
        Capped at [0.0, 10.0].
        """
        # Determine CVSS base score (default based on severity if cvss not provided)
        cvss = finding.get("cvss") or finding.get("cvss_score") or finding.get("cvss_base_score")
        if cvss is None:
            sev = str(finding.get("severity", "MEDIUM")).upper()
            cvss_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 1.0}
            cvss = cvss_map.get(sev, 5.0)
        else:
            cvss = float(cvss)

        exploitability = compute_exploitability_score(finding)
        business_impact = compute_business_impact(finding, self.config_path)

        score = (cvss / 10.0) * (exploitability / 100.0) * business_impact * 10.0
        return round(max(0.0, min(10.0, score)), 1)

    def prioritize_findings(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich all findings with exploitability, business impact, and risk_score,
        and return sorted descending by risk_score.
        """
        enriched = []
        for v in vulnerabilities:
            item = dict(v)
            item["exploitability_score"] = compute_exploitability_score(item)
            item["business_impact"] = compute_business_impact(item, self.config_path)
            item["risk_score"] = self.calculate_risk_score(item)
            enriched.append(item)

        return sorted(enriched, key=lambda x: x["risk_score"], reverse=True)

    def group_by_risk_tiers(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group findings into risk tiers:
          CRITICAL_RISK: score >= 8.0
          HIGH_RISK: score 5.0 – 7.9
          MEDIUM_RISK: score 3.0 – 4.9
          LOW_RISK: score < 3.0
        """
        prioritized = self.prioritize_findings(vulnerabilities)
        tiers = {
            "CRITICAL_RISK": [],
            "HIGH_RISK": [],
            "MEDIUM_RISK": [],
            "LOW_RISK": []
        }

        for item in prioritized:
            score = item["risk_score"]
            if score >= 8.0:
                tiers["CRITICAL_RISK"].append(item)
            elif score >= 5.0:
                tiers["HIGH_RISK"].append(item)
            elif score >= 3.0:
                tiers["MEDIUM_RISK"].append(item)
            else:
                tiers["LOW_RISK"].append(item)

        return tiers

    def generate_prioritized_roadmap(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """
        Generate an ordered action list roadmap:
        e.g., "1. Fix CVE-2023-12345 (9.2/10) - Update Apache to 2.4.49"
        """
        prioritized = self.prioritize_findings(vulnerabilities)
        roadmap = []

        for idx, item in enumerate(prioritized, 1):
            cve_id = item.get("cve") or item.get("cve_id") or item.get("id") or f"VULN-{idx:03d}"
            title = item.get("title") or item.get("type") or "Security Finding"
            score = item["risk_score"]
            remediation = item.get("remediation") or item.get("solution") or "Apply latest vendor patch"

            entry = f"{idx}. Fix {cve_id} ({score}/10) - {remediation}"
            roadmap.append(entry)

        return roadmap
