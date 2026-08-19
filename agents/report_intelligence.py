"""
Report Intelligence Layer
Uses LLM to enrich reports:
  - LARGE model: Executive summary, risk narrative, prioritization
  - SMALL model: Finding categorization, remediation extraction
"""

import json
import logging
from typing import List, Dict, Any

from agents.llm_client import LLMClient, TaskTier, llm_extract, llm_analyze

logger = logging.getLogger(__name__)


class ReportIntelligence:
    """LLM-powered enrichment for security reports"""

    def __init__(self):
        self.client = LLMClient.get()

    async def is_available(self) -> bool:
        return await self.client.is_available()

    async def generate_executive_summary(
        self, target: str, findings: List[Dict], discoveries: List[Dict]
    ) -> str:
        """LARGE model: Write a narrative executive summary"""

        if not await self.is_available():
            return self._fallback_summary(target, findings)

        # Compact findings for LLM
        finding_summary = "\n".join([
            f"- [{f.get('severity', 'INFO')}] {f.get('title', '')}: {f.get('description', '')[:150]}"
            for f in findings[:20]
        ])

        discovery_summary = "\n".join([
            f"- {d.get('type', 'unknown')}: {json.dumps({k: v for k, v in d.items() if k != 'type'})[:200]}"
            for d in discoveries[:15]
        ])

        prompt = f"""You are a senior security consultant writing an executive summary for a penetration test report.

Target: {target}

Findings ({len(findings)} total):
{finding_summary}

Discoveries:
{discovery_summary}

Write a 3-paragraph executive summary:
1. Overall security posture assessment (1 paragraph)
2. Most critical concerns and business impact (1 paragraph)
3. Recommended priorities (1 paragraph)

Be concise, professional, and specific to the findings. Avoid generic advice."""

        summary = await self.client.generate(
            prompt, tier=TaskTier.LARGE, max_tokens=800, temperature=0.4
        )
        return summary or self._fallback_summary(target, findings)

    async def prioritize_findings(self, findings: List[Dict]) -> List[Dict]:
        """LARGE model: Re-rank findings by real-world exploitability"""

        if not await self.is_available() or len(findings) == 0:
            return findings

        finding_json = json.dumps([
            {"id": i, "title": f.get("title"), "severity": f.get("severity"),
             "description": f.get("description", "")[:200]}
            for i, f in enumerate(findings[:30])
        ])

        prompt = f"""Analyze these security findings and rank them by real-world exploitability and business impact.

Findings:
{finding_json}

For each finding, provide a priority score 1-10 (10=highest priority) and 1-line justification.
Return JSON: {{"rankings": [{{"id": 0, "priority": 8, "reason": "..."}}, ...]}}"""

        result = await self.client.generate_json(prompt, tier=TaskTier.LARGE, max_tokens=2000)

        rankings = {r["id"]: r for r in result.get("rankings", []) if "id" in r}

        # Attach priority to original findings
        for i, f in enumerate(findings):
            if i in rankings:
                f["llm_priority"] = rankings[i].get("priority", 5)
                f["llm_reason"] = rankings[i].get("reason", "")

        # Sort by LLM priority
        findings.sort(key=lambda x: x.get("llm_priority", 5), reverse=True)
        return findings

    async def suggest_remediation(self, finding: Dict) -> str:
        """SMALL model: Generate specific remediation for a finding"""

        if not await self.is_available():
            return finding.get("remediation", "Investigate finding and implement appropriate controls")

        prompt = f"""Provide specific, actionable remediation steps for this security finding.
Be concrete - give exact code, config, or commands where possible.
Keep it under 3 sentences.

Finding: {finding.get('title')}
Description: {finding.get('description', '')}
Category: {finding.get('category', '')}"""

        remediation = await self.client.generate(
            prompt, tier=TaskTier.SMALL, max_tokens=300, temperature=0.3
        )
        return remediation.strip() if remediation else "Investigate and remediate"

    async def categorize_findings(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """SMALL model: Group findings into attack categories"""

        if not await self.is_available():
            return self._fallback_categorize(findings)

        titles = [f.get("title", "") for f in findings[:40]]

        prompt = f"""Group these security findings into attack categories.
Categories: authentication, injection, information_disclosure, misconfiguration,
crypto, access_control, dos, business_logic, other.

Findings:
{json.dumps([{"i": i, "title": t} for i, t in enumerate(titles)])}

Return JSON: {{"categorization": [{{"i": 0, "category": "misconfiguration"}}, ...]}}"""

        result = await self.client.generate_json(prompt, tier=TaskTier.SMALL, max_tokens=1500)

        grouped: Dict[str, List[Dict]] = {}
        for item in result.get("categorization", []):
            idx = item.get("i")
            cat = item.get("category", "other")
            if idx is not None and 0 <= idx < len(findings):
                grouped.setdefault(cat, []).append(findings[idx])

        return grouped if grouped else self._fallback_categorize(findings)

    async def analyze_endpoints(self, endpoints: List[str], base_url: str) -> Dict:
        """SMALL model: Analyze discovered endpoints for interesting patterns"""

        if not await self.is_available() or not endpoints:
            return {"interesting": [], "categories": {}}

        prompt = f"""Analyze these API endpoints discovered on {base_url}.
Identify which are most interesting from a security perspective (admin, auth, upload, debug, etc).

Endpoints:
{json.dumps(endpoints[:50])}

Return JSON:
{{
  "interesting": [{{"endpoint": "/admin", "reason": "admin interface", "risk": "high"}}],
  "categories": {{"admin": ["/admin"], "auth": ["/login"], "upload": ["/upload"]}}
}}"""

        return await self.client.generate_json(prompt, tier=TaskTier.SMALL, max_tokens=1500)

    def _fallback_summary(self, target: str, findings: List[Dict]) -> str:
        counts = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

        parts = [f"Security assessment of {target} identified {len(findings)} total findings."]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts.get(sev):
                parts.append(f"{counts[sev]} {sev.lower()} severity findings identified.")
        if not findings:
            parts.append("No significant security issues were detected during this assessment.")
        return " ".join(parts)

    def _fallback_categorize(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        grouped = {}
        for f in findings:
            cat = f.get("category", "other")
            grouped.setdefault(cat, []).append(f)
        return grouped