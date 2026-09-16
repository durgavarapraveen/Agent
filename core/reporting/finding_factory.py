"""Generic Finding Factory — LLM-enriched vulnerability finding generation.

All modules produce raw evidence; this factory enriches with CWE, remediation,
severity, and CVSS from LLM analysis instead of hardcoded values.
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

ENRICHMENT_PROMPT = """You are a vulnerability classification expert. Given this raw finding from an automated security scan, produce a structured classification.

## Raw Finding
- **Attack Type**: {attack_type}
- **Description**: {description}
- **Evidence**: {evidence}
- **Target**: {target}
- **Location**: {location}

Respond as JSON only:
{{
  "cwe_id": "CWE-XXX (most specific CWE that matches)",
  "cwe_name": "Name of the CWE",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence_adjustment": 0.0 to 1.0,
  "remediation": "Specific remediation steps for this exact finding",
  "owasp_category": "OWASP Top 10 category if applicable",
  "attack_class": "Broader attack classification",
  "cvss_vector_hint": "Suggested CVSS 3.1 base vector string"
}}

Rules:
- Pick the MOST SPECIFIC CWE, not a generic parent.
- Remediation must be actionable and specific to the evidence, not generic advice.
- Severity must reflect actual exploitability based on the evidence.
- If evidence is weak/partial, lower severity and confidence."""

BATCH_ENRICHMENT_PROMPT = """You are a vulnerability classification expert. Classify these {count} raw findings.

{findings_text}

For EACH finding, respond with its index and classification as a JSON array:
[
  {{
    "index": 0,
    "cwe_id": "CWE-XXX",
    "cwe_name": "...",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "confidence_adjustment": 0.0 to 1.0,
    "remediation": "...",
    "owasp_category": "...",
    "attack_class": "..."
  }},
  ...
]

Rules:
- Pick the MOST SPECIFIC CWE for each.
- Remediation must be actionable, not generic.
- Severity must match actual exploitability from evidence."""


class FindingFactory:
    """Produces enriched vulnerability findings from raw detection evidence."""

    def __init__(self, llm_client=None):
        self._llm = llm_client

    async def _get_llm(self):
        if self._llm:
            return self._llm
        from agents.universal_llm_harness import get_llm_client
        self._llm = get_llm_client()
        return self._llm

    def create_raw(self, *,
                   attack_type: str,
                   description: str,
                   evidence: str,
                   target: str,
                   location: str = "",
                   source: str = "",
                   tool: str = "",
                   status: str = "confirmed",
                   extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create a raw finding without enrichment (for immediate use)."""
        finding = {
            "finding_id": str(uuid.uuid4()),
            "title": "",
            "type": attack_type,
            "description": description,
            "severity": "MEDIUM",
            "confidence_score": 0.5,
            "target": target,
            "location": location or target,
            "evidence": evidence[:2000],
            "cwe": "",
            "source": source,
            "tool": tool,
            "attack_type": attack_type,
            "status": status,
            "remediation": "",
        }
        if extra:
            finding.update(extra)
        finding["title"] = finding.get("title") or f"{attack_type}: {location or target}"
        return finding

    async def create_enriched(self, *,
                               attack_type: str,
                               description: str,
                               evidence: str,
                               target: str,
                               location: str = "",
                               source: str = "",
                               tool: str = "",
                               status: str = "confirmed",
                               extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create a finding enriched with LLM-derived CWE, severity, remediation."""
        finding = self.create_raw(
            attack_type=attack_type, description=description, evidence=evidence,
            target=target, location=location, source=source, tool=tool,
            status=status, extra=extra,
        )

        enrichment = await self._enrich_single(finding)
        if enrichment:
            self._apply_enrichment(finding, enrichment)

        return finding

    async def enrich_batch(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich multiple raw findings in a single LLM call (cheaper)."""
        if not findings:
            return findings

        if len(findings) == 1:
            enrichment = await self._enrich_single(findings[0])
            if enrichment:
                self._apply_enrichment(findings[0], enrichment)
            return findings

        # Batch up to 10 at a time
        for batch_start in range(0, len(findings), 10):
            batch = findings[batch_start:batch_start + 10]
            enrichments = await self._enrich_batch(batch)
            for i, enrichment in enumerate(enrichments):
                if enrichment and batch_start + i < len(findings):
                    self._apply_enrichment(findings[batch_start + i], enrichment)

        return findings

    async def _enrich_single(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Call LLM to classify a single finding."""
        try:
            llm = await self._get_llm()
            from core.llm.task_tier import TaskTier
            prompt = ENRICHMENT_PROMPT.format(
                attack_type=finding.get("attack_type", finding.get("type", "")),
                description=finding.get("description", ""),
                evidence=finding.get("evidence", "")[:1000],
                target=finding.get("target", ""),
                location=finding.get("location", ""),
            )
            resp = await llm.generate(
                messages=[{"role": "user", "content": prompt}],
                tier=TaskTier.SMALL,
                temperature=0.1,
            )
            return self._parse_json(resp.content)
        except Exception as e:
            logger.debug(f"[FindingFactory] Enrichment failed: {e}")
            return None

    async def _enrich_batch(self, batch: List[Dict[str, Any]]) -> List[Optional[Dict[str, Any]]]:
        """Call LLM to classify a batch of findings."""
        results: List[Optional[Dict[str, Any]]] = [None] * len(batch)
        try:
            llm = await self._get_llm()
            from core.llm.task_tier import TaskTier

            findings_text = ""
            for i, f in enumerate(batch):
                findings_text += (
                    f"\n### Finding {i}\n"
                    f"- Attack: {f.get('attack_type', f.get('type', ''))}\n"
                    f"- Description: {f.get('description', '')[:200]}\n"
                    f"- Evidence: {f.get('evidence', '')[:300]}\n"
                    f"- Target: {f.get('target', '')}\n"
                    f"- Location: {f.get('location', '')}\n"
                )

            prompt = BATCH_ENRICHMENT_PROMPT.format(
                count=len(batch), findings_text=findings_text,
            )
            resp = await llm.generate(
                messages=[{"role": "user", "content": prompt}],
                tier=TaskTier.MEDIUM,
                temperature=0.1,
            )
            parsed = self._parse_json(resp.content)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict) and "index" in item:
                        idx = item["index"]
                        if 0 <= idx < len(results):
                            results[idx] = item
            elif isinstance(parsed, dict) and "index" in parsed:
                idx = parsed["index"]
                if 0 <= idx < len(results):
                    results[idx] = parsed
        except Exception as e:
            logger.debug(f"[FindingFactory] Batch enrichment failed: {e}")

        return results

    @staticmethod
    def _apply_enrichment(finding: Dict[str, Any], enrichment: Dict[str, Any]) -> None:
        """Merge LLM enrichment into a finding."""
        if enrichment.get("cwe_id"):
            finding["cwe"] = enrichment["cwe_id"]
        if enrichment.get("cwe_name"):
            finding["cwe_name"] = enrichment["cwe_name"]
        if enrichment.get("severity"):
            finding["severity"] = enrichment["severity"].upper()
        if enrichment.get("remediation"):
            finding["remediation"] = enrichment["remediation"]
        if enrichment.get("owasp_category"):
            finding["owasp_category"] = enrichment["owasp_category"]
        if enrichment.get("attack_class"):
            finding["attack_class"] = enrichment["attack_class"]
        if enrichment.get("confidence_adjustment") is not None:
            try:
                adj = float(enrichment["confidence_adjustment"])
                if 0.0 <= adj <= 1.0:
                    finding["confidence_score"] = adj
            except (ValueError, TypeError):
                pass
        if enrichment.get("cvss_vector_hint"):
            finding["cvss_vector_hint"] = enrichment["cvss_vector_hint"]
        # Update title with CWE if available
        if finding.get("cwe") and finding["cwe"] not in finding.get("title", ""):
            finding["title"] = f"[{finding['cwe']}] {finding.get('title', '')}"

    @staticmethod
    def _parse_json(raw: str) -> Any:
        """Extract JSON from LLM response."""
        text = raw
        if "```json" in raw:
            text = raw.split("```json")[1].split("```")[0]
        elif "```" in raw:
            text = raw.split("```")[1].split("```")[0]
        try:
            return json.loads(text)
        except (json.JSONDecodeError, IndexError):
            return None


# Module-level singleton for reuse
_factory: Optional[FindingFactory] = None


def get_finding_factory(llm_client=None) -> FindingFactory:
    global _factory
    if _factory is None:
        _factory = FindingFactory(llm_client=llm_client)
    return _factory
