"""
LLM-Powered Finding Validator — uses the LLM to analyze each finding's
evidence and assign a confidence score before reporting.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class LLMFindingValidator:
    """Uses LLM to validate findings and assess confidence."""

    def __init__(self, max_concurrent: int = 3):
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self.validation_results: List[Dict] = []

    async def _get_llm(self):
        """Get or initialize the LLM client."""
        from agents.llm_client import LLMClient
        client = LLMClient.get()
        if client is None:
            try:
                client = LLMClient()
            except Exception:
                return None
        return client

    async def validate_finding(self, finding: Dict) -> Dict:
        """Validate a single finding using LLM analysis."""
        async with self._semaphore:
            llm = await self._get_llm()
            if not llm:
                return finding

            title = finding.get("title", "Unknown")
            vuln_type = finding.get("type", "Unknown")
            severity = finding.get("severity", "INFO")
            target = finding.get("target") or finding.get("location", "")
            details = finding.get("details", "")
            proof = finding.get("proof") or finding.get("evidence", "")
            tool = finding.get("tool", "unknown")

            prompt = f"""You are a senior penetration tester validating security findings.

Analyze this finding and assess its validity:

**Title:** {title}
**Type:** {vuln_type}
**Severity:** {severity}
**Target:** {target}
**Tool:** {tool}
**Details:** {details[:500]}
**Evidence/Proof:** {str(proof)[:800]}

Respond with ONLY a JSON object (no markdown, no explanation):
{{
  "is_valid": true/false,
  "confidence": 0.0-1.0,
  "adjusted_severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
  "reasoning": "one sentence",
  "is_false_positive": true/false,
  "fp_reason": "reason if false positive, empty otherwise"
}}

Rules for validation:
- Tool-confirmed findings (nuclei, sqlmap, nmap) with matching evidence are HIGH confidence
- Missing header findings are valid but may be LOW severity depending on context
- Findings without concrete proof/evidence should be lower confidence
- Check if the severity matches the actual impact
- Common false positives: generic info pages reported as vulns, HTTP 200 on error pages, benign headers"""

            try:
                from agents.llm_client import TaskTier
                response = await llm.generate(prompt, tier=TaskTier.SMALL)

                if not response:
                    return finding

                # Parse LLM response
                resp_text = response if isinstance(response, str) else str(response)

                # Extract JSON from response
                json_match = None
                # Try to find JSON block
                for start_char in ['{']:
                    idx = resp_text.find(start_char)
                    if idx >= 0:
                        # Find matching closing brace
                        depth = 0
                        for i in range(idx, len(resp_text)):
                            if resp_text[i] == '{':
                                depth += 1
                            elif resp_text[i] == '}':
                                depth -= 1
                                if depth == 0:
                                    json_match = resp_text[idx:i+1]
                                    break
                        break

                if not json_match:
                    return finding

                result = json.loads(json_match)

                # Apply LLM validation results
                validated = dict(finding)

                if isinstance(result.get("confidence"), (int, float)):
                    llm_conf = float(result["confidence"])
                    existing_conf = finding.get("confidence_score", 0.5)
                    if isinstance(existing_conf, (int, float)):
                        existing_conf = float(existing_conf)
                    else:
                        existing_conf = 0.5
                    # Weighted average: 60% existing (tool-based), 40% LLM
                    validated["confidence_score"] = round(existing_conf * 0.6 + llm_conf * 0.4, 2)

                if result.get("adjusted_severity") in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                    if result["adjusted_severity"] != severity:
                        validated["original_severity"] = severity
                        validated["severity"] = result["adjusted_severity"]
                        validated["severity_adjusted_by"] = "llm_validator"

                if result.get("is_false_positive"):
                    validated["status"] = "FALSE_POSITIVE"
                    validated["fp_reason"] = result.get("fp_reason", "LLM flagged as false positive")
                    validated["confidence_score"] = min(validated.get("confidence_score", 0.5), 0.2)

                if result.get("is_valid") is False and not result.get("is_false_positive"):
                    validated["status"] = "UNCONFIRMED"
                    validated["confidence_score"] = min(validated.get("confidence_score", 0.5), 0.3)

                validated["llm_validation"] = {
                    "validated": True,
                    "reasoning": result.get("reasoning", ""),
                    "raw_confidence": result.get("confidence", 0.5),
                }

                logger.info(f"[LLMValidator] {title}: confidence={validated['confidence_score']:.0%} "
                           f"severity={validated['severity']} valid={result.get('is_valid', '?')}")

                self.validation_results.append({
                    "title": title,
                    "original_severity": severity,
                    "adjusted_severity": validated.get("severity"),
                    "confidence": validated.get("confidence_score"),
                    "is_valid": result.get("is_valid"),
                    "is_false_positive": result.get("is_false_positive", False),
                })

                return validated

            except json.JSONDecodeError:
                logger.warning(f"[LLMValidator] Failed to parse LLM response for: {title}")
                return finding
            except Exception as e:
                logger.warning(f"[LLMValidator] Validation failed for {title}: {e}")
                return finding

    async def validate_findings(self, findings: List[Dict],
                                 max_findings: int = 50) -> List[Dict]:
        """Validate multiple findings concurrently."""
        if not findings:
            return findings

        # Prioritize by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            enumerate(findings),
            key=lambda x: severity_order.get((x[1].get("severity") or "INFO").upper(), 4)
        )

        to_validate = sorted_findings[:max_findings]
        skip_indices = {idx for idx, _ in sorted_findings[max_findings:]}

        tasks = []
        index_map = {}
        for i, (orig_idx, f) in enumerate(to_validate):
            tasks.append(self.validate_finding(f))
            index_map[i] = orig_idx

        validated_list = await asyncio.gather(*tasks, return_exceptions=True)

        result = list(findings)
        for i, validated in enumerate(validated_list):
            orig_idx = index_map[i]
            if isinstance(validated, Exception):
                logger.warning(f"[LLMValidator] Exception validating finding {orig_idx}: {validated}")
                continue
            if isinstance(validated, dict):
                result[orig_idx] = validated

        # Stats
        fp_count = len([r for r in self.validation_results if r.get("is_false_positive")])
        adjusted = len([r for r in self.validation_results
                        if r.get("original_severity") != r.get("adjusted_severity")])

        logger.info(f"[LLMValidator] Validated {len(self.validation_results)}/{len(findings)} findings: "
                    f"{fp_count} false positives, {adjusted} severity adjustments")

        return result

    def get_summary(self) -> Dict:
        """Get validation summary."""
        if not self.validation_results:
            return {"validated": 0}

        return {
            "validated": len(self.validation_results),
            "false_positives": len([r for r in self.validation_results if r.get("is_false_positive")]),
            "severity_adjustments": len([r for r in self.validation_results
                                         if r.get("original_severity") != r.get("adjusted_severity")]),
            "avg_confidence": round(
                sum(r.get("confidence", 0.5) for r in self.validation_results) /
                max(len(self.validation_results), 1), 2
            ),
        }
