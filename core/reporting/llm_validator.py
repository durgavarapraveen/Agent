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

            # Untrusted content (proof/evidence/details) is fenced in labeled
            # envelopes with a safety preamble. Attacker-crafted response bodies
            # cannot escape the envelope to inject validator directives.
            from core.llm.prompt_safety import guarded_prompt
            instructions = (
                "You are a senior penetration tester validating security findings.\n\n"
                "Analyze the finding metadata (below) and the untrusted evidence "
                "sections. Respond with ONLY a JSON object (no markdown, no "
                "explanation):\n"
                "{\n"
                '  "is_valid": true/false,\n'
                '  "confidence": 0.0-1.0,\n'
                '  "adjusted_severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",\n'
                '  "reasoning": "one sentence",\n'
                '  "is_false_positive": true/false,\n'
                '  "fp_reason": "reason if false positive, empty otherwise"\n'
                "}\n\n"
                "Rules for validation:\n"
                "- Tool-confirmed findings (nuclei, sqlmap, nmap) with matching "
                "evidence are HIGH confidence.\n"
                "- Missing-header findings are valid but may be LOW severity "
                "depending on context.\n"
                "- Findings without concrete proof/evidence should be lower "
                "confidence.\n"
                "- Check if the severity matches the actual impact.\n"
                "- Common false positives: generic info pages reported as vulns, "
                "HTTP 200 on error pages, benign headers.\n\n"
                f"Finding metadata (trusted):\n"
                f"  title    = {title!r}\n"
                f"  type     = {vuln_type!r}\n"
                f"  severity = {severity!r}\n"
                f"  target   = {target!r}\n"
                f"  tool     = {tool!r}"
            )
            prompt = guarded_prompt(instructions, [
                ("details", str(details)[:500]),
                ("evidence", str(proof)[:800]),
            ])

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
                    # Never drop tool-confirmed findings — the LLM is less
                    # authoritative than an actual scanner/exploit that produced proof.
                    _tool_confirmed = bool(
                        finding.get("exploited") or finding.get("confirmed")
                        or finding.get("proof") or finding.get("evidence")
                        or str(finding.get("tool") or "").lower() in
                        ("sqlmap", "nuclei", "nikto", "sslscan", "nmap", "dalfox",
                         "ffuf", "gobuster", "profiler", "exploit_agent")
                        or str(finding.get("type") or "").upper() in
                        ("SQL_INJECTION", "SQLI", "NUCLEI_MATCH", "XSS",
                         "COMMAND_INJECTION", "RCE", "SSRF", "XXE", "PATH_TRAVERSAL")
                    )
                    if _tool_confirmed:
                        validated["llm_fp_overridden"] = True
                        validated["fp_reason"] = result.get("fp_reason", "")
                        logger.info(f"[LLMValidator] Overriding FP for tool-confirmed: {title}")
                    else:
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

    async def _validate_batch(self, batch: List) -> List[Dict]:
        """Validate up to N findings in ONE LLM call. Returns a list of verdict
        dicts aligned with the input batch."""
        async with self._semaphore:
            llm = await self._get_llm()
            if not llm:
                return [None] * len(batch)
            lines = []
            for i, (_, f) in enumerate(batch):
                lines.append(
                    f"[{i}] title={f.get('title','')!r} sev={f.get('severity','INFO')} "
                    f"type={f.get('type','')} tool={f.get('tool','')} "
                    f"loc={(f.get('location') or f.get('target',''))[:80]!r} "
                    f"proof={str(f.get('proof') or f.get('evidence',''))[:200]!r}")
            prompt = (
                "You are a senior pentester. For EACH finding below, return a JSON "
                "object in a single array. Order MUST match input order.\n"
                "Schema: [{\"i\":<index>, \"is_valid\":bool, \"confidence\":0-1, "
                "\"adjusted_severity\":\"CRITICAL|HIGH|MEDIUM|LOW|INFO\", "
                "\"is_false_positive\":bool, \"reasoning\":\"<one sentence>\"}]\n\n"
                "FINDINGS:\n" + "\n".join(lines) + "\n\nReturn ONLY the JSON array."
            )
            try:
                from agents.llm_client import TaskTier
                resp = await llm.generate(prompt, tier=TaskTier.SMALL)
                text = resp if isinstance(resp, str) else str(resp)
                import re, json as _json
                m = re.search(r"\[[\s\S]*\]", text)
                if not m:
                    return [None] * len(batch)
                arr = _json.loads(m.group(0))
                by_i = {int(item.get("i", -1)): item for item in arr if isinstance(item, dict)}
                return [by_i.get(i) for i in range(len(batch))]
            except Exception:
                return [None] * len(batch)

    async def validate_findings(self, findings: List[Dict],
                                 max_findings: int = 50,
                                 batch_size: int = 10) -> List[Dict]:
        """Validate findings via BATCHED LLM calls (10 findings per prompt).

        Token-savings changes vs previous 1-per-call design:
          1. Skip already-tool-confirmed findings (nuclei/sqlmap/nmap/dalfox/
             nikto with `confirmed=True` or `source` in tool set) — the tool
             evidence IS the validation, extra LLM check is wasteful.
          2. Batch remaining findings into groups of 10 per prompt so the
             ~500-token instruction preamble is amortised across a batch.
          3. Skip INFO severity by default — they're context, not exploits.
        """
        if not findings:
            return findings

        TOOL_CONFIRMED_SOURCES = {"nuclei", "sqlmap", "nmap", "dalfox", "nikto",
                                    "wpscan", "sslscan", "sqlmap_dump",
                                    "cross_role_replay", "semantic_api_fuzzer",
                                    "expert_probes", "dom_sink_monitor",
                                    "graphql_ws_probe", "request_replayer"}
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        result = list(findings)

        # Bucket 1: skip validation for tool-confirmed / INFO findings
        needs_validation: List = []
        for orig_idx, f in enumerate(findings):
            sev = (f.get("severity") or "INFO").upper()
            source = str(f.get("source") or f.get("tool") or "").lower()
            is_tool_confirmed = (f.get("confirmed") is True) or any(
                s in source for s in TOOL_CONFIRMED_SOURCES)
            if is_tool_confirmed or sev == "INFO":
                # Mark as trusted so downstream code doesn't re-flag it
                f.setdefault("_llm_validation", {"is_valid": True,
                    "confidence": 0.9 if is_tool_confirmed else 0.5,
                    "reasoning": "tool-confirmed; LLM validation skipped"
                                    if is_tool_confirmed else "info severity — no validation"})
                continue
            needs_validation.append((orig_idx, f))

        # Prioritise by severity + cap
        needs_validation.sort(key=lambda x: severity_order.get(
            (x[1].get("severity") or "INFO").upper(), 4))
        needs_validation = needs_validation[:max_findings]

        if not needs_validation:
            return result

        # Bucket 2: batch what's left
        batches = [needs_validation[i:i + batch_size]
                    for i in range(0, len(needs_validation), batch_size)]
        tasks = [self._validate_batch(b) for b in batches]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        # Flatten batch results and re-map to indices
        validated_list = []
        index_map = {}
        i = 0
        for b_idx, br in enumerate(batch_results):
            batch_items = batches[b_idx]
            if isinstance(br, Exception) or not br:
                for orig_idx, f in batch_items:
                    validated_list.append(f)
                    index_map[i] = orig_idx
                    i += 1
                continue
            for (orig_idx, f), verdict in zip(batch_items, br):
                if isinstance(verdict, dict):
                    fcopy = dict(f)
                    fcopy["_llm_validation"] = verdict
                    validated_list.append(fcopy)
                else:
                    validated_list.append(f)
                index_map[i] = orig_idx
                i += 1

        # Merge validated copies back into the result list
        for i, validated in enumerate(validated_list):
            orig_idx = index_map[i]
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
