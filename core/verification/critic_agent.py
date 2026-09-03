"""
CriticAgent — adversarial finding verifier (Planner–Worker–Critic loop).

The Worker layer (scanners, exploit agent, injection matrix) produces candidate
findings. The RetestEngine mechanically re-probes them. The CriticAgent adds a
*semantic* second opinion: an LLM is instructed to argue AGAINST each finding and
enumerate concrete false-positive scenarios, then deliver a verdict. Findings that
both the retest layer and the critic reject are quarantined instead of reported,
which autonomously drives down the false-positive rate without a human in the loop.

Design goals:
  - Never silently drop a finding. A rejected finding is tagged and downgraded so
    it stays auditable in the report.
  - Cost-aware: strong tool-confirmed evidence short-circuits the LLM call.
  - Fail-open: if the LLM is unavailable or returns garbage, the verdict is
    UNCERTAIN and the finding is preserved unchanged.
  - Concurrency-bounded so a large finding set does not stampede the provider.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"          # critic agrees this is a real, exploitable/valid finding
    FALSE_POSITIVE = "FALSE_POSITIVE"  # critic argues it is not a real vulnerability
    UNCERTAIN = "UNCERTAIN"          # insufficient evidence to decide either way


@dataclass
class CriticVerdict:
    verdict: Verdict
    confidence: float                # 0.0–1.0 the critic assigns to its own verdict
    reasoning: str = ""
    false_positive_scenarios: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    model: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "confidence": round(float(self.confidence), 3),
            "reasoning": self.reasoning,
            "false_positive_scenarios": self.false_positive_scenarios,
            "missing_evidence": self.missing_evidence,
            "model": self.model,
        }


# Finding types whose presence is established by the tool itself with concrete
# evidence — the critic still reviews these but with a lower bar to confirm.
_STRONG_TOOL_TYPES = {
    "NUCLEI_MATCH", "SQL_INJECTION", "SQLI", "XSS", "COMMAND_INJECTION",
    "RCE", "SSRF", "XXE", "PATH_TRAVERSAL", "FILE_DISCLOSURE",
}

# Low-signal informational types that are the most common false positives.
_NOISE_PRONE_TYPES = {
    "MISSING_HEADER", "TLS_WEAKNESS", "INFO_DISCLOSURE", "NIKTO_FINDING",
    "DIRECTORY_LISTING", "COOKIE_FLAG", "VERSION_DISCLOSURE",
}

_SYSTEM_PROMPT = (
    "You are a skeptical senior penetration-test reviewer performing quality control. "
    "Your job is to challenge a candidate security finding and decide whether it is a "
    "genuine vulnerability or a false positive. Assume the scanner may be wrong. "
    "Weigh only the concrete evidence provided. Reflected input that is not executed, "
    "generic error pages, headers set at a CDN/edge, default banners, and 200-status "
    "responses without a working payload are NOT vulnerabilities. "
    "Respond ONLY with a JSON object."
)


class CriticAgent:
    """Adversarial LLM verifier for candidate findings."""

    def __init__(
        self,
        llm_client: Optional[Any] = None,
        max_concurrency: int = 4,
        confirm_threshold: float = 0.6,
        reject_threshold: float = 0.6,
        max_tokens: int = 900,
    ):
        """
        Args:
            llm_client: object exposing async generate_json_with_retry(...).
                        Defaults to the shared LLMClient proxy.
            max_concurrency: parallel LLM verifications.
            confirm_threshold: min critic confidence to accept a CONFIRMED verdict.
            reject_threshold: min critic confidence to act on a FALSE_POSITIVE verdict.
        """
        self._llm = llm_client
        self._sem = asyncio.Semaphore(max(1, max_concurrency))
        self.confirm_threshold = confirm_threshold
        self.reject_threshold = reject_threshold
        self.max_tokens = max_tokens

    # ------------------------------------------------------------------ LLM

    def _get_llm(self):
        if self._llm is not None:
            return self._llm
        # Lazy import to avoid a hard dependency at module import time.
        from agents.llm_client import LLMClient
        self._llm = LLMClient.get()
        return self._llm

    # ------------------------------------------------------------- prompting

    @staticmethod
    def _summarize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extract a compact, evidence-focused view of the finding for the prompt."""
        evidence = finding.get("evidence") or finding.get("proof") or {}
        if isinstance(evidence, dict):
            evidence_str = json.dumps(evidence, default=str)[:1200]
        else:
            evidence_str = str(evidence)[:1200]

        return {
            "type": finding.get("type") or finding.get("vuln_type") or "UNKNOWN",
            "title": finding.get("title") or "",
            "severity": finding.get("severity") or "",
            "location": finding.get("location") or finding.get("url")
            or finding.get("affected_endpoint") or finding.get("target") or "",
            "method": finding.get("method") or "",
            "payload": str(finding.get("payload") or finding.get("post_data") or "")[:500],
            "matched_indicator": finding.get("tracer_used") or finding.get("matched_error") or "",
            "status_code": finding.get("status_code") or finding.get("expected_status") or "",
            "source": finding.get("source") or "",
            "tool_confirmed": bool(finding.get("confirmed") or finding.get("exploited")),
            "description": str(finding.get("description") or "")[:600],
            "evidence": evidence_str,
        }

    def _build_prompt(self, finding: Dict[str, Any]) -> str:
        summary = self._summarize_finding(finding)
        return (
            "Review this candidate security finding and decide if it is real.\n\n"
            f"FINDING:\n{json.dumps(summary, indent=2, default=str)}\n\n"
            "Argue against the finding first: list every plausible reason it could be a "
            "false positive given ONLY the evidence above. Then decide.\n\n"
            "Return JSON exactly in this shape:\n"
            "{\n"
            '  "verdict": "CONFIRMED" | "FALSE_POSITIVE" | "UNCERTAIN",\n'
            '  "confidence": 0.0-1.0,\n'
            '  "reasoning": "one or two sentences",\n'
            '  "false_positive_scenarios": ["..."],\n'
            '  "missing_evidence": ["what evidence would make this conclusive"]\n'
            "}\n"
            "Rules: choose FALSE_POSITIVE only if the evidence is genuinely insufficient "
            "or contradicts a real vulnerability. Choose UNCERTAIN when you cannot tell. "
            "confidence is how sure you are of your own verdict."
        )

    # ------------------------------------------------------------- verify one

    async def verify_finding(self, finding: Dict[str, Any]) -> CriticVerdict:
        """Return the critic's verdict for a single finding. Never raises."""
        ftype = str(finding.get("type") or finding.get("vuln_type") or "").upper()

        # Cost short-circuit: exploit agent already proved it with live evidence.
        if finding.get("exploited") and finding.get("evidence") and ftype in _STRONG_TOOL_TYPES:
            return CriticVerdict(
                verdict=Verdict.CONFIRMED, confidence=0.9,
                reasoning="Exploit agent produced live proof for a strong-signal finding.",
                model="heuristic",
            )

        prompt = self._build_prompt(finding)
        llm = self._get_llm()

        try:
            async with self._sem:
                data, raw = await llm.generate_json_with_retry(
                    prompt,
                    system=_SYSTEM_PROMPT,
                    max_tokens=self.max_tokens,
                    mandatory_fields=["verdict"],
                    max_retries=2,
                )
        except Exception as e:  # noqa: BLE001 — fail-open by design
            logger.warning(f"[Critic] LLM verification error for '{finding.get('title')}': {e}")
            return CriticVerdict(Verdict.UNCERTAIN, 0.0, reasoning=f"LLM error: {e}")

        if not data:
            return CriticVerdict(Verdict.UNCERTAIN, 0.0, reasoning="Empty LLM response")

        return self._parse_verdict(data)

    @staticmethod
    def _parse_verdict(data: Dict[str, Any]) -> CriticVerdict:
        raw_verdict = str(data.get("verdict", "")).strip().upper()
        try:
            verdict = Verdict(raw_verdict)
        except ValueError:
            # Tolerate near-miss labels.
            if "FALSE" in raw_verdict or raw_verdict in ("FP", "REJECT", "REJECTED"):
                verdict = Verdict.FALSE_POSITIVE
            elif "CONFIRM" in raw_verdict or raw_verdict in ("TRUE", "REAL", "VALID"):
                verdict = Verdict.CONFIRMED
            else:
                verdict = Verdict.UNCERTAIN

        try:
            conf = float(data.get("confidence", 0.5))
        except (TypeError, ValueError):
            conf = 0.5
        conf = max(0.0, min(1.0, conf))

        def _as_list(v):
            if isinstance(v, list):
                return [str(x) for x in v][:8]
            if v:
                return [str(v)]
            return []

        return CriticVerdict(
            verdict=verdict,
            confidence=conf,
            reasoning=str(data.get("reasoning", ""))[:600],
            false_positive_scenarios=_as_list(data.get("false_positive_scenarios")),
            missing_evidence=_as_list(data.get("missing_evidence")),
            model=str(data.get("model", "llm")),
        )

    # ------------------------------------------------------------ verify many

    async def verify_findings(
        self, findings: List[Dict[str, Any]], quarantine: bool = True
    ) -> Dict[str, Any]:
        """
        Verify a batch of findings concurrently and annotate each in place.

        Each finding gains:
          - finding["critic"] : the verdict dict
          - finding["confidence_score"] : nudged up/down by the verdict
          - finding["status"] : set to "QUARANTINED" when confidently rejected
                                 (only if quarantine=True and not tool-exploited)

        Returns a summary: {confirmed, false_positive, uncertain, quarantined, findings}.
        The returned "findings" list excludes quarantined items so callers can report
        only the surviving set while the originals keep their annotation.
        """
        if not findings:
            return {"confirmed": 0, "false_positive": 0, "uncertain": 0,
                    "quarantined": 0, "findings": []}

        logger.info(f"CRITIC_START: adversarially verifying {len(findings)} findings")
        verdicts = await asyncio.gather(
            *(self.verify_finding(f) for f in findings), return_exceptions=True
        )

        confirmed = false_pos = uncertain = quarantined = 0
        survivors: List[Dict[str, Any]] = []

        for finding, verdict in zip(findings, verdicts):
            if isinstance(verdict, Exception):
                logger.warning(f"[Critic] verdict exception: {verdict}")
                verdict = CriticVerdict(Verdict.UNCERTAIN, 0.0, reasoning=str(verdict))

            finding["critic"] = verdict.to_dict()
            base = float(finding.get("confidence_score", 0.75))

            if verdict.verdict == Verdict.CONFIRMED and verdict.confidence >= self.confirm_threshold:
                confirmed += 1
                finding["confidence_score"] = min(0.98, round(base + 0.10 * verdict.confidence, 3))
                survivors.append(finding)

            elif verdict.verdict == Verdict.FALSE_POSITIVE and verdict.confidence >= self.reject_threshold:
                false_pos += 1
                finding["confidence_score"] = max(0.05, round(base - 0.30 * verdict.confidence, 3))
                # Never quarantine something the exploit layer actually proved.
                tool_proven = bool(finding.get("exploited") or finding.get("confirmed"))
                if quarantine and not tool_proven:
                    finding["status"] = "QUARANTINED"
                    finding["quarantine_reason"] = verdict.reasoning or "Critic rejected finding"
                    quarantined += 1
                else:
                    survivors.append(finding)
            else:
                uncertain += 1
                survivors.append(finding)

        logger.info(
            f"CRITIC_COMPLETE: confirmed={confirmed} false_positive={false_pos} "
            f"uncertain={uncertain} quarantined={quarantined}"
        )
        return {
            "confirmed": confirmed,
            "false_positive": false_pos,
            "uncertain": uncertain,
            "quarantined": quarantined,
            "findings": survivors,
        }
