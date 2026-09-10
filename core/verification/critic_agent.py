
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
    INCONCLUSIVE = "INCONCLUSIVE"    # evidence exists but contradictory or ambiguous


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

    def __init__(
        self,
        llm_client: Optional[Any] = None,
        max_concurrency: int = 4,
        confirm_threshold: float = 0.6,
        reject_threshold: float = 0.85,
        max_tokens: int = 900,
    ):
        self._llm = llm_client
        self._sem = asyncio.Semaphore(max(1, max_concurrency))
        self.confirm_threshold = confirm_threshold
        self.reject_threshold = reject_threshold
        self.max_tokens = max_tokens


    def _get_llm(self):
        if self._llm is not None:
            return self._llm
        # Lazy import to avoid a hard dependency at module import time.
        from agents.llm_client import LLMClient
        self._llm = LLMClient.get()
        return self._llm


    @staticmethod
    def _summarize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
        evidence = finding.get("evidence") or finding.get("proof") or {}
        if isinstance(evidence, dict):
            evidence_str = json.dumps(evidence, default=str)[:4000]
        else:
            evidence_str = str(evidence)[:4000]

        return {
            "type": finding.get("type") or finding.get("vuln_type") or "UNKNOWN",
            "title": finding.get("title") or "",
            "severity": finding.get("severity") or "",
            "location": finding.get("location") or finding.get("url")
            or finding.get("affected_endpoint") or finding.get("target") or "",
            "method": finding.get("method") or "",
            "payload": str(finding.get("payload") or finding.get("post_data") or "")[:2000],
            "matched_indicator": finding.get("tracer_used") or finding.get("matched_error") or "",
            "status_code": finding.get("status_code") or finding.get("expected_status") or "",
            "source": finding.get("source") or "",
            "tool_confirmed": bool(finding.get("confirmed") or finding.get("exploited")),
            "description": str(finding.get("description") or "")[:2000],
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
            '  "verdict": "CONFIRMED" | "FALSE_POSITIVE" | "UNCERTAIN" | "INCONCLUSIVE",\n'
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
        ftype = str(finding.get("type") or finding.get("vuln_type") or "").upper()

        gate_result = self._check_confirmation_gate(finding, ftype)
        if gate_result is not None:
            return gate_result

        # ── Phase 27: SPA catch-all detection ──
        if self._is_spa_false_positive(finding):
            return CriticVerdict(
                verdict=Verdict.FALSE_POSITIVE, confidence=0.95,
                reasoning="SPA catch-all: endpoint returns identical content for random paths — "
                          "finding is likely against the SPA shell, not a real endpoint.",
                false_positive_scenarios=["SPA framework serves same page for all routes"],
                model="heuristic_spa",
            )

        # ── Phase 27: Target degradation guard ──
        if self._target_was_degraded(finding):
            return CriticVerdict(
                verdict=Verdict.UNCERTAIN, confidence=0.3,
                reasoning="Target was degraded/throttled when this finding was produced — "
                          "results may be unreliable. Needs retest when target is healthy.",
                missing_evidence=["Retest when target health is HEALTHY"],
                model="heuristic_health",
            )

        # ── Phase 27: Identity context validation ──
        identity_issue = self._check_identity_context(finding)
        if identity_issue:
            return CriticVerdict(
                verdict=Verdict.UNCERTAIN, confidence=0.4,
                reasoning=identity_issue,
                missing_evidence=["Retest with correct identity/session"],
                model="heuristic_identity",
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
            elif "INCONCLUSIVE" in raw_verdict or raw_verdict in ("AMBIGUOUS", "MIXED"):
                verdict = Verdict.INCONCLUSIVE
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
            reasoning=str(data.get("reasoning", ""))[:2000],
            false_positive_scenarios=_as_list(data.get("false_positive_scenarios")),
            missing_evidence=_as_list(data.get("missing_evidence")),
            model=str(data.get("model", "llm")),
        )

    # --------------------------------------------------------- Phase 27 helpers

    @staticmethod
    def _check_confirmation_gate(self, finding: Dict[str, Any],
                                ftype: str) -> Optional[CriticVerdict]:
        try:
            from core.verification.finding_confirmation_gate import (
                FindingConfirmationGate, ConfirmationStage,
                _is_llm_wording_only, _is_status_code_only,
            )
            if _is_llm_wording_only(finding):
                return CriticVerdict(
                    verdict=Verdict.UNCERTAIN, confidence=0.1,
                    reasoning="P0.6: evidence is LLM wording only — not confirmable",
                    missing_evidence=["concrete tool output", "reproduction proof"],
                    model="p0.6_gate",
                )
            if _is_status_code_only(finding):
                return CriticVerdict(
                    verdict=Verdict.UNCERTAIN, confidence=0.1,
                    reasoning="P0.6: evidence is HTTP status code only — not confirmable",
                    missing_evidence=["response body analysis", "reproduction proof"],
                    model="p0.6_gate",
                )
        except ImportError:
            pass
        return None

    def _is_spa_false_positive(finding: Dict[str, Any]) -> bool:
        spa_indicators = finding.get("spa_catch_all", False)
        if spa_indicators:
            return True
        response_body = str(finding.get("response_body", finding.get("proof", "")))
        if not response_body:
            return False
        spa_markers = [
            '<div id="app">', '<div id="root">', "window.__NUXT__",
            "window.__NEXT_DATA__", "__webpack_require__",
            '<script type="module"', "ng-app=", "data-reactroot",
        ]
        ftype = str(finding.get("type", "")).upper()
        if ftype in ("PATH_TRAVERSAL", "INFO_DISCLOSURE", "DIRECTORY_LISTING"):
            if any(m in response_body for m in spa_markers):
                return True
        return False

    def _target_was_degraded(self, finding: Dict[str, Any]) -> bool:
        health_at_test = finding.get("target_health_state", "")
        if health_at_test in ("DEGRADED", "THROTTLED", "PAUSED"):
            return True
        response_time = finding.get("response_time_ms", 0)
        status_code = finding.get("status_code", 200)
        if status_code in (429, 503, 502) and not finding.get("exploited"):
            return True
        if response_time and response_time > 30000 and not finding.get("exploited"):
            return True
        return False

    @staticmethod
    def _check_identity_context(finding: Dict[str, Any]) -> str:
        ftype = str(finding.get("type", finding.get("attack_type", ""))).upper()
        authz_types = {"IDOR", "BOLA", "PRIVILEGE_ESCALATION", "AUTHORIZATION",
                       "HORIZONTAL_ACCESS", "VERTICAL_ACCESS", "BROKEN_ACCESS_CONTROL"}
        if ftype in authz_types or "authz" in ftype.lower():
            identity = finding.get("identity") or finding.get("identity_id") or finding.get("tested_as")
            if not identity:
                return (f"Authorization finding ({ftype}) has no identity context — "
                        "cannot verify which user/role was used. Needs identity-aware retest.")
            identities_used = finding.get("identities_compared", [])
            if ftype in ("IDOR", "BOLA", "HORIZONTAL_ACCESS") and len(identities_used) < 2:
                return (f"IDOR/horizontal finding requires comparison between 2+ identities, "
                        f"but only {len(identities_used)} identity recorded.")
        return ""

    # ------------------------------------------------------------ verify many

    async def verify_findings(
        self, findings: List[Dict[str, Any]], quarantine: bool = True
    ) -> Dict[str, Any]:
        if not findings:
            return {"confirmed": 0, "false_positive": 0, "uncertain": 0,
                    "inconclusive": 0, "quarantined": 0, "findings": []}

        logger.info(f"CRITIC_START: adversarially verifying {len(findings)} findings")
        verdicts = await asyncio.gather(
            *(self.verify_finding(f) for f in findings), return_exceptions=True
        )

        confirmed = false_pos = uncertain = inconclusive = quarantined = 0
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
                # Only quarantine LOW-EVIDENCE findings the critic is very sure about.
                # Anything the tools/agent actually demonstrated (evidence/proof/exploited/
                # confirmed, or produced by a scanner/agent source) is downgraded, never
                # dropped — a skeptical LLM must not delete real findings on a live target.
                _tool_sources = {
                    "exploit_agent", "agentic_executor", "objective_agent",
                    "sqlmap", "nuclei", "nikto", "dalfox", "sslscan",
                    "nmap", "ffuf", "gobuster", "feroxbuster", "katana",
                    "arjun", "profiler",
                }
                has_evidence = bool(
                    finding.get("exploited") or finding.get("confirmed")
                    or finding.get("evidence") or finding.get("proof")
                    or str(finding.get("source") or "").lower() in _tool_sources
                    or str(finding.get("tool") or "").lower() in _tool_sources
                    or str(finding.get("type") or "").upper() in _STRONG_TOOL_TYPES
                )
                if quarantine and not has_evidence:
                    finding["status"] = "QUARANTINED"
                    finding["quarantine_reason"] = verdict.reasoning or "Critic rejected finding"
                    quarantined += 1
                else:
                    finding["critic_flag"] = "downgraded_by_critic"
                    survivors.append(finding)

            elif verdict.verdict == Verdict.INCONCLUSIVE:
                inconclusive += 1
                finding["confidence_score"] = max(0.2, round(base - 0.10, 3))
                finding["critic_flag"] = "inconclusive"
                survivors.append(finding)

            else:
                uncertain += 1
                survivors.append(finding)

        logger.info(
            f"CRITIC_COMPLETE: confirmed={confirmed} false_positive={false_pos} "
            f"uncertain={uncertain} inconclusive={inconclusive} quarantined={quarantined}"
        )
        return {
            "confirmed": confirmed,
            "false_positive": false_pos,
            "uncertain": uncertain,
            "inconclusive": inconclusive,
            "quarantined": quarantined,
            "findings": survivors,
        }
