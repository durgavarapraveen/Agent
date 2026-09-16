"""Pα Dynamic Hypothesis Engine — catch-all vulnerability discovery for any attack surface."""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.intelligence.signal_collector import ReconSignal, SignalClassifier, SignalCollector

logger = logging.getLogger(__name__)


@dataclass
class DynamicHypothesis:
    hyp_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    vulnerability_class: str = ""
    description: str = ""
    confidence: str = "medium"   # low/medium/high
    severity: str = "medium"     # critical/high/medium/low/info
    attack_surface: str = ""     # classified surface type
    test_steps: List[Dict[str, Any]] = field(default_factory=list)
    success_criteria: str = ""
    tools_needed: List[str] = field(default_factory=list)
    signals: List[str] = field(default_factory=list)  # raw signal data that triggered this
    cwe: str = ""

    def priority_score(self) -> float:
        sev_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}
        conf_map = {"high": 1.0, "medium": 0.6, "low": 0.3}
        return sev_map.get(self.severity, 0.5) * conf_map.get(self.confidence, 0.5)


@dataclass
class ExploitStep:
    tool: str          # "network_broker" | "browser_actuator" | "custom_probe"
    action: Dict[str, Any] = field(default_factory=dict)
    expect: str = ""
    extract: str = ""


@dataclass
class ExploitPlan:
    hypothesis: DynamicHypothesis = field(default_factory=DynamicHypothesis)
    steps: List[ExploitStep] = field(default_factory=list)
    rollback: List[ExploitStep] = field(default_factory=list)


@dataclass
class ExploitResult:
    plan: ExploitPlan = field(default_factory=ExploitPlan)
    success: bool = False
    evidence: str = ""
    raw_responses: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""


HYPOTHESIS_PROMPT = """You are an expert penetration tester. Given these recon signals from {target}:

{classified_signals}

Technologies detected: {technologies}
Endpoints discovered: {endpoints_summary}

For each attack surface you identify, generate a hypothesis as JSON:
{{
  "hypotheses": [
    {{
      "vulnerability_class": "CWE or OWASP category",
      "description": "what the vulnerability is",
      "confidence": "low|medium|high",
      "severity": "critical|high|medium|low",
      "attack_surface": "surface type",
      "test_steps": [
        {{
          "tool": "network_broker|browser_actuator|custom_probe",
          "action": {{"method": "GET|POST|...", "url": "...", "headers": {{}}, "body": "..."}},
          "expect": "what success looks like",
          "extract": "what to pull from response"
        }}
      ],
      "success_criteria": "what confirms the vuln",
      "cwe": "CWE-XXX"
    }}
  ]
}}

Generate hypotheses for ANY vulnerability you see evidence for.
Focus on exploitable issues, not theoretical ones.
Maximum 15 hypotheses, ranked by severity × confidence.
Do NOT generate hypotheses for things already covered by standard scanning (basic SQLi, XSS via parameter reflection, directory bruteforce).
Focus on logic flaws, misconfigurations, and advanced attack surfaces."""

ANALYSIS_PROMPT = """Given this hypothesis:
- Class: {vuln_class}
- Description: {description}
- Success criteria: {success_criteria}

And these test results:
{results}

Did the test confirm a vulnerability?
Respond as JSON:
{{
  "confirmed": true|false,
  "partial": true|false,
  "severity": "critical|high|medium|low|info",
  "evidence_summary": "what proves it",
  "finding_title": "short title for the finding",
  "remediation": "how to fix",
  "next_test": "if partial, what additional test would confirm/deny"
}}"""


class DynamicHypothesisEngine:
    def __init__(self, ctx, llm_client=None):
        self.ctx = ctx
        self.llm_client = llm_client
        self.classifier = SignalClassifier()
        self.collector = SignalCollector()
        self._findings: List[Dict[str, Any]] = []
        self._hypotheses_tested = 0
        self._hypotheses_confirmed = 0

    async def _get_llm(self):
        if self.llm_client:
            return self.llm_client
        from agents.universal_llm_harness import get_llm_client
        self.llm_client = get_llm_client()
        return self.llm_client

    async def run_cycle(self, signals: Optional[List[ReconSignal]] = None,
                        cycle_name: str = "first_order") -> List[Dict[str, Any]]:
        """Full Pα cycle: collect → classify → hypothesize → plan → execute → analyze."""
        logger.info(f"[Pα] Starting {cycle_name} hypothesis cycle")

        if signals is None:
            signals = self.collector.collect_from_ctx(self.ctx)

        if not signals:
            logger.info("[Pα] No signals to process")
            return []

        classified = self.classifier.classify(signals)
        surfaces = {k: len(v) for k, v in classified.items() if k != "unknown"}
        logger.info(f"[Pα] Classified {len(signals)} signals into {len(surfaces)} attack surfaces: {surfaces}")

        hypotheses = await self._generate_hypotheses(classified)
        if not hypotheses:
            logger.info("[Pα] LLM generated no hypotheses")
            return []

        ranked = sorted(hypotheses, key=lambda h: h.priority_score(), reverse=True)
        logger.info(f"[Pα] Generated {len(ranked)} hypotheses, testing top candidates")

        findings = []
        max_tests = min(len(ranked), 20)
        for hyp in ranked[:max_tests]:
            # Skip if a specialist module handles this surface
            if self._has_specialist(hyp):
                logger.debug(f"[Pα] Routing {hyp.vulnerability_class} to specialist module")
                continue

            self._hypotheses_tested += 1
            result = await self._execute_hypothesis(hyp)
            if result and result.success:
                finding = await self._analyze_result(result)
                if finding:
                    self._hypotheses_confirmed += 1
                    findings.append(finding)
                    self._findings.append(finding)

        logger.info(f"[Pα] Cycle complete: {self._hypotheses_tested} tested, "
                    f"{self._hypotheses_confirmed} confirmed, {len(findings)} new findings")
        return findings

    # Maps attack surface categories to their specialist modules.
    # If the module imports successfully, Pα routes to it instead of handling directly.
    _SPECIALIST_MODULES = {
        "race_condition": "core.exploitation.race_probe",
        "jwt": "core.exploitation.crypto_chain",
        "crypto": "core.exploitation.crypto_chain",
        "serialization": "core.exploitation.crypto_chain",
        "websocket": "core.actuation.browser_agent",
        "client_side": "core.actuation.browser_agent",
        "dom": "core.actuation.browser_agent",
        "xss": "core.actuation.browser_agent",
        "upload": "core.exploitation.param_fuzzer",
        "parameter": "core.exploitation.param_fuzzer",
        "chatbot": "core.exploitation.chatbot_exploit",
        "llm": "core.exploitation.chatbot_exploit",
        "web3": "core.exploitation.web3_probe",
        "blockchain": "core.exploitation.web3_probe",
        "smart_contract": "core.exploitation.web3_probe",
        "identity": "core.intelligence.identity_intel",
        "osint": "core.intelligence.identity_intel",
        "session": "core.exploitation.session_probe",
        "cookie": "core.exploitation.session_probe",
        "second_order": "core.exploitation.second_order",
        "stored_injection": "core.exploitation.second_order",
        "authorization": "core.exploitation.authz_matrix",
        "idor": "core.exploitation.authz_matrix",
        "bola": "core.exploitation.authz_matrix",
    }

    def _has_specialist(self, hyp: DynamicHypothesis) -> bool:
        """Check if a dedicated module handles this vulnerability class."""
        surface = hyp.attack_surface.lower()
        module_path = self._SPECIALIST_MODULES.get(surface)
        if not module_path:
            return False
        try:
            __import__(module_path)
            return True
        except ImportError:
            return False

    async def _generate_hypotheses(self, classified: Dict[str, List[ReconSignal]]) -> List[DynamicHypothesis]:
        llm = await self._get_llm()

        signal_text = ""
        for surface, sigs in classified.items():
            if surface == "unknown":
                continue
            signal_text += f"\n## {surface.upper()} ({len(sigs)} signals)\n"
            for sig in sigs[:5]:
                signal_text += f"  - [{sig.source}] {sig.raw_data[:200]}\n"

        if not signal_text.strip():
            return []

        techs = ", ".join(
            t if isinstance(t, str) else t.get("name", str(t))
            for t in (getattr(self.ctx, "technologies", []) or [])[:20]
        ) or "unknown"

        ep_count = len(getattr(self.ctx, "endpoints", []) or [])
        endpoints_summary = f"{ep_count} endpoints discovered"

        prompt = HYPOTHESIS_PROMPT.format(
            target=getattr(self.ctx, "target", "unknown"),
            classified_signals=signal_text,
            technologies=techs,
            endpoints_summary=endpoints_summary,
        )

        try:
            from core.llm.task_tier import TaskTier
            resp = await llm.generate(
                messages=[{"role": "user", "content": prompt}],
                tier=TaskTier.MEDIUM,
                temperature=0.3,
            )
            return self._parse_hypotheses(resp.content)
        except Exception as e:
            logger.error(f"[Pα] Hypothesis generation failed: {e}")
            return []

    def _parse_hypotheses(self, raw: str) -> List[DynamicHypothesis]:
        hypotheses = []
        try:
            # Extract JSON from LLM response
            json_match = raw
            if "```json" in raw:
                json_match = raw.split("```json")[1].split("```")[0]
            elif "```" in raw:
                json_match = raw.split("```")[1].split("```")[0]

            data = json.loads(json_match)
            items = data.get("hypotheses", []) if isinstance(data, dict) else data

            for item in items:
                if not isinstance(item, dict):
                    continue
                hyp = DynamicHypothesis(
                    vulnerability_class=item.get("vulnerability_class", ""),
                    description=item.get("description", ""),
                    confidence=item.get("confidence", "medium"),
                    severity=item.get("severity", "medium"),
                    attack_surface=item.get("attack_surface", ""),
                    test_steps=item.get("test_steps", []),
                    success_criteria=item.get("success_criteria", ""),
                    cwe=item.get("cwe", ""),
                )
                hypotheses.append(hyp)
        except (json.JSONDecodeError, IndexError, KeyError) as e:
            logger.warning(f"[Pα] Failed to parse hypotheses JSON: {e}")
        return hypotheses

    async def _execute_hypothesis(self, hyp: DynamicHypothesis) -> Optional[ExploitResult]:
        """Execute test steps from a hypothesis using available tools."""
        logger.info(f"[Pα] Testing: {hyp.vulnerability_class} — {hyp.description[:80]}")

        result = ExploitResult(plan=ExploitPlan(hypothesis=hyp))

        for step in hyp.test_steps:
            if not isinstance(step, dict):
                continue
            tool = step.get("tool", "network_broker")
            action = step.get("action", {})

            try:
                step_result = await self._execute_step(tool, action)
                result.raw_responses.append(step_result)
            except Exception as e:
                logger.debug(f"[Pα] Step failed: {e}")
                result.raw_responses.append({"error": str(e)})

        if result.raw_responses:
            result.success = True
            result.evidence = json.dumps(result.raw_responses[:3], default=str)[:2000]

        return result

    async def _execute_step(self, tool: str, action: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single exploit step via the appropriate tool."""
        if tool in ("network_broker", "http"):
            return await self._execute_http(action)
        elif tool in ("custom_probe", "probe"):
            return await self._execute_probe(action)
        elif tool in ("browser_actuator", "browser"):
            return await self._execute_browser(action)
        else:
            return await self._execute_http(action)

    async def _execute_http(self, action: Dict[str, Any]) -> Dict[str, Any]:
        method = action.get("method", "GET").upper()
        url = action.get("url", "")
        if not url:
            return {"error": "no url"}

        # Scope check
        try:
            from core.security.authorization import TargetScopeValidator
            from urllib.parse import urlparse
            host = urlparse(url).hostname
            if host and not TargetScopeValidator.get().is_authorized(host):
                return {"error": "out of scope", "url": url}
        except Exception:
            return {"error": "scope check failed — rejecting (fail-closed)"}

        try:
            from core.network.broker import NetworkBroker
            broker = NetworkBroker()
            resp = await broker.send_request(
                method=method,
                url=url,
                headers=action.get("headers", {}),
                body=action.get("body"),
                timeout=action.get("timeout", 15),
            )
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers) if hasattr(resp, "headers") else {},
                "body": str(resp.text or resp.body or "")[:2000],
                "url": url,
            }
        except Exception as e:
            return {"error": str(e), "url": url}

    async def _execute_probe(self, action: Dict[str, Any]) -> Dict[str, Any]:
        try:
            from core.exploitation.custom_probe import run_custom_probe
            result = await run_custom_probe(action, self.ctx)
            return {"result": str(result)[:2000]}
        except Exception as e:
            return {"error": str(e)}

    async def _execute_browser(self, action: Dict[str, Any]) -> Dict[str, Any]:
        try:
            from core.actuation.browser_actuator import BrowserActuator
            browser = BrowserActuator()
            result = await browser.run_actions(action.get("actions", [action]))
            return {"result": str(result)[:2000]}
        except Exception as e:
            return {"error": str(e)}

    async def _analyze_result(self, result: ExploitResult) -> Optional[Dict[str, Any]]:
        """LLM evaluates whether the exploit succeeded."""
        hyp = result.plan.hypothesis
        llm = await self._get_llm()

        prompt = ANALYSIS_PROMPT.format(
            vuln_class=hyp.vulnerability_class,
            description=hyp.description,
            success_criteria=hyp.success_criteria,
            results=result.evidence[:3000],
        )

        try:
            from core.llm.task_tier import TaskTier
            resp = await llm.generate(
                messages=[{"role": "user", "content": prompt}],
                tier=TaskTier.SMALL,
                temperature=0.1,
            )

            analysis = self._parse_analysis(resp.content)
            if not analysis:
                return None

            if analysis.get("confirmed") or analysis.get("partial"):
                finding = {
                    "finding_id": str(uuid.uuid4()),
                    "title": analysis.get("finding_title", hyp.vulnerability_class),
                    "type": hyp.vulnerability_class,
                    "description": hyp.description,
                    "severity": analysis.get("severity", hyp.severity).upper(),
                    "confidence_score": {"high": 0.9, "medium": 0.6, "low": 0.3}.get(hyp.confidence, 0.5),
                    "target": getattr(self.ctx, "target", ""),
                    "evidence": analysis.get("evidence_summary", ""),
                    "remediation": analysis.get("remediation", ""),
                    "cwe": hyp.cwe,
                    "source": "dynamic_hypothesis_engine",
                    "attack_surface": hyp.attack_surface,
                    "status": "confirmed" if analysis.get("confirmed") else "partial",
                    "tool": "pa_engine",
                }
                return finding
        except Exception as e:
            logger.error(f"[Pα] Result analysis failed: {e}")
        return None

    def _parse_analysis(self, raw: str) -> Optional[Dict[str, Any]]:
        try:
            text = raw
            if "```json" in raw:
                text = raw.split("```json")[1].split("```")[0]
            elif "```" in raw:
                text = raw.split("```")[1].split("```")[0]
            return json.loads(text)
        except (json.JSONDecodeError, IndexError):
            logger.debug(f"[Pα] Could not parse analysis response")
            return None

    def stats(self) -> Dict[str, Any]:
        return {
            "hypotheses_tested": self._hypotheses_tested,
            "hypotheses_confirmed": self._hypotheses_confirmed,
            "findings": len(self._findings),
        }
