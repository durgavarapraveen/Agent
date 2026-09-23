"""Jev (TypeSafe AI System-One) classifier client.

A thin async wrapper over the Jev ``POST /systemone`` endpoint. Jev returns typed
decisions (noul / choice / score) with probabilities instead of text, so this is a
CLASSIFIER — not an ``LLMProvider``. Use it for fast, cheap routing / gating / risk
decisions alongside the reasoning LLM.

Design:
  * httpx (already the harness HTTP client) → the egress firewall guard applies
    automatically; ``api.typesafe.ai`` is on the infra allowlist.
  * Best-effort: every failure returns ``{}`` / ``None`` and logs a warning; a
    classifier outage must never break a scan.
  * Optional per-scan cost accounting via the shared LLMCostLog.

Request:
    {"state": <text|json|list>, "model": "jev-latest",
     "questions": {"<name>": {"type": "noul|choice|score",
                              "instructions": "...", "options": [...]}}}
Response (keyed by question name):
    {"<name>": {"type": ..., "value": ..., "probability": 0-1,
                "probabilities": {opt: p, ...}}}
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from core.llm.jev_config import (
    jev_api_key, jev_base_url, jev_enabled, jev_model, PRICE_INPUT_PER_1M,
)

logger = logging.getLogger(__name__)


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class JevClassifier:
    """Async Jev System-One classifier. Stateless; safe to construct per call."""

    def __init__(self, api_key: str = "", base_url: str = "", model: str = "",
                 cost_log: Any = None, scan_id: str = ""):
        self.api_key = api_key or jev_api_key()
        self.base_url = (base_url or jev_base_url()).rstrip("/")
        self.model = model or jev_model()
        self._cost_log = cost_log
        self._scan_id = scan_id

    # Process-wide circuit breaker: once the Jev endpoint proves unreachable
    # (Cloudflare/HTML block page, or auth failure), stop calling it for the rest
    # of the run. This avoids (a) re-egressing scan state — including attack
    # payloads — to a third party on every decision, and (b) wasting latency on a
    # blocked endpoint. Jev is opt-in and degrades gracefully to {} when off.
    _circuit_open: bool = False
    _circuit_reason: str = ""

    def is_available(self) -> bool:
        return bool(self.api_key) and not type(self)._circuit_open

    @classmethod
    def _trip_circuit(cls, reason: str) -> None:
        if not cls._circuit_open:
            cls._circuit_open = True
            cls._circuit_reason = reason
            logger.warning("[Jev] disabled for this run — %s. No further requests "
                           "(and no further scan-state egress) will be made.", reason)

    async def classify(self, state: Any,
                       questions: Dict[str, Dict[str, Any]],
                       timeout: float = 20.0, site: str = "") -> Dict[str, Any]:
        """POST one request answering every question in parallel. Returns the
        per-question answer map, or ``{}`` on any failure. ``site`` labels where
        in the harness the decision was made (routing/phase_gate/tool_gate/triage)
        for the Jev decision log."""
        if not self.is_available():
            return {}
        if not questions:
            return {}
        # SystemOne schema: choice/score questions take `criteria` (a map of
        # option -> description), NOT an `options` list. Convert here so every
        # caller sends a valid request (an `options` list → HTTP 422). See
        # docs.typesafe.ai/introduction/quickstart.
        norm_q: Dict[str, Any] = {}
        for _k, _q in questions.items():
            _q = dict(_q or {})
            if "options" in _q and "criteria" not in _q:
                _opts = _q.pop("options") or []
                _q["criteria"] = _opts if isinstance(_opts, dict) else {
                    str(o): str(o) for o in _opts}
            norm_q[_k] = _q
        questions = norm_q
        body = {"state": state, "model": self.model, "questions": questions}
        url = f"{self.base_url}/systemone"
        start = time.monotonic()
        client = None
        try:
            import httpx
            client = httpx.AsyncClient(timeout=timeout)
            resp = await client.post(
                url, json=body,
                headers={"Authorization": f"Bearer {self.api_key}",
                         "Content-Type": "application/json",
                         # A real User-Agent + JSON Accept so the request isn't
                         # blocked as a bot by the endpoint's CDN (default
                         # python-httpx UA triggers Cloudflare "Attention Required").
                         "Accept": "application/json",
                         "User-Agent": "neo-scanner/2.0 (+jev-classifier)"})
            if resp.status_code >= 400:
                # Surface the server's validation detail (e.g. 422 body) so a
                # request-schema mismatch is diagnosable instead of a bare status.
                _detail = ""
                try:
                    _detail = resp.text[:500]
                except Exception:
                    pass
                # Distinguish an edge/CDN block or auth failure (endpoint unreachable
                # → trip the circuit, stop re-sending scan state) from a per-request
                # schema error like 422 (fixable, keep Jev enabled).
                _ct = (resp.headers.get("content-type", "") or "").lower()
                _blocked = (
                    resp.status_code in (401, 403, 407, 429)
                    or "text/html" in _ct
                    or "attention required" in _detail.lower()
                    or "cloudflare" in _detail.lower()
                    or "cf-ray" in {k.lower() for k in resp.headers.keys()}
                )
                logger.warning("[Jev] classify HTTP %s at %s — body=%s | sent=%s",
                               resp.status_code, url, _detail,
                               json.dumps(body, default=str)[:300])
                if _blocked:
                    self._trip_circuit(
                        f"endpoint unreachable (HTTP {resp.status_code}"
                        f"{', CDN/Cloudflare block' if 'text/html' in _ct or 'cloudflare' in _detail.lower() else ''}"
                        f") — check JEV_API_KEY / JEV_BASE_URL, or unset JEV_API_KEY to disable")
                return {}
            data = resp.json()
        except Exception as e:
            logger.warning("[Jev] classify failed: %s", e)
            return {}
        finally:
            if client is not None:
                try:
                    await client.aclose()
                except Exception:
                    pass

        latency = (time.monotonic() - start) * 1000
        answers = data.get("answers", data) if isinstance(data, dict) else {}
        answers = answers if isinstance(answers, dict) else {}
        self._account(state, questions, answers)
        self._log_decisions(state, questions, answers, site, latency)
        logger.info("[Jev] %s site=%s questions=%d latency=%.0fms",
                    self.model, site or "-", len(questions), latency)
        return answers

    def _log_decisions(self, state: Any, questions: Dict, answers: Dict,
                       site: str, latency_ms: float) -> None:
        """Persist each decision to the Jev decision log (UI audit tab). Best-
        effort — never breaks a decision."""
        try:
            import json
            from core.economics import jev_log
            scan_id = self._scan_id or jev_log.current_scan_id()
            if not scan_id:
                return
            preview = state if isinstance(state, str) else json.dumps(state)
            for name, q in questions.items():
                a = answers.get(name) or {}
                _val, _prob = self._value_prob(a)
                jev_log.log(
                    scan_id, site=site, decision_type=str(q.get("type", "")),
                    question=str(q.get("instructions", "")),
                    state_preview=str(preview)[:2000],
                    value=str(_val),
                    probability=_prob,
                    model=self.model, duration_ms=int(latency_ms))
        except Exception as e:
            logger.debug("[Jev] decision log skipped: %s", e)

    def _account(self, state: Any, questions: Dict, answers: Dict) -> None:
        """Meter input spend against the per-scan cost log. Mirrors the harness
        convention: use the injected cost_log/scan_id, else fall back to the
        global LLMCostLog + ANTIGRAVITY_SCAN_ID so Jev is metered by default."""
        try:
            import json
            import os
            scan_id = self._scan_id or os.getenv("ANTIGRAVITY_SCAN_ID", "")
            if not scan_id:
                return
            cost_log = self._cost_log
            if cost_log is None:
                from core.economics.cost_log import get_cost_log
                cost_log = get_cost_log()
            blob = state if isinstance(state, str) else json.dumps(state)
            blob += json.dumps(questions)
            in_tok = _estimate_tokens(blob)
            cost = in_tok * PRICE_INPUT_PER_1M / 1_000_000
            cost_log.record(scan_id, provider="jev", model=self.model,
                            input_tokens=in_tok, output_tokens=0,
                            cost_usd=round(cost, 8))
        except Exception as e:  # accounting must never break a scan
            logger.debug("[Jev] cost accounting skipped: %s", e)

    # ── single-question convenience helpers ──────────────────────────────

    async def noul(self, state: Any, instructions: str,
                   name: str = "q", site: str = "") -> Tuple[Optional[bool], float]:
        """Yes/no. Returns (True/False/None, probability)."""
        ans = await self.classify(state, {name: {"type": "noul",
                                                  "instructions": instructions}}, site=site)
        # Parse via the shared extractor so noul honours the real SystemOne
        # schema (choice/probabilities/confidence), not the legacy value/probability.
        val, prob = self._value_prob(ans.get(name) or {})
        if isinstance(val, bool):
            b = val
        elif isinstance(val, (int, float)):
            b = bool(val)
        elif isinstance(val, str):
            b = val.strip().lower() in ("true", "yes", "1")
        else:
            b = None
        return b, prob

    @staticmethod
    def _value_prob(a: Dict[str, Any]) -> Tuple[Optional[str], float]:
        """Extract (value, probability) from a SystemOne answer. Response uses
        `choice` (the selected value), `probabilities` (per-option map) and
        `confidence` — not the old `value`/`probability`."""
        a = a or {}
        val = a.get("choice", a.get("score", a.get("value")))
        probs = a.get("probabilities")
        if val is not None and isinstance(probs, dict) and str(val) in {str(k) for k in probs}:
            try:
                prob = float(probs.get(val, probs.get(str(val), 0.0)) or 0.0)
            except Exception:
                prob = float(a.get("confidence", 0.0) or 0.0)
        else:
            prob = float(a.get("confidence", a.get("probability", 0.0)) or 0.0)
        return val, prob

    async def choice(self, state: Any, instructions: str, options: List[str],
                     name: str = "q", site: str = "") -> Tuple[Optional[str], float]:
        """Pick one of ``options``. Returns (value, probability)."""
        ans = await self.classify(state, {name: {"type": "choice",
                                                  "instructions": instructions,
                                                  "options": options}}, site=site)
        return self._value_prob(ans.get(name) or {})

    async def score(self, state: Any, instructions: str, levels: List[str],
                    name: str = "q", site: str = "") -> Tuple[Optional[str], float]:
        """Rate against ordered ``levels``. Returns (level, probability)."""
        ans = await self.classify(state, {name: {"type": "score",
                                                 "instructions": instructions,
                                                 "options": levels}}, site=site)
        return self._value_prob(ans.get(name) or {})


_default: Optional[JevClassifier] = None


def get_jev(cost_log: Any = None, scan_id: str = "") -> Optional[JevClassifier]:
    """Shared classifier, or None when no JEV_API_KEY is configured. Pass a
    cost_log + scan_id to meter spend for this scan."""
    if not jev_enabled():
        return None
    if cost_log or scan_id:
        return JevClassifier(cost_log=cost_log, scan_id=scan_id)
    global _default
    if _default is None:
        _default = JevClassifier()
    return _default
