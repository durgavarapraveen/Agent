"""WorkflowRecorder (gaps §1) — turn observed traffic into an ordered sequence
of workflow steps with state deltas.

Source order is the capture order (ctx.captured_requests), which for a browser-
driven or replayed session is the real user journey (login → search → cart →
address → payment). No hardcoded workflow — the steps ARE what was observed.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Value tokens that carry workflow state between steps (produced then consumed).
_ID_KEY_RE = re.compile(r"(id|token|cart|order|session|price|total|amount|qty|quantity|coupon|user|account)", re.I)


@dataclass
class WorkflowStep:
    index: int
    method: str
    url: str
    request: Dict[str, Any]                       # raw captured request
    produced: Dict[str, str] = field(default_factory=dict)   # values in the response
    consumed: Dict[str, str] = field(default_factory=dict)   # values reused from earlier steps
    numeric_fields: Dict[str, float] = field(default_factory=dict)  # tamperable numbers in the request

    def label(self) -> str:
        # deterministic label from path; LLM refines this later (§5, Bedrock-gated)
        from urllib.parse import urlparse
        return f"{self.method} {urlparse(self.url).path or '/'}"


class WorkflowRecorder:
    def record(self, ctx) -> List[WorkflowStep]:
        reqs = getattr(ctx, "captured_requests", None) or []
        steps: List[WorkflowStep] = []
        for i, req in enumerate(reqs):
            if not isinstance(req, dict) or not (req.get("url") or req.get("endpoint")):
                continue
            step = WorkflowStep(
                index=i,
                method=str(req.get("method", "GET")).upper(),
                url=req.get("url") or req.get("endpoint"),
                request=req,
            )
            step.produced = self._values(req.get("response") or req.get("response_body") or "")
            step.numeric_fields = self._numeric_fields(req)
            steps.append(step)

        # link consumed values (a value produced by an earlier step that appears
        # in this step's request → data dependency / ordering edge)
        for j, step in enumerate(steps):
            req_blob = self._request_blob(step.request)
            for earlier in steps[:j]:
                for k, v in earlier.produced.items():
                    if v and len(v) >= 3 and v in req_blob:
                        step.consumed[k] = v
        logger.info("WorkflowRecorder: %d steps recorded", len(steps))
        return steps

    # ── extraction helpers ─────────────────────────────────────────────
    def _values(self, body) -> Dict[str, str]:
        out: Dict[str, str] = {}
        obj = self._as_json(body)
        if isinstance(obj, (dict, list)):
            self._walk(obj, out)
        return out

    def _walk(self, o, out: Dict[str, str], prefix: str = "") -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                key = f"{prefix}.{k}" if prefix else str(k)
                if isinstance(v, (dict, list)):
                    self._walk(v, out, key)
                elif _ID_KEY_RE.search(str(k)) and v not in (None, ""):
                    out[key] = str(v)
        elif isinstance(o, list):
            for i, v in enumerate(o[:20]):
                self._walk(v, out, f"{prefix}[{i}]")

    def _numeric_fields(self, req: Dict[str, Any]) -> Dict[str, float]:
        out: Dict[str, float] = {}
        obj = self._as_json(req.get("body") or req.get("data"))
        if isinstance(obj, dict):
            for k, v in obj.items():
                try:
                    if isinstance(v, bool):
                        continue
                    out[k] = float(v)
                except (TypeError, ValueError):
                    continue
        # query numeric params
        from urllib.parse import urlparse, parse_qsl
        for k, v in parse_qsl(urlparse(req.get("url", "")).query):
            try:
                out[k] = float(v)
            except ValueError:
                continue
        return out

    @staticmethod
    def _as_json(body):
        if isinstance(body, (dict, list)):
            return body
        if isinstance(body, str):
            try:
                return json.loads(body)
            except Exception:
                return None
        return None

    @staticmethod
    def _request_blob(req: Dict[str, Any]) -> str:
        parts = [str(req.get("url", "")), str(req.get("body") or req.get("data") or "")]
        h = req.get("headers") or {}
        if isinstance(h, dict):
            parts.append(str(h.get("Cookie", h.get("cookie", ""))))
        return " ".join(parts)
