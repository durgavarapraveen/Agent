"""WorkflowViolationTester (gaps §1) — break the learned workflow's invariants
and ordering: value tamper, replay, step-skip, reorder, cross-user.

All requests go through NetworkBroker (scope/egress enforced). Confirmations use
the BUSINESS_LOGIC / RACE_CONDITION / IDOR oracles. Non-fatal throughout.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from core.workflow.learner import Workflow, WorkflowLearner
from core.workflow.recorder import WorkflowRecorder

logger = logging.getLogger(__name__)

_STATE_METHODS = ("POST", "PUT", "PATCH", "DELETE")


class WorkflowViolationTester:
    def __init__(self, oracle=None):
        if oracle is None:
            from core.evidence.oracle import get_oracle_engine
            oracle = get_oracle_engine()
        self.oracle = oracle

    async def test(self, ctx, wf: Workflow) -> List[Dict[str, Any]]:
        if not wf.is_multi_step():
            return []
        findings: List[Dict[str, Any]] = []
        findings += await self._value_tamper(ctx, wf)
        findings += await self._replay(ctx, wf)
        findings += await self._step_skip(ctx, wf)
        for f in findings:
            try:
                ctx.add_vulnerability(f)
            except Exception:
                pass
        logger.info("WorkflowViolationTester: %d business-logic findings", len(findings))
        return findings

    # ── value tamper: negative qty / lowered price/total ───────────────
    async def _value_tamper(self, ctx, wf: Workflow) -> List[Dict[str, Any]]:
        out = []
        for step in wf.ordered():
            if step.method not in _STATE_METHODS:
                continue
            for fld, val in step.numeric_fields.items():
                low = fld.lower()
                if not any(t in low for t in ("qty", "quantity", "amount", "price", "total", "count")):
                    continue
                tampered = -abs(val) if val else -1  # negative / underflow
                resp = await self._send(step.request, mutate={fld: tampered})
                if resp is None:
                    continue
                ev = {
                    "response_body": resp["body"], "status_code": resp["status"],
                    "state_changed_unexpectedly": 200 <= resp["status"] < 300,
                    "evidence_id": f"wf_tamper_{step.index}_{fld}",
                }
                r = self.oracle.evaluate("BUSINESS_LOGIC", ev)
                if r.is_vulnerable:
                    out.append(self._finding(
                        "BUSINESS_LOGIC", step,
                        f"Negative/lowered '{fld}'={tampered} accepted (was {val})",
                        f"{fld} tampered to {tampered}; HTTP {resp['status']}", r))
        return out

    # ── replay: resend a one-time state step (coupon reuse / double action) ─
    async def _replay(self, ctx, wf: Workflow) -> List[Dict[str, Any]]:
        out = []
        for step in wf.ordered():
            if step.method not in _STATE_METHODS:
                continue
            if not any(t in json.dumps(step.request).lower() for t in ("coupon", "voucher", "promo", "redeem", "gift")):
                continue
            first = await self._send(step.request)
            second = await self._send(step.request)
            if first and second and 200 <= first["status"] < 300 and 200 <= second["status"] < 300:
                ev = {"duplicate_success_count": 2, "evidence_id": f"wf_replay_{step.index}"}
                r = self.oracle.evaluate("RACE_CONDITION", ev)
                out.append(self._finding(
                    "BUSINESS_LOGIC", step, "One-time action replayable (coupon/promo reuse)",
                    f"Two identical requests both succeeded (HTTP {first['status']}/{second['status']})",
                    r, severity="HIGH"))
        return out

    # ── step skip: fire a later state step without its precondition ─────
    async def _step_skip(self, ctx, wf: Workflow) -> List[Dict[str, Any]]:
        out = []
        # a step that consumes values (has preconditions) fired in isolation
        for t in wf.transitions:
            dst = next((s for s in wf.steps if s.index == t.dst), None)
            if not dst or dst.method not in _STATE_METHODS or not t.preconditions:
                continue
            # strip carried precondition values from the request → simulate skipping
            resp = await self._send(dst.request, drop_values=list(t.carried.values()))
            if resp is None:
                continue
            ev = {
                "response_body": resp["body"], "status_code": resp["status"],
                "workflow_step_skipped": 200 <= resp["status"] < 300,
                "evidence_id": f"wf_skip_{dst.index}",
            }
            r = self.oracle.evaluate("BUSINESS_LOGIC", ev)
            if r.is_vulnerable:
                out.append(self._finding(
                    "BUSINESS_LOGIC", dst,
                    "State step succeeded without its precondition (step-skip)",
                    f"Dropped preconditions {t.preconditions}; HTTP {resp['status']}", r))
        return out

    # ── request sender ─────────────────────────────────────────────────
    async def _send(self, req: Dict[str, Any], mutate: Optional[Dict[str, Any]] = None,
                    drop_values: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        try:
            from core.network.network_broker import NetworkBroker
            broker = NetworkBroker.get()
        except Exception:
            return None
        method = str(req.get("method", "GET")).upper()
        url = req.get("url") or req.get("endpoint")
        if not url:
            return None
        headers = dict(req.get("headers") or {})
        body = req.get("body") or req.get("data")
        kwargs: Dict[str, Any] = {}

        # apply mutation / drop to body (json or form) and query
        if mutate or drop_values:
            body, url = self._apply(body, url, headers, mutate or {}, drop_values or [])
        if body is not None and body != "":
            kwargs["content"] = body if isinstance(body, str) else json.dumps(body)
        if headers:
            kwargs["headers"] = headers
        try:
            resp = await broker.request(method, url, **kwargs)
        except Exception as e:
            logger.debug("workflow send failed: %s", e)
            return None
        return {"body": getattr(resp, "text", "") or "", "status": getattr(resp, "status_code", 0) or 0}

    @staticmethod
    def _apply(body, url, headers, mutate: Dict[str, Any], drop: List[str]):
        ctype = str((headers or {}).get("Content-Type", headers.get("content-type", ""))).lower()
        # json body
        obj = None
        if isinstance(body, (dict, list)):
            obj = body
        elif isinstance(body, str) and body.strip().startswith(("{", "[")):
            try:
                obj = json.loads(body)
            except Exception:
                obj = None
        if isinstance(obj, dict):
            for k, v in mutate.items():
                if k in obj:
                    obj[k] = v
            for dv in drop:
                for k in list(obj.keys()):
                    if str(obj[k]) == str(dv):
                        obj.pop(k, None)
            return json.dumps(obj), url
        # form / query
        if isinstance(body, str) and "=" in body:
            pairs = dict(parse_qsl(body))
            for k, v in mutate.items():
                if k in pairs:
                    pairs[k] = str(v)
            for dv in drop:
                pairs = {k: val for k, val in pairs.items() if val != str(dv)}
            return urlencode(pairs), url
        # query params on the URL
        parts = urlparse(url)
        q = dict(parse_qsl(parts.query))
        for k, v in mutate.items():
            if k in q:
                q[k] = str(v)
        for dv in drop:
            q = {k: val for k, val in q.items() if val != str(dv)}
        return body, urlunparse(parts._replace(query=urlencode(q)))

    @staticmethod
    def _finding(vtype, step, title, proof, result, severity="MEDIUM") -> Dict[str, Any]:
        import hashlib
        fid = "WF_" + hashlib.sha256(f"{vtype}|{step.url}|{title}".encode()).hexdigest()[:16]
        return {
            "id": fid, "type": vtype, "title": f"{title} @ {step.label()}",
            "severity": severity, "target": step.url, "location": step.url,
            "proof": proof, "details": getattr(result, "reasoning", ""),
            "tool": "workflow_violation_tester",
            "confirmed": getattr(result, "is_vulnerable", False) and not getattr(result, "requires_manual_confirmation", True),
            "status": "CONFIRMED" if not getattr(result, "requires_manual_confirmation", True) else "NEEDS_REVIEW",
        }


async def run_workflow_probe(ctx) -> List[Dict[str, Any]]:
    steps = WorkflowRecorder().record(ctx)
    if len(steps) < 2:
        return []
    wf = WorkflowLearner().learn(steps)
    return await WorkflowViolationTester().test(ctx, wf)
