
from __future__ import annotations

import json
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional

from core.actuation.actuators import Actuators
from core.actuation.browser_actuator import BrowserActuator

logger = logging.getLogger(__name__)

_SYSTEM = (
    "You are an elite penetration tester working an AUTHORIZED engagement. You act by "
    "choosing ONE tool action at a time; after each action you receive the real response. "
    "Think step by step, chain requests, and adapt. Multi-step logic (forge a JWT, decode "
    "a secret, manipulate state across requests, drive the browser for client-side bugs) "
    "is expected. When you have concretely demonstrated a vulnerability, call report_finding "
    "with the evidence. Respond ONLY with a JSON object for the next action."
)

_ACTION_SPEC = (
    'Respond with JSON: {"reasoning":"1 sentence","tool":"<name>","args":{...}} '
    'or {"done":true}. Tools:\n'
    '- http_request {method, path, headers?, json_body?, params?}\n'
    '- jwt_decode {token}   - jwt_forge {payload, alg("none"|"HS256"), key?}\n'
    '- encode {text, scheme}   - decode {text, scheme}\n'
    '- upload_file {path, filename, content, content_type?}\n'
    '- browser_run {actions:[{action:"navigate|fill|click|eval|wait|dom|localStorage", ...}]} '
    '(real headless Chromium — for DOM/CSP/SPA/client-side)\n'
    '- report_finding {type, severity, title, evidence} (record a demonstrated vulnerability)\n'
)


class ObjectiveAgentLoop:
    def __init__(
        self,
        target: str,
        harness: Any,
        auth_headers: Optional[Dict[str, str]] = None,
        scope_validator: Optional[Any] = None,
        max_steps: int = 12,
        history_chars: int = 4000,
        verifier: Optional[Callable[[], Awaitable[bool]]] = None,
        enable_browser: bool = True,
    ):
        self.target = target.rstrip("/")
        self.harness = harness
        self.max_steps = max_steps
        self.history_chars = history_chars
        self.verifier = verifier
        self.enable_browser = enable_browser
        self.act = Actuators(self.target, auth_headers, scope_validator=scope_validator)
        self._browser = BrowserActuator(scope_validator=scope_validator) if enable_browser else None
        self.findings: List[Dict[str, Any]] = []

    async def _dispatch(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if tool == "http_request":
                return await self.act.http_request(
                    args.get("method", "GET"), args.get("path", "/"),
                    headers=args.get("headers"), json_body=args.get("json_body"),
                    data=args.get("data"), params=args.get("params"))
            if tool == "jwt_decode":
                return self.act.jwt_decode(args.get("token", ""))
            if tool == "jwt_forge":
                return self.act.jwt_forge(args.get("payload", {}), args.get("alg", "none"), args.get("key", ""))
            if tool == "encode":
                return self.act.encode(args.get("text", ""), args.get("scheme", "base64"))
            if tool == "decode":
                return self.act.decode(args.get("text", ""), args.get("scheme", "base64"))
            if tool == "upload_file":
                return await self.act.upload_file(
                    args.get("path", "/"), args.get("filename", "x"),
                    args.get("content", ""), args.get("content_type", "application/octet-stream"))
            if tool == "browser_run":
                if not self._browser:
                    return {"error": "browser disabled"}
                return await self._browser.run_actions(args.get("actions", []))
            if tool == "report_finding":
                finding = {
                    "type": str(args.get("type", "AGENT_FINDING")).upper(),
                    "severity": str(args.get("severity", "MEDIUM")).upper(),
                    "title": args.get("title", "Agent-reported finding"),
                    "location": self.target,
                    "evidence": args.get("evidence", ""),
                    "proof": str(args.get("evidence", "")),
                    "tool": "objective_agent", "source": "objective_agent",
                    "exploited": True, "confidence_score": 0.8,
                }
                self.findings.append(finding)
                return {"recorded": True, "finding": finding["title"]}
            return {"error": f"unknown tool {tool}"}
        except Exception as e:
            return {"error": str(e)}

    def _build_prompt(self, objective: str, hint: str, context: str,
                      history: List[Dict[str, Any]]) -> str:
        hist = json.dumps(history, default=str)[-self.history_chars:]
        return (
            f"OBJECTIVE: {objective}\n"
            f"TARGET: {self.target}\n"
            + (f"HINT: {hint}\n" if hint else "")
            + (f"CONTEXT: {context}\n" if context else "")
            + f"\nACTIONS SO FAR (most recent last):\n{hist or '(none yet)'}\n\n"
            + _ACTION_SPEC
            + "\nChoose the single best next action."
        )

    async def _manual_guidance(self, objective: str, history: List[Dict[str, Any]]) -> str:
        if self.harness is None or not history:
            return ""
        try:
            hist = json.dumps(history, default=str)[-3000:]
            prompt = (
                f"An automated agent tried but FAILED to exploit this objective:\n{objective}\n\n"
                f"Actions it took and the responses:\n{hist}\n\n"
                "In 2-4 short sentences, tell a human pentester: (1) the most promising lead "
                "from these responses, and (2) the concrete next manual steps to try. Be specific."
            )
            return await self.harness.generate_text(prompt, max_tokens=300)
        except Exception:
            return ""

    def _record_review(self, objective: str, category: str, result: Dict[str, Any],
                       manual_guidance: str = "", scan_id: str = "") -> None:
        try:
            from core.reporting.review_queue import (
                get_review_queue, STATUS_SUCCESS, STATUS_NEEDS_MANUAL)
            q = get_review_queue()
            tried = " | ".join(
                f"{h.get('tool')}({json.dumps(h.get('args', {}), default=str)[:120]})"
                for h in result.get("history", [])
            )
            if result.get("success") or result.get("findings"):
                for f in (result.get("findings") or [{"title": objective, "severity": "MEDIUM"}]):
                    q.record(
                        target=self.target, title=f.get("title", objective),
                        status=STATUS_SUCCESS, category=category,
                        severity=f.get("severity", ""), steps=result.get("steps", 0),
                        evidence=str(f.get("evidence", "")), tried_summary=tried,
                        history=result.get("history", []), scan_id=scan_id,
                    )
            else:
                q.record(
                    target=self.target, title=objective, status=STATUS_NEEDS_MANUAL,
                    category=category, steps=result.get("steps", 0), tried_summary=tried,
                    manual_guidance=manual_guidance, history=result.get("history", []),
                    scan_id=scan_id,
                )
        except Exception as e:
            logger.debug(f"[AgentLoop] review-queue record failed: {e}")

    async def run(self, objective: str, hint: str = "", context: str = "",
                  category: str = "", record: bool = True, scan_id: str = "") -> Dict[str, Any]:
        if self.harness is None:
            return {"success": False, "steps": 0, "findings": [], "history": []}

        try:
            from agents.universal_llm_harness import TaskTier
            tier = TaskTier.LARGE
        except Exception:
            tier = None

        history: List[Dict[str, Any]] = []
        for step in range(self.max_steps):
            prompt = self._build_prompt(objective, hint, context, history)
            try:
                decision = (await self.harness.generate_json(prompt, system=_SYSTEM, tier=tier)
                            if tier is not None else
                            await self.harness.generate_json(prompt, system=_SYSTEM))
            except Exception as e:
                logger.debug(f"[AgentLoop] planning error step {step}: {e}")
                break
            if not decision or decision.get("done"):
                break
            tool = decision.get("tool")
            if not tool:
                break
            args = decision.get("args", {}) or {}
            obs = await self._dispatch(tool, args)
            # Truncate large observations to save LLM tokens.
            obs_s = json.dumps(obs, default=str)
            if len(obs_s) > 4000:
                obs = {"truncated": obs_s[:3900] + "…", "full_len": len(obs_s)}
            history.append({"tool": tool, "args": args, "obs": obs})

            # Pluggable success check (e.g. benchmark oracle).
            if self.verifier is not None:
                try:
                    if await self.verifier():
                        logger.info(f"[AgentLoop] objective verified after {step + 1} steps")
                        res = {"success": True, "steps": step + 1,
                               "findings": self.findings, "history": history}
                        if record:
                            self._record_review(objective, category, res, scan_id=scan_id)
                        return res
                except Exception:
                    pass

        # No external verifier → success is whether the agent demonstrated a finding.
        success = bool(self.findings) if self.verifier is None else False
        res = {"success": success, "steps": len(history),
               "findings": self.findings, "history": history}
        if record:
            guidance = "" if success else await self._manual_guidance(objective, history)
            self._record_review(objective, category, res, manual_guidance=guidance, scan_id=scan_id)
        return res
