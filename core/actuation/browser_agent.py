"""P3: LLM-Driven Browser Agent — client-side validation bypass, DOM XSS, CSRF, hidden fields."""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BrowserGoal:
    url: str
    goal: str
    success_criteria: str
    category: str = ""  # "validation_bypass", "xss", "hidden_field", "csrf", "state_manipulation"
    max_steps: int = 15
    cwe: str = ""
    severity: str = "HIGH"


@dataclass
class AgentStep:
    action: str
    selector: str = ""
    value: str = ""
    reasoning: str = ""
    result: str = ""
    screenshot: str = ""  # base64 if captured


@dataclass
class AgentResult:
    goal: BrowserGoal
    steps: List[AgentStep] = field(default_factory=list)
    succeeded: bool = False
    evidence: str = ""
    finding: Optional[Dict[str, Any]] = None
    error: str = ""


GOAL_TEMPLATES: List[BrowserGoal] = [
    BrowserGoal(
        url="", goal="Find forms with client-side validation (disabled buttons, required/maxlength/pattern attributes). "
                      "Remove those attributes via DOM manipulation and submit invalid data. Check if server accepts it.",
        success_criteria="Server returns 200/201 for data that client-side validation would have blocked",
        category="validation_bypass", cwe="CWE-602", severity="HIGH",
    ),
    BrowserGoal(
        url="", goal="Find hidden form fields (type=hidden, display:none). Modify their values "
                      "(user IDs, role fields, price fields, CSRF tokens) and submit the form.",
        success_criteria="Server accepts the modified hidden field value and changes behavior",
        category="hidden_field", cwe="CWE-472", severity="HIGH",
    ),
    BrowserGoal(
        url="", goal="Inject XSS payloads into all input fields, URL parameters, and URL fragments. "
                      "Payloads: <script>alert(1)</script>, <img src=x onerror=alert(1)>, "
                      "javascript:alert(1), <svg/onload=alert(1)>. Check DOM for payload execution.",
        success_criteria="XSS payload appears unescaped in DOM or triggers console alert/error event",
        category="xss", cwe="CWE-79", severity="HIGH",
    ),
    BrowserGoal(
        url="", goal="Check localStorage/sessionStorage for role flags, auth tokens, or feature flags. "
                      "Modify them (set role=admin, isAdmin=true, premium=true) and reload the page. "
                      "Check if new UI or functionality is exposed.",
        success_criteria="Modified storage value changes page behavior, reveals admin UI, or grants new permissions",
        category="state_manipulation", cwe="CWE-602", severity="HIGH",
    ),
    BrowserGoal(
        url="", goal="Find price/quantity/discount fields in forms. Change values to negative numbers, "
                      "zero, or very large numbers via DOM manipulation or direct input. Submit and check response.",
        success_criteria="Server accepts negative price or zero-cost purchase",
        category="business_logic", cwe="CWE-20", severity="CRITICAL",
    ),
]


BROWSER_AGENT_PROMPT = """You are a security testing browser agent. Your goal: {goal}

Current page URL: {url}
Page DOM (interactive elements):
{dom_tree}

Steps taken so far:
{history}

Console messages:
{console}

Success criteria: {success_criteria}

Respond as JSON:
{{
  "action": "click|type|evaluate|modify_attr|remove_attr|set_storage|navigate|screenshot|done",
  "selector": "CSS selector for the target element",
  "value": "value to type or set",
  "reasoning": "why this action"
}}

Rules:
- Only interact with elements visible in the DOM tree
- Use evaluate for arbitrary JS: document.querySelector(...).removeAttribute(...)
- Use modify_attr/remove_attr for DOM manipulation
- Use set_storage for localStorage/sessionStorage changes
- Return {{"action": "done", "reasoning": "..."}} when goal is achieved or impossible
- Be methodical — try different payloads if one fails"""


class BrowserAgent:
    MAX_GOALS = 10

    def __init__(self, ctx=None, llm_client=None):
        self.ctx = ctx
        self.llm_client = llm_client
        self._findings: List[Dict[str, Any]] = []
        self._goals_tested = 0

    async def _get_llm(self):
        if self.llm_client:
            return self.llm_client
        from agents.universal_llm_harness import get_llm_client
        self.llm_client = get_llm_client()
        return self.llm_client

    def generate_goals(self) -> List[BrowserGoal]:
        """Generate browser testing goals from context."""
        target = getattr(self.ctx, "target", "") if self.ctx else ""
        if not target:
            return []

        goals = []
        for template in GOAL_TEMPLATES:
            goal = BrowserGoal(
                url=target,
                goal=template.goal,
                success_criteria=template.success_criteria,
                category=template.category,
                max_steps=template.max_steps,
                cwe=template.cwe,
                severity=template.severity,
            )
            goals.append(goal)

        # Add goals for specific discovered forms/pages. ctx.endpoints may be a
        # dict ({url: meta}) — slicing a dict raises TypeError(slice(None,20,None)),
        # so normalize to a list first.
        _eps = getattr(self.ctx, "endpoints", []) or []
        if isinstance(_eps, dict):
            _eps = list(_eps.keys())
        for ep in list(_eps)[:20]:
            url = ep if isinstance(ep, str) else (
                ep.get("url", "") if isinstance(ep, dict) else getattr(ep, "url", "") or "")
            if not url:
                continue
            try:
                from core.common import target_shape as ts
                _privileged = ts.is_privileged_path(url)
            except Exception:
                path_lower = url.lower()
                _privileged = any(kw in path_lower for kw in
                                  ("/admin", "/dashboard", "/settings", "/profile"))
            if _privileged:
                goals.append(BrowserGoal(
                    url=url,
                    goal=f"Navigate to {url}. Check if admin/restricted content is accessible. "
                         f"Try modifying client-side route guards or role checks.",
                    success_criteria="Admin content visible or route guard bypassed",
                    category="route_bypass", cwe="CWE-602", severity="CRITICAL",
                ))

        logger.info(f"[BrowserAgent] Generated {len(goals)} testing goals")
        return goals[:self.MAX_GOALS]

    async def execute_goal(self, goal: BrowserGoal) -> AgentResult:
        """Execute a single browser testing goal with LLM reasoning loop."""
        self._goals_tested += 1
        result = AgentResult(goal=goal)

        # Scope check
        try:
            from core.security.authorization import TargetScopeValidator
            from urllib.parse import urlparse
            host = urlparse(goal.url).hostname
            if host and not TargetScopeValidator.get().is_authorized(host):
                result.error = "out of scope"
                return result
        except Exception:
            result.error = "scope check failed — rejecting (fail-closed)"
            return result

        try:
            from core.actuation.browser_actuator import BrowserActuator
            # Drive the SPA AUTHENTICATED — inject the logged-in session (JWT in
            # localStorage + Authorization header + cookies) so DOM XSS / business
            # logic behind login are reachable.
            actuator = BrowserActuator(auth=BrowserActuator.auth_from_ctx(self.ctx))
        except Exception as e:
            result.error = f"Browser unavailable: {e}"
            return result

        llm = await self._get_llm()

        # Navigate to target
        try:
            nav_result = await actuator.run_actions([
                {"action": "navigate", "url": goal.url},
            ])
        except Exception as e:
            result.error = f"Navigation failed: {e}"
            return result

        history = []

        for step_num in range(goal.max_steps):
            # Get current DOM state
            try:
                dom_result = await actuator.run_actions([
                    {"action": "evaluate", "expression": """
                        (() => {
                            const els = document.querySelectorAll('input, button, select, textarea, a, form, [role="button"]');
                            return Array.from(els).slice(0, 50).map(el => ({
                                tag: el.tagName, type: el.type || '', name: el.name || '',
                                id: el.id || '', value: el.value || '',
                                hidden: el.type === 'hidden' || getComputedStyle(el).display === 'none',
                                disabled: el.disabled, required: el.required,
                                href: el.href || '', text: el.textContent?.trim()?.slice(0, 50) || '',
                                attrs: Object.fromEntries(Array.from(el.attributes).map(a => [a.name, a.value]).slice(0, 10)),
                            }));
                        })()
                    """},
                ])
                dom_tree = json.dumps(dom_result, default=str)[:3000] if dom_result else "[]"
            except Exception:
                dom_tree = "[]"

            # Get console messages
            try:
                console_result = await actuator.run_actions([
                    {"action": "evaluate", "expression": "window.__console_log || '[]'"},
                ])
                console = str(console_result)[:500] if console_result else ""
            except Exception:
                console = ""

            # Ask LLM for next action
            history_text = "\n".join(
                f"Step {i+1}: {s.action} on '{s.selector}' = {s.result[:100]}"
                for i, s in enumerate(result.steps)
            ) or "None yet"

            prompt = BROWSER_AGENT_PROMPT.format(
                goal=goal.goal, url=goal.url, dom_tree=dom_tree,
                history=history_text, console=console,
                success_criteria=goal.success_criteria,
            )

            try:
                from core.common.schemas import TaskTier
                resp = await llm.generate_response(
                    prompt,
                    tier=TaskTier.SMALL,
                    temperature=0.2,
                )
                action_data = self._parse_action(resp.content)
            except Exception as e:
                logger.debug(f"[BrowserAgent] LLM failed: {e}")
                break

            if not action_data or action_data.get("action") == "done":
                if action_data:
                    result.evidence = action_data.get("reasoning", "")
                break

            # Execute the action
            step = AgentStep(
                action=action_data.get("action", ""),
                selector=action_data.get("selector", ""),
                value=action_data.get("value", ""),
                reasoning=action_data.get("reasoning", ""),
            )

            try:
                action_result = await self._execute_browser_action(actuator, action_data)
                step.result = str(action_result)[:500]
            except Exception as e:
                step.result = f"Error: {e}"

            result.steps.append(step)

            # Check for XSS indicators in console
            if "alert" in step.result.lower() or "xss" in step.result.lower():
                result.succeeded = True
                result.evidence = f"XSS triggered: {step.result[:200]}"
                break

        # Evaluate if goal was achieved
        if not result.succeeded and result.steps:
            result.succeeded = await self._evaluate_success(result, goal)

        if result.succeeded:
            result.finding = self._build_finding(result)
            self._findings.append(result.finding)

        return result

    async def _execute_browser_action(self, actuator, action_data: Dict) -> Any:
        """Map LLM action to BrowserActuator call."""
        action = action_data.get("action", "")
        selector = action_data.get("selector", "")
        value = action_data.get("value", "")

        if action == "click":
            return await actuator.run_actions([{"action": "click", "selector": selector}])
        elif action == "type":
            return await actuator.run_actions([
                {"action": "click", "selector": selector},
                {"action": "fill", "selector": selector, "value": value},
            ])
        elif action == "evaluate":
            return await actuator.run_actions([{"action": "evaluate", "expression": value}])
        elif action == "modify_attr":
            expr = f'document.querySelector("{selector}")?.setAttribute("{action_data.get("attr", "")}", "{value}")'
            return await actuator.run_actions([{"action": "evaluate", "expression": expr}])
        elif action == "remove_attr":
            expr = f'document.querySelector("{selector}")?.removeAttribute("{value}")'
            return await actuator.run_actions([{"action": "evaluate", "expression": expr}])
        elif action == "set_storage":
            expr = f'localStorage.setItem("{selector}", "{value}")'
            return await actuator.run_actions([{"action": "evaluate", "expression": expr}])
        elif action == "navigate":
            return await actuator.run_actions([{"action": "navigate", "url": value}])
        elif action == "screenshot":
            return await actuator.run_actions([{"action": "screenshot"}])
        return None

    async def _evaluate_success(self, result: AgentResult, goal: BrowserGoal) -> bool:
        """LLM evaluates if goal was achieved from step history."""
        try:
            llm = await self._get_llm()
            from core.common.schemas import TaskTier

            steps_summary = "\n".join(
                f"Step {i+1}: {s.action} on '{s.selector}' → {s.result[:150]}"
                for i, s in enumerate(result.steps)
            )

            resp = await llm.generate_response(
                (
                    f"Goal: {goal.goal}\n"
                    f"Success criteria: {goal.success_criteria}\n"
                    f"Steps taken:\n{steps_summary}\n\n"
                    f"Was the goal achieved? Respond with JSON: "
                    f'{{"achieved": true/false, "evidence": "what proves it"}}'
                ),
                tier=TaskTier.SMALL,
                temperature=0.1,
            )
            data = self._parse_action(resp.content)
            if data and data.get("achieved"):
                result.evidence = data.get("evidence", "")
                return True
        except Exception:
            pass
        return False

    def _parse_action(self, raw: str) -> Optional[Dict[str, Any]]:
        try:
            text = raw
            if "```json" in raw:
                text = raw.split("```json")[1].split("```")[0]
            elif "```" in raw:
                text = raw.split("```")[1].split("```")[0]
            return json.loads(text)
        except (json.JSONDecodeError, IndexError):
            return None

    def _build_finding(self, result: AgentResult) -> Dict[str, Any]:
        goal = result.goal
        return {
            "finding_id": str(uuid.uuid4()),
            "title": f"Client-Side {goal.category.replace('_', ' ').title()}: {goal.url}",
            "type": f"Client-Side {goal.category.replace('_', ' ').title()}",
            "description": (
                f"Browser agent achieved goal '{goal.goal[:100]}' on {goal.url}. "
                f"Evidence: {result.evidence[:200]}"
            ),
            "severity": goal.severity,
            "confidence_score": 0.75,
            "target": getattr(self.ctx, "target", ""),
            "location": goal.url,
            "evidence": result.evidence[:500],
            "cwe": goal.cwe,
            "source": "browser_agent",
            "tool": "p3_browser_agent",
            "attack_type": goal.category,
            "status": "confirmed",
            "remediation": (
                "Never rely on client-side validation alone. Enforce all security "
                "checks server-side. Sanitize and validate all input on the backend."
            ),
        }

    async def run_all(self) -> List[Dict[str, Any]]:
        """Generate and execute all browser testing goals."""
        goals = self.generate_goals()
        if not goals:
            return []

        for goal in goals:
            try:
                await self.execute_goal(goal)
            except Exception as e:
                logger.warning(f"[BrowserAgent] Goal failed: {e}")

        if self._findings:
            try:
                from core.reporting.finding_factory import get_finding_factory
                await get_finding_factory().enrich_batch(self._findings)
            except Exception as e:
                logger.debug(f"[BrowserAgent] Batch enrichment failed: {e}")

        logger.info(f"[BrowserAgent] Tested {self._goals_tested} goals, "
                    f"{len(self._findings)} findings")
        return self._findings

    @property
    def findings(self) -> List[Dict[str, Any]]:
        return self._findings

    def stats(self) -> Dict[str, Any]:
        return {
            "goals_tested": self._goals_tested,
            "findings": len(self._findings),
        }


async def run_browser_agent(ctx) -> List[Dict[str, Any]]:
    """Convenience function for central_brain integration."""
    if not getattr(ctx, "target", ""):
        return []
    agent = BrowserAgent(ctx=ctx)
    return await agent.run_all()
