"""P1-19 — Domain-aware workflow generator.

Uses the inferred domain model (AppUnderstanding entities, state transitions,
roles) plus captured request data to auto-generate multi-step BrowserWorkflows
for business-logic security testing.

The generator is domain-independent: it reads whatever entities/transitions the
AppUnderstandingEngine inferred (ecommerce cart→checkout, healthcare
appointment→prescription, banking transfer→confirm, etc.) and builds
executable browser workflows from them.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from core.workflows.browser_workflows import (
    BrowserWorkflow, WorkflowStep, StepOutcome,
    create_login_workflow,
)

logger = logging.getLogger(__name__)

_ENTITY_ACTION_MAP = {
    "create": "fill",
    "add": "click",
    "submit": "click",
    "update": "fill",
    "delete": "click",
    "confirm": "click",
    "approve": "click",
    "reject": "click",
    "cancel": "click",
    "checkout": "click",
    "pay": "click",
    "transfer": "click",
    "login": "fill",
    "register": "fill",
    "signup": "fill",
    "search": "fill",
    "upload": "click",
    "download": "click",
    "view": "navigate",
    "list": "navigate",
    "navigate": "navigate",
}


def _action_for_verb(verb: str) -> str:
    v = verb.lower().strip()
    return _ENTITY_ACTION_MAP.get(v, "click")


class WorkflowGenerator:
    """Generates BrowserWorkflows from domain model artifacts."""

    def __init__(self, target_url: str, understanding: Any = None,
                 captured_requests: Optional[List[Any]] = None,
                 credentials: Optional[Dict[str, str]] = None):
        self.target_url = target_url.rstrip("/")
        self.understanding = understanding
        self.captured = captured_requests or []
        self.credentials = credentials or {}

    def generate_all(self) -> List[BrowserWorkflow]:
        workflows: List[BrowserWorkflow] = []
        workflows.extend(self._from_state_transitions())
        workflows.extend(self._from_entities())
        workflows.extend(self._from_captured_flows())
        if not workflows:
            workflows.extend(self._generic_workflows())
        return workflows

    def _from_state_transitions(self) -> List[BrowserWorkflow]:
        if not self.understanding:
            return []
        transitions = getattr(self.understanding, "state_transitions", []) or []
        if not transitions:
            return []

        workflows = []
        grouped: Dict[str, List[Dict]] = {}
        for t in transitions:
            entity = t.get("entity", "") or t.get("resource", "") or "resource"
            grouped.setdefault(entity, []).append(t)

        for entity, chain in grouped.items():
            steps = []
            steps.append(WorkflowStep(
                step_id=f"nav_{entity}",
                action="navigate",
                description=f"Navigate to {entity} area",
                url=self.target_url,
                timeout_ms=15000,
            ))

            for i, t in enumerate(chain[:10]):
                from_state = t.get("from_state", t.get("from", ""))
                to_state = t.get("to_state", t.get("to", ""))
                action_verb = t.get("action", t.get("trigger", "click"))
                step_action = _action_for_verb(action_verb)

                desc = f"{action_verb}: {from_state} → {to_state}" if from_state else action_verb
                steps.append(WorkflowStep(
                    step_id=f"step_{entity}_{i}",
                    action=step_action,
                    description=desc,
                    selector=t.get("selector", ""),
                    value=t.get("value", ""),
                    url=t.get("url", ""),
                    timeout_ms=int(t.get("timeout_ms", 8000)),
                    evidence_capture=True,
                ))

            steps.append(WorkflowStep(
                step_id=f"verify_{entity}",
                action="eval",
                description=f"Verify {entity} final state",
                script="JSON.stringify({url: location.href, title: document.title, body: document.body.innerText.substring(0, 1000)})",
                evidence_capture=True,
            ))

            workflows.append(BrowserWorkflow(
                name=f"{entity.title()} State Flow",
                workflow_type="state_transition",
                target_url=self.target_url,
                steps=steps,
                metadata={"entity": entity, "transitions": len(chain)},
            ))

        return workflows

    def _from_entities(self) -> List[BrowserWorkflow]:
        if not self.understanding:
            return []
        entities = getattr(self.understanding, "entities", []) or []
        if not entities:
            return []

        workflows = []
        for ent in entities[:8]:
            name = ent.get("name", "") or ent.get("entity", "")
            if not name:
                continue
            operations = ent.get("operations", []) or ent.get("actions", []) or ["view", "create"]

            steps = [WorkflowStep(
                step_id=f"nav_{name}",
                action="navigate",
                description=f"Navigate to {name}",
                url=self.target_url,
                timeout_ms=15000,
            )]

            for j, op in enumerate(operations[:6]):
                op_name = op if isinstance(op, str) else op.get("name", "view")
                steps.append(WorkflowStep(
                    step_id=f"{name}_{op_name}_{j}",
                    action=_action_for_verb(op_name),
                    description=f"{op_name} {name}",
                    evidence_capture=True,
                ))

            steps.append(WorkflowStep(
                step_id=f"verify_{name}",
                action="eval",
                description=f"Capture {name} state",
                script="JSON.stringify({url: location.href, cookies: document.cookie, body: document.body.innerText.substring(0, 500)})",
                evidence_capture=True,
            ))

            workflows.append(BrowserWorkflow(
                name=f"{name.title()} CRUD Flow",
                workflow_type="entity_crud",
                target_url=self.target_url,
                steps=steps,
                metadata={"entity": name},
            ))

        return workflows

    def _from_captured_flows(self) -> List[BrowserWorkflow]:
        if len(self.captured) < 3:
            return []

        api_reqs = []
        for r in self.captured:
            method = r.get("method", "") if isinstance(r, dict) else getattr(r, "method", "")
            rtype = r.get("resource_type", "") if isinstance(r, dict) else getattr(r, "resource_type", "")
            if method in ("POST", "PUT", "PATCH", "DELETE") or rtype in ("xhr", "fetch"):
                api_reqs.append(r)

        if len(api_reqs) < 2:
            return []

        steps = [WorkflowStep(
            step_id="nav_start",
            action="navigate",
            description="Navigate to target",
            url=self.target_url,
            timeout_ms=15000,
        )]

        for i, req in enumerate(api_reqs[:12]):
            url = req.get("url", "") if isinstance(req, dict) else getattr(req, "url", "")
            method = req.get("method", "GET") if isinstance(req, dict) else getattr(req, "method", "GET")
            steps.append(WorkflowStep(
                step_id=f"api_{i}",
                action="eval",
                description=f"{method} {url.split('?')[0][-60:]}",
                script=self._build_fetch_script(req),
                evidence_capture=True,
            ))

        steps.append(WorkflowStep(
            step_id="verify_final",
            action="eval",
            description="Capture final state",
            script="JSON.stringify({url: location.href, cookies: document.cookie})",
            evidence_capture=True,
        ))

        return [BrowserWorkflow(
            name="Captured API Flow",
            workflow_type="captured_replay",
            target_url=self.target_url,
            steps=steps,
            metadata={"api_requests": len(api_reqs)},
        )]

    def _build_fetch_script(self, req: Any) -> str:
        if isinstance(req, dict):
            url = req.get("url", "")
            method = req.get("method", "GET")
            body = req.get("post_data", "")
        else:
            url = getattr(req, "url", "")
            method = getattr(req, "method", "GET")
            body = getattr(req, "post_data", "")

        parts = [f"fetch('{url}', {{method: '{method}'"]
        if body and method != "GET":
            safe_body = body.replace("'", "\\'").replace("\n", "\\n")[:500]
            parts.append(f", body: '{safe_body}'")
            parts.append(", headers: {'Content-Type': 'application/json'}")
        parts.append("}).then(r => r.status + ' ' + r.statusText).catch(e => 'ERR:' + e)")
        return "".join(parts)

    def _generic_workflows(self) -> List[BrowserWorkflow]:
        workflows = []
        if self.credentials.get("username") and self.credentials.get("password"):
            workflows.append(create_login_workflow(
                self.target_url,
                self.credentials["username"],
                self.credentials["password"],
            ))

        workflows.append(BrowserWorkflow(
            name="Anonymous Navigation Flow",
            workflow_type="navigation",
            target_url=self.target_url,
            steps=[
                WorkflowStep("nav_home", "navigate", "Navigate to home",
                             url=self.target_url, timeout_ms=15000),
                WorkflowStep("capture_links", "eval", "Discover navigation",
                             script="JSON.stringify(Array.from(document.querySelectorAll('a[href]')).slice(0, 20).map(a => ({href: a.href, text: a.innerText.trim().substring(0, 50)})))",
                             evidence_capture=True),
                WorkflowStep("capture_forms", "eval", "Discover forms",
                             script="JSON.stringify(Array.from(document.querySelectorAll('form')).map(f => ({action: f.action, method: f.method, inputs: Array.from(f.querySelectorAll('input,select,textarea')).map(i => ({name: i.name, type: i.type}))})))",
                             evidence_capture=True),
                WorkflowStep("capture_state", "eval", "Capture app state",
                             script="JSON.stringify({cookies: document.cookie, localStorage: Object.keys(localStorage), sessionStorage: Object.keys(sessionStorage)})",
                             evidence_capture=True),
            ],
        ))

        return workflows
