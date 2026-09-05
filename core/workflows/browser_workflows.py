"""
Browser Workflow Definitions (Phase 19).

Declarative workflow models for multi-step browser interactions.
Each workflow is a sequence of steps with preconditions, expected
outcomes, and evidence capture points. The BrowserActuator executes
the steps; this module defines what to execute and how to verify.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class WorkflowState(str, Enum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    STEP_FAILED = "STEP_FAILED"
    COMPLETED = "COMPLETED"
    ABORTED = "ABORTED"


class StepOutcome(str, Enum):
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass
class WorkflowStep:
    step_id: str
    action: str
    description: str = ""
    selector: str = ""
    value: str = ""
    url: str = ""
    script: str = ""
    timeout_ms: int = 8000
    expected_signal: str = ""
    evidence_capture: bool = False
    outcome: StepOutcome = StepOutcome.PENDING
    error: str = ""
    evidence_id: str = ""

    def to_action(self) -> Dict[str, Any]:
        a: Dict[str, Any] = {"action": self.action}
        if self.url:
            a["url"] = self.url
        if self.selector:
            a["selector"] = self.selector
        if self.value:
            a["value"] = self.value
        if self.script:
            a["script"] = self.script
        a["timeout"] = self.timeout_ms
        return a


@dataclass
class BrowserWorkflow:
    workflow_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    workflow_type: str = ""
    target_url: str = ""
    identity_id: str = ""
    steps: List[WorkflowStep] = field(default_factory=list)
    state: WorkflowState = WorkflowState.CREATED
    preconditions: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def get_actions(self) -> List[Dict[str, Any]]:
        return [s.to_action() for s in self.steps if s.outcome == StepOutcome.PENDING]

    def mark_step(self, step_id: str, outcome: StepOutcome,
                  error: str = "", evidence_id: str = "") -> None:
        for s in self.steps:
            if s.step_id == step_id:
                s.outcome = outcome
                s.error = error
                s.evidence_id = evidence_id
                if evidence_id:
                    self.evidence_ids.append(evidence_id)
                return

    def is_complete(self) -> bool:
        return all(s.outcome != StepOutcome.PENDING for s in self.steps)

    def has_failures(self) -> bool:
        return any(s.outcome == StepOutcome.FAILED for s in self.steps)


# --- Workflow Factories ---

def create_login_workflow(
    login_url: str,
    username: str,
    password: str,
    username_selector: str = "input[name='email'], input[name='username'], input[type='email']",
    password_selector: str = "input[name='password'], input[type='password']",
    submit_selector: str = "button[type='submit'], input[type='submit']",
    identity_id: str = "",
) -> BrowserWorkflow:
    return BrowserWorkflow(
        name="Multi-Step Login",
        workflow_type="login",
        target_url=login_url,
        identity_id=identity_id,
        steps=[
            WorkflowStep("login_nav", "navigate", "Navigate to login",
                         url=login_url, timeout_ms=15000),
            WorkflowStep("login_user", "fill", "Enter username",
                         selector=username_selector, value=username),
            WorkflowStep("login_pass", "fill", "Enter password",
                         selector=password_selector, value=password),
            WorkflowStep("login_submit", "click", "Submit login",
                         selector=submit_selector),
            WorkflowStep("login_wait", "wait", "Wait for redirect",
                         timeout_ms=3000),
            WorkflowStep("login_verify", "eval", "Verify login success",
                         script="document.cookie.includes('token') || document.cookie.includes('session') || !document.querySelector('input[type=\"password\"]')",
                         expected_signal="true", evidence_capture=True),
            WorkflowStep("login_url", "eval", "Capture final URL",
                         script="window.location.href", evidence_capture=True),
        ],
    )


def create_admin_workflow(
    admin_url: str,
    identity_id: str = "",
) -> BrowserWorkflow:
    return BrowserWorkflow(
        name="Admin Panel Access",
        workflow_type="admin_access",
        target_url=admin_url,
        identity_id=identity_id,
        steps=[
            WorkflowStep("admin_nav", "navigate", "Navigate to admin panel",
                         url=admin_url, timeout_ms=15000),
            WorkflowStep("admin_check_auth", "eval", "Check authentication state",
                         script="document.querySelector('.login-form, input[type=\"password\"]') ? 'login_required' : 'accessible'",
                         expected_signal="accessible", evidence_capture=True),
            WorkflowStep("admin_check_priv", "eval", "Verify admin privileges",
                         script="document.body.innerText.substring(0, 2000)",
                         evidence_capture=True),
            WorkflowStep("admin_dom", "dom", "Capture admin DOM",
                         evidence_capture=True),
        ],
    )


def create_file_upload_workflow(
    upload_url: str,
    file_selector: str = "input[type='file']",
    submit_selector: str = "button[type='submit']",
    identity_id: str = "",
) -> BrowserWorkflow:
    return BrowserWorkflow(
        name="File Upload Test",
        workflow_type="file_upload",
        target_url=upload_url,
        identity_id=identity_id,
        steps=[
            WorkflowStep("upload_nav", "navigate", "Navigate to upload page",
                         url=upload_url, timeout_ms=15000),
            WorkflowStep("upload_before", "dom", "Capture pre-upload DOM",
                         evidence_capture=True),
            WorkflowStep("upload_submit", "click", "Submit upload form",
                         selector=submit_selector),
            WorkflowStep("upload_wait", "wait", "Wait for upload processing",
                         timeout_ms=5000),
            WorkflowStep("upload_after", "dom", "Capture post-upload DOM",
                         evidence_capture=True),
            WorkflowStep("upload_result", "eval", "Check upload result",
                         script="document.body.innerText.substring(0, 2000)",
                         expected_signal="success|uploaded|saved", evidence_capture=True),
        ],
    )


def create_csrf_workflow(
    target_url: str,
    action_selector: str = "form",
    identity_id: str = "",
) -> BrowserWorkflow:
    return BrowserWorkflow(
        name="CSRF Verification",
        workflow_type="csrf",
        target_url=target_url,
        identity_id=identity_id,
        steps=[
            WorkflowStep("csrf_nav", "navigate", "Navigate to target",
                         url=target_url, timeout_ms=15000),
            WorkflowStep("csrf_before", "eval", "Capture pre-action state",
                         script="JSON.stringify({url: location.href, cookies: document.cookie, title: document.title})",
                         evidence_capture=True),
            WorkflowStep("csrf_check_token", "eval", "Check for CSRF token",
                         script="!!document.querySelector('input[name*=\"csrf\"], input[name*=\"token\"], meta[name*=\"csrf\"]')",
                         expected_signal="true", evidence_capture=True),
            WorkflowStep("csrf_submit_no_token", "eval",
                         "Attempt action without CSRF token",
                         script="""
(function() {
    var form = document.querySelector('SELECTOR');
    if (!form) return 'no_form';
    var tokenInput = form.querySelector('input[name*="csrf"], input[name*="token"]');
    if (tokenInput) tokenInput.value = '';
    return 'token_cleared';
})()
""".replace("SELECTOR", action_selector),
                         evidence_capture=True),
            WorkflowStep("csrf_after", "eval", "Capture post-action state",
                         script="JSON.stringify({url: location.href, cookies: document.cookie, title: document.title})",
                         evidence_capture=True),
        ],
    )


def create_token_refresh_workflow(
    api_base_url: str,
    token_endpoint: str = "/api/token",
    refresh_endpoint: str = "/api/token/refresh",
    identity_id: str = "",
) -> BrowserWorkflow:
    return BrowserWorkflow(
        name="API Token Refresh",
        workflow_type="token_refresh",
        target_url=api_base_url,
        identity_id=identity_id,
        steps=[
            WorkflowStep("token_nav", "navigate", "Navigate to API base",
                         url=api_base_url, timeout_ms=15000),
            WorkflowStep("token_obtain", "eval", "Obtain initial token",
                         script=f"fetch('{token_endpoint}').then(r=>r.json()).then(d=>JSON.stringify(d)).catch(e=>'ERR:'+e)",
                         evidence_capture=True),
            WorkflowStep("token_use", "eval", "Use token for API call",
                         script="localStorage.getItem('token') || sessionStorage.getItem('token') || 'no_stored_token'",
                         evidence_capture=True),
            WorkflowStep("token_refresh", "eval", "Attempt token refresh",
                         script=f"fetch('{refresh_endpoint}', {{method:'POST'}}).then(r=>r.status+' '+r.statusText).catch(e=>'ERR:'+e)",
                         evidence_capture=True),
            WorkflowStep("token_expired_test", "eval", "Test with expired token",
                         script="'expired_token_test_placeholder'",
                         evidence_capture=True),
        ],
    )
