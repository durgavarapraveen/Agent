"""P1-19 — Workflow executor with negative test case generation.

Drives BrowserWorkflows through BrowserActuator, captures the request/response
pairs per workflow, builds state machines via WorkflowCrawler, generates
negative test cases (skip-step, reorder, replay, direct-access-final), and
executes those negative cases to find business-logic vulnerabilities.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class WorkflowResult:
    workflow_name: str
    workflow_type: str
    steps_total: int = 0
    steps_succeeded: int = 0
    steps_failed: int = 0
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    negative_cases_run: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""


class WorkflowExecutor:
    """Executes BrowserWorkflows and their negative test cases."""

    def __init__(self, target_url: str, scan_id: str = "",
                 max_negative_cases: int = 20):
        self.target_url = target_url
        self.scan_id = scan_id
        self.max_negative_cases = max_negative_cases

    async def execute_workflow(self, workflow: Any) -> WorkflowResult:
        from core.actuation.browser_actuator import BrowserActuator
        browser = BrowserActuator()

        result = WorkflowResult(
            workflow_name=workflow.name,
            workflow_type=workflow.workflow_type,
            steps_total=len(workflow.steps),
        )

        actions = workflow.get_actions()
        if not actions:
            result.error = "no pending actions"
            return result

        try:
            browser_result = await browser.run_actions(actions)
        except Exception as e:
            result.error = str(e)[:300]
            return result

        if browser_result.get("error"):
            result.error = browser_result["error"][:300]
            return result

        results_list = browser_result.get("results", [])
        for i, step in enumerate(workflow.steps):
            if i < len(results_list):
                r = results_list[i]
                is_err = isinstance(r, str) and r.startswith("ERR ")
                if is_err:
                    from core.workflows.browser_workflows import StepOutcome
                    step.outcome = StepOutcome.FAILED
                    step.error = r
                    result.steps_failed += 1
                else:
                    from core.workflows.browser_workflows import StepOutcome
                    step.outcome = StepOutcome.SUCCESS
                    result.steps_succeeded += 1
                    if step.evidence_capture:
                        result.evidence.append({
                            "step_id": step.step_id,
                            "description": step.description,
                            "result": str(r)[:2000],
                        })

        return result

    async def execute_with_negative_tests(self, workflow: Any,
                                           captured_requests: Optional[List[Any]] = None
                                           ) -> WorkflowResult:
        result = await self.execute_workflow(workflow)
        if result.error or result.steps_succeeded < 2:
            return result

        try:
            from core.discovery.workflow_crawler import WorkflowCrawler
            crawler = WorkflowCrawler()

            reqs = captured_requests or []
            if not reqs:
                return result

            sm = crawler.build_from_requests(reqs)
            if len(sm.steps) < 2:
                return result

            test_cases = crawler.generate_test_cases(sm)
            if not test_cases:
                return result

            from core.actuation.browser_actuator import BrowserActuator
            browser = BrowserActuator()

            for tc in test_cases[:self.max_negative_cases]:
                result.negative_cases_run += 1
                materialized = crawler.materialize(tc, sm)
                if not materialized:
                    continue

                actions = self._requests_to_actions(materialized)
                try:
                    neg_result = await browser.run_actions(actions)
                except Exception:
                    continue

                finding = self._analyze_negative_result(tc, neg_result, sm)
                if finding:
                    result.findings.append(finding)

        except Exception as e:
            logger.debug(f"[WorkflowExecutor] negative tests failed: {e}")

        return result

    def _requests_to_actions(self, request_dicts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for req in request_dicts:
            url = req.get("url", "")
            method = req.get("method", "GET")
            post_data = req.get("post_data", "")

            if method == "GET":
                actions.append({"action": "navigate", "url": url, "timeout": 10000})
            else:
                script = f"fetch('{url}', {{method: '{method}'"
                if post_data:
                    safe = post_data.replace("'", "\\'").replace("\n", "\\n")[:500]
                    script += f", body: '{safe}', headers: {{'Content-Type': 'application/json'}}"
                script += "}).then(r => r.status + ' ' + r.statusText).catch(e => 'ERR:' + e)"
                actions.append({"action": "eval", "script": script})

        actions.append({
            "action": "eval",
            "script": "JSON.stringify({url: location.href, status: 'completed'})",
        })
        return actions

    def _analyze_negative_result(self, test_case: Any, browser_result: Dict[str, Any],
                                  sm: Any) -> Optional[Dict[str, Any]]:
        if browser_result.get("error"):
            return None

        results = browser_result.get("results", [])
        if not results:
            return None

        last = str(results[-1]) if results else ""
        all_results = " ".join(str(r) for r in results)

        is_success_response = False
        for r in results:
            r_str = str(r)
            if any(code in r_str for code in ("200 ", "201 ", "204 ")):
                is_success_response = True
                break

        if not is_success_response:
            return None

        severity = "medium"
        if test_case.kind == "skip_step":
            severity = "high"
        elif test_case.kind == "direct_access_final":
            severity = "high"
        elif test_case.kind == "reorder":
            severity = "medium"
        elif test_case.kind == "replay_step":
            severity = "low"

        return {
            "type": "business_logic",
            "subtype": f"workflow_{test_case.kind}",
            "title": f"Business Logic: {test_case.description}",
            "severity": severity,
            "description": (
                f"Negative test '{test_case.kind}' succeeded when it should have failed. "
                f"Test: {test_case.description}. "
                f"The application allowed a workflow violation, indicating missing "
                f"server-side state validation."
            ),
            "evidence": {
                "test_kind": test_case.kind,
                "description": test_case.description,
                "step_sequence": test_case.step_sequence,
                "responses": [str(r)[:200] for r in results[:5]],
            },
            "remediation": (
                "Enforce workflow state transitions server-side. Each step should "
                "verify that all prerequisite steps have been completed before "
                "proceeding. Use server-side session state, not client-side tokens."
            ),
            "target": self.target_url,
        }

    async def execute_all(self, workflows: List[Any],
                           captured_requests: Optional[List[Any]] = None
                           ) -> List[WorkflowResult]:
        results = []
        for wf in workflows:
            try:
                r = await self.execute_with_negative_tests(wf, captured_requests)
                results.append(r)
                logger.info(
                    f"[WorkflowExecutor] {wf.name}: "
                    f"{r.steps_succeeded}/{r.steps_total} steps ok, "
                    f"{r.negative_cases_run} negative tests, "
                    f"{len(r.findings)} findings")
            except Exception as e:
                results.append(WorkflowResult(
                    workflow_name=wf.name,
                    workflow_type=getattr(wf, "workflow_type", ""),
                    error=str(e)[:300],
                ))
        return results
