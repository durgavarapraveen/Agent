"""Phase 3.4 — Jira / Linear ticket export."""
from __future__ import annotations

import json

import httpx

from core.integrations.ticket_export import (
    JiraProvider,
    LinearProvider,
    TicketExporter,
    finding_to_ticket_fields,
)

FINDING = {
    "id": "v1", "title": "SQL Injection in login", "type": "sqli",
    "severity": "critical", "url": "https://app.test/login",
    "description": "Boolean-based SQLi", "proof": "' OR 1=1-- returns 200",
    "fix": "Use parameterized queries",
}


def test_finding_to_ticket_fields():
    f = finding_to_ticket_fields(FINDING)
    assert f["title"].startswith("[CRITICAL]")
    assert "parameterized queries" in f["description"]
    assert "https://app.test/login" in f["description"]
    assert f["severity"] == "critical"


def _jira_client():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path.endswith("/issue"):
            body = json.loads(request.content)
            assert body["fields"]["project"]["key"]  # project set
            return httpx.Response(201, json={"id": "10001", "key": "SEC-1"})
        if request.method == "GET" and "/issue/10001" in path:
            return httpx.Response(200, json={"fields": {"status": {"name": "Done"}}})
        if request.method == "POST" and path.endswith("/transitions"):
            return httpx.Response(204)
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_jira_create_and_status_and_close():
    jira = JiraProvider(base_url="https://jira.test", email="me@test", token="tok",
                        project_key="SEC", client=_jira_client())
    ref = jira.create_ticket(FINDING)
    assert ref.provider == "jira"
    assert ref.key == "SEC-1"
    assert ref.url == "https://jira.test/browse/SEC-1"
    assert jira.get_status("10001") == "Done"
    assert jira.close_ticket("10001") is True


def _linear_client():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        q = body.get("query", "")
        if "issueCreate" in q:
            return httpx.Response(200, json={"data": {"issueCreate": {
                "success": True, "issue": {"id": "uuid-1", "identifier": "SEC-9",
                                            "url": "https://linear.app/x/SEC-9"}}}})
        if "issue(id" in q or "issue(" in q:
            return httpx.Response(200, json={"data": {"issue": {"state": {"name": "Todo"}}}})
        return httpx.Response(200, json={"data": {}})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_linear_create_and_status():
    linear = LinearProvider(api_key="lin_key", team_id="team1", client=_linear_client())
    ref = linear.create_ticket(FINDING)
    assert ref.provider == "linear"
    assert ref.key == "SEC-9"
    assert ref.url.endswith("SEC-9")
    assert linear.get_status("uuid-1") == "Todo"


def test_exporter_export_and_sync():
    jira = JiraProvider(base_url="https://jira.test", email="me@test", token="tok",
                        client=_jira_client())
    exporter = TicketExporter(jira)
    finding = dict(FINDING)
    ref = exporter.export(finding)
    assert finding["ticket"]["key"] == "SEC-1"

    status = exporter.sync_status("10001", finding)
    assert status == "Done"
    assert finding["status"] == "fixed"  # Done → fixed


def test_auto_close_only_when_not_reproducible():
    jira = JiraProvider(base_url="https://jira.test", email="me@test", token="tok",
                        client=_jira_client())
    exporter = TicketExporter(jira)

    # Still reproducible → do NOT close.
    assert exporter.auto_close_if_fixed("10001", dict(FINDING), reproducer=lambda tc: True) is False
    # Fixed (not reproducible) → close.
    f = dict(FINDING)
    assert exporter.auto_close_if_fixed("10001", f, reproducer=lambda tc: False) is True
    assert f["status"] == "fixed"
