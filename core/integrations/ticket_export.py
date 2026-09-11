"""Phase 3.4 — Jira / Linear ticket export & bi-directional sync.

One-click export of a finding to a tracker (Jira REST or Linear GraphQL) with
severity, description, reproduction steps and fix suggestion; poll ticket status
back; and auto-close the ticket when a re-scan confirms the fix.

These target third-party SaaS APIs (Jira/Linear), NOT the pentest target, so
they use a plain httpx client — the scope-enforced client (Phase 0.5) would
correctly block them. Each provider accepts an injectable ``client`` so tests
drive it with ``httpx.MockTransport`` and never touch the network.

Config via env: ``JIRA_URL``, ``JIRA_EMAIL``, ``JIRA_TOKEN``, ``JIRA_PROJECT_KEY``;
``LINEAR_API_KEY``, ``LINEAR_TEAM_ID``.
"""
from __future__ import annotations

import base64
import logging
import os
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

# Map internal severities → tracker priority labels.
_JIRA_PRIORITY = {"critical": "Highest", "high": "High", "medium": "Medium",
                  "low": "Low", "info": "Lowest"}


@dataclass
class TicketRef:
    provider: str
    id: str
    key: str = ""
    url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"provider": self.provider, "id": self.id, "key": self.key, "url": self.url}


def finding_to_ticket_fields(finding: Dict[str, Any]) -> Dict[str, str]:
    """Render a finding into a ticket title + markdown description."""
    sev = str(finding.get("severity", "medium")).lower()
    title = f"[{sev.upper()}] {finding.get('title') or finding.get('type', 'Security finding')}"
    repro = finding.get("reproduction") or finding.get("proof") or finding.get("evidence") or "See scan evidence."
    fix = finding.get("fix") or finding.get("remediation") or "Apply input validation / authorization checks."
    desc = (
        f"*Severity:* {sev}\n"
        f"*URL:* {finding.get('url') or finding.get('target', 'n/a')}\n\n"
        f"*Description:*\n{finding.get('description', finding.get('title', ''))}\n\n"
        f"*Reproduction:*\n{repro}\n\n"
        f"*Suggested fix:*\n{fix}\n"
    )
    return {"title": title[:250], "description": desc, "severity": sev}


class TicketProvider(ABC):
    name = "abstract"
    _client: Optional[httpx.Client] = None

    @contextmanager
    def _session(self):
        """Yield an httpx client. An injected client is owned by the caller and
        never closed here (so it can be reused across calls); a self-created one
        is closed on exit."""
        if self._client is not None:
            yield self._client
        else:
            c = httpx.Client(timeout=20)
            try:
                yield c
            finally:
                c.close()

    @abstractmethod
    def create_ticket(self, finding: Dict[str, Any]) -> TicketRef: ...

    @abstractmethod
    def update_ticket(self, ticket_id: str, fields: Dict[str, Any]) -> bool: ...

    @abstractmethod
    def get_status(self, ticket_id: str) -> str: ...

    def close_ticket(self, ticket_id: str) -> bool:
        return self.update_ticket(ticket_id, {"close": True})


class JiraProvider(TicketProvider):
    name = "jira"

    def __init__(self, base_url: Optional[str] = None, email: Optional[str] = None,
                 token: Optional[str] = None, project_key: Optional[str] = None,
                 client: Optional[httpx.Client] = None):
        self.base_url = (base_url or os.getenv("JIRA_URL", "")).rstrip("/")
        self.email = email or os.getenv("JIRA_EMAIL", "")
        self.token = token or os.getenv("JIRA_TOKEN", "")
        self.project_key = project_key or os.getenv("JIRA_PROJECT_KEY", "SEC")
        self._client = client

    def _auth_header(self) -> Dict[str, str]:
        # Jira Cloud uses Basic email:token; Server/DC uses Bearer PAT.
        if self.email:
            raw = f"{self.email}:{self.token}".encode("utf-8")
            return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}
        return {"Authorization": f"Bearer {self.token}"}

    def create_ticket(self, finding: Dict[str, Any]) -> TicketRef:
        fields = finding_to_ticket_fields(finding)
        payload = {"fields": {
            "project": {"key": self.project_key},
            "summary": fields["title"],
            "description": fields["description"],
            "issuetype": {"name": "Bug"},
            "priority": {"name": _JIRA_PRIORITY.get(fields["severity"], "Medium")},
        }}
        with self._session() as c:
            r = c.post(f"{self.base_url}/rest/api/2/issue",
                       json=payload, headers={**self._auth_header(),
                                              "Content-Type": "application/json"})
            r.raise_for_status()
            data = r.json()
        key = data.get("key", "")
        return TicketRef(provider=self.name, id=str(data.get("id", key)), key=key,
                         url=f"{self.base_url}/browse/{key}" if key else "")

    def update_ticket(self, ticket_id: str, fields: Dict[str, Any]) -> bool:
        with self._session() as c:
            if fields.get("close"):
                r = c.post(f"{self.base_url}/rest/api/2/issue/{ticket_id}/transitions",
                           json={"transition": {"id": fields.get("transition_id", "31")}},
                           headers={**self._auth_header(), "Content-Type": "application/json"})
            else:
                r = c.put(f"{self.base_url}/rest/api/2/issue/{ticket_id}",
                          json={"fields": fields},
                          headers={**self._auth_header(), "Content-Type": "application/json"})
            return r.status_code < 300

    def get_status(self, ticket_id: str) -> str:
        with self._session() as c:
            r = c.get(f"{self.base_url}/rest/api/2/issue/{ticket_id}",
                      headers=self._auth_header())
            r.raise_for_status()
            data = r.json()
        return (data.get("fields", {}).get("status", {}) or {}).get("name", "unknown")


class LinearProvider(TicketProvider):
    name = "linear"
    ENDPOINT = "https://api.linear.app/graphql"

    def __init__(self, api_key: Optional[str] = None, team_id: Optional[str] = None,
                 client: Optional[httpx.Client] = None):
        self.api_key = api_key or os.getenv("LINEAR_API_KEY", "")
        self.team_id = team_id or os.getenv("LINEAR_TEAM_ID", "")
        self._client = client

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": self.api_key, "Content-Type": "application/json"}

    def _gql(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        with self._session() as c:
            r = c.post(self.ENDPOINT, json={"query": query, "variables": variables},
                       headers=self._headers())
            r.raise_for_status()
            return r.json()

    def create_ticket(self, finding: Dict[str, Any]) -> TicketRef:
        fields = finding_to_ticket_fields(finding)
        query = ("mutation IssueCreate($input: IssueCreateInput!) { "
                 "issueCreate(input: $input) { success issue { id identifier url } } }")
        data = self._gql(query, {"input": {
            "teamId": self.team_id, "title": fields["title"],
            "description": fields["description"]}})
        issue = ((data.get("data", {}) or {}).get("issueCreate", {}) or {}).get("issue", {}) or {}
        return TicketRef(provider=self.name, id=str(issue.get("id", "")),
                         key=issue.get("identifier", ""), url=issue.get("url", ""))

    def update_ticket(self, ticket_id: str, fields: Dict[str, Any]) -> bool:
        query = ("mutation IssueUpdate($id: String!, $input: IssueUpdateInput!) { "
                 "issueUpdate(id: $id, input: $input) { success } }")
        inp: Dict[str, Any] = {}
        if fields.get("close"):
            inp["stateId"] = fields.get("done_state_id", "")
        data = self._gql(query, {"id": ticket_id, "input": inp or fields})
        return bool(((data.get("data", {}) or {}).get("issueUpdate", {}) or {}).get("success"))

    def get_status(self, ticket_id: str) -> str:
        query = "query Issue($id: String!) { issue(id: $id) { state { name } } }"
        data = self._gql(query, {"id": ticket_id})
        return (((data.get("data", {}) or {}).get("issue", {}) or {}).get("state", {}) or {}).get("name", "unknown")


class TicketExporter:
    """One-click export + bi-directional sync over any TicketProvider."""

    DONE_STATES = {"done", "closed", "resolved", "complete", "completed", "fixed"}

    def __init__(self, provider: TicketProvider):
        self.provider = provider

    def export(self, finding: Dict[str, Any]) -> TicketRef:
        ref = self.provider.create_ticket(finding)
        finding["ticket"] = ref.to_dict()
        logger.info("ticket_export: %s ticket %s created for %s",
                    self.provider.name, ref.key or ref.id, finding.get("title"))
        return ref

    def sync_status(self, ticket_id: str, finding: Dict[str, Any]) -> str:
        status = self.provider.get_status(ticket_id)
        finding["ticket_status"] = status
        if status.lower() in self.DONE_STATES:
            finding["status"] = "fixed"
        return status

    def auto_close_if_fixed(self, ticket_id: str, finding: Dict[str, Any],
                            reproducer: Callable[[Dict[str, Any]], bool]) -> bool:
        """Close the ticket only when a re-scan can no longer reproduce the finding."""
        try:
            still_vulnerable = bool(reproducer(finding.get("test_case", finding)))
        except Exception as e:
            logger.warning("ticket_export: reproducer error (%s); not closing", e)
            return False
        if still_vulnerable:
            return False
        ok = self.provider.close_ticket(ticket_id)
        if ok:
            finding["status"] = "fixed"
        return ok
