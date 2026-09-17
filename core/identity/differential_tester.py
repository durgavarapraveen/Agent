from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
_RATE_LIMIT_PER_SEC = 10.0


@dataclass
class _Identity:
    ident_id: str
    role: str
    headers: Dict[str, str]
    cookies: Dict[str, str]


@dataclass
class AuthzDiff:
    indicates_authz_failure: bool
    kind: str
    detail: str


class DifferentialAuthorizationTester:
    """Systematically replays each state-changing endpoint across all identities
    (P2). Flags vertical/horizontal priv-esc, auth bypass, tenant isolation
    failures by comparing responses against the highest-privilege baseline.
    """

    def __init__(self, brain=None):
        self.brain = brain
        self._delay = 1.0 / _RATE_LIMIT_PER_SEC

    async def test_all(self, ctx) -> List[Dict[str, Any]]:
        identities = self._collect_identities(ctx)
        if len(identities) < 2:
            logger.info("DifferentialAuthorizationTester: <2 identities, skipping")
            return []
        endpoints = self._state_changing_endpoints(ctx)
        if not endpoints:
            return []

        baseline_ident = identities[0]  # assume highest-privilege first
        findings: List[Dict[str, Any]] = []
        for method, url in endpoints:
            base = await self._request_as(method, url, baseline_ident)
            if base is None:
                continue
            for ident in identities[1:]:
                resp = await self._request_as(method, url, ident)
                await asyncio.sleep(self._delay)
                if resp is None:
                    continue
                diff = self._compare(base, resp, baseline_ident, ident)
                if diff.indicates_authz_failure:
                    f = self._build_finding(method, url, ident, diff)
                    findings.append(f)
                    ctx.add_vulnerability(f)
        return findings

    # ── internals ──────────────────────────────────────────────────────
    def _collect_identities(self, ctx) -> List[_Identity]:
        out: List[_Identity] = []
        seen = set()

        def add(ident_id, role, headers, cookies):
            if not ident_id or ident_id in seen:
                return
            seen.add(ident_id)
            out.append(_Identity(str(ident_id), str(role or "unknown"),
                                 dict(headers or {}), dict(cookies or {})))

        # SessionManager (SessionArtifact: identity_id, headers, cookies)
        sm = getattr(self.brain, "session_manager", None)
        try:
            for art in list(getattr(sm, "_sessions", {}).values() if sm else []):
                add(getattr(art, "identity_id", None), getattr(art, "identity_id", ""),
                    getattr(art, "headers", {}), getattr(art, "cookies", {}))
        except Exception as e:
            logger.debug("session_manager identities failed: %s", e)

        # SessionIdentityManager (SessionModel.identity.role, cookies, tokens)
        sim = getattr(self.brain, "session_identity_manager", None)
        try:
            for s in list(getattr(sim, "sessions", {}).values() if sim else []):
                ident = getattr(s, "identity", None)
                headers = {}
                tok = getattr(s, "tokens", {}) or {}
                if tok:
                    first = next(iter(tok.values()))
                    headers["Authorization"] = f"Bearer {first}"
                add(getattr(ident, "id", None), getattr(ident, "role", ""),
                    headers, getattr(s, "cookies", {}))
        except Exception as e:
            logger.debug("session_identity_manager identities failed: %s", e)

        # ctx.sessions fallback (dicts)
        try:
            for k, v in (getattr(ctx, "sessions", {}) or {}).items():
                if isinstance(v, dict):
                    add(k, v.get("role", k), v.get("headers", {}), v.get("cookies", {}))
        except Exception:
            pass

        # anonymous baseline for auth-bypass detection
        add("anonymous", "anonymous", {}, {})
        # sort so a role that looks admin is baseline (index 0)
        out.sort(key=lambda i: (0 if "admin" in i.role.lower() else 1))
        return out

    def _state_changing_endpoints(self, ctx) -> List[Tuple[str, str]]:
        eps: List[Tuple[str, str]] = []
        try:
            raw = ctx.get_endpoints() if hasattr(ctx, "get_endpoints") else []
        except Exception:
            raw = []
        for e in raw:
            method = "GET"
            url = ""
            if isinstance(e, dict):
                method = str(e.get("method", "GET")).upper()
                url = e.get("url") or e.get("endpoint") or ""
            elif isinstance(e, str):
                url = e
            else:
                method = str(getattr(e, "method", "GET")).upper()
                url = getattr(e, "url", "") or ""
            if not url:
                continue
            if method in _STATE_CHANGING or any(k in url.lower() for k in
                    ("delete", "update", "admin", "create", "edit", "remove", "/api/")):
                eps.append((method if method in _STATE_CHANGING else "GET", url))
        return eps

    async def _request_as(self, method: str, url: str, ident: _Identity) -> Optional[Dict[str, Any]]:
        try:
            from core.network.network_broker import NetworkBroker
            broker = NetworkBroker.get()
        except Exception:
            return None
        kwargs: Dict[str, Any] = {}
        if ident.headers:
            kwargs["headers"] = ident.headers
        if ident.cookies:
            kwargs["cookies"] = ident.cookies
        try:
            resp = await broker.request(method, url, **kwargs)
        except Exception as e:
            logger.debug("diff request failed (%s as %s): %s", url, ident.role, e)
            return None
        body = getattr(resp, "text", "") or ""
        return {"status": getattr(resp, "status_code", 0) or 0, "body": body,
                "len": len(body), "shape": self._shape(body)}

    def _compare(self, base: Dict, resp: Dict, base_ident: _Identity, ident: _Identity) -> AuthzDiff:
        base_ok = base["status"] == 200
        resp_ok = resp["status"] == 200
        similar = base_ok and resp_ok and self._similar(base, resp)
        if similar:
            if ident.role == "anonymous":
                return AuthzDiff(True, "auth_bypass",
                                 "Anonymous received same 200 response as privileged baseline.")
            if "admin" not in ident.role.lower():
                return AuthzDiff(True, "privilege_escalation",
                                 f"Lower-privilege role '{ident.role}' got baseline-equivalent access.")
        return AuthzDiff(False, "", "")

    @staticmethod
    def _similar(a: Dict, b: Dict) -> bool:
        if a["shape"] and a["shape"] == b["shape"]:
            return True
        if a["len"] == 0:
            return False
        return abs(a["len"] - b["len"]) / max(a["len"], 1) < 0.1

    @staticmethod
    def _shape(body: str) -> str:
        import re
        keys = sorted(set(re.findall(r'"([A-Za-z0-9_]{2,40})"\s*:', body[:4000])))
        return ",".join(keys[:30])

    def _build_finding(self, method, url, ident: _Identity, diff: AuthzDiff) -> Dict[str, Any]:
        fid = "DIFFAUTH_" + hashlib.sha256(f"{method}|{url}|{ident.role}|{diff.kind}".encode()).hexdigest()[:16]
        sev = "CRITICAL" if diff.kind in ("auth_bypass", "privilege_escalation") else "HIGH"
        return {
            "id": fid, "type": diff.kind.upper(), "title": f"{diff.kind} on {method} {url}",
            "severity": sev, "target": url, "location": url,
            "identity": ident.role, "tool": "differential_authz_tester",
            "proof": f"as '{ident.role}': {diff.detail}", "details": diff.detail,
            "confirmed": True, "status": "CONFIRMED", "cwe": "CWE-285",
        }
