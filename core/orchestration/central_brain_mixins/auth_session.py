from __future__ import annotations

import logging
from typing import Any, Dict

from agents.llm_client import TaskTier
from core.orchestration.central_brain_mixins._auth_helpers import (
    _auth_find_token,
    _auth_is_spa_shell,
)

logger = logging.getLogger(__name__)


class AuthSessionMixin:
    """Identity context + authenticated-session lifecycle: JeV auth-possibility,
    LLM-driven registration, login re-resolution, live session setup, and
    auto-login with harvested creds. Extracted from CentralBrain; nearly all
    dependencies are self attrs or method-local imports.
    """

    def _build_identity_context(self) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {}
        if self.ctx.harvested_creds:
            best = self.ctx.harvested_creds[0]
            ctx["username"] = best.get("username", best.get("email", ""))
            ctx["password"] = best.get("password", "")
            ctx["login_url"] = best.get("login_url", "")
            ctx["role"] = best.get("role", "default")
            # Store all credential sets for multi-role testing
            ctx["all_credentials"] = [
                {
                    "role": c.get("role", "default"),
                    "username": c.get("username", c.get("email", "")),
                    "password": c.get("password", ""),
                    "login_url": c.get("login_url", ""),
                }
                for c in self.ctx.harvested_creds if c.get("username")
            ]
        if self.ctx.sessions:
            for _sid, sess in self.ctx.sessions.items():
                token = getattr(sess, "token", None) or getattr(sess, "jwt", None)
                if token:
                    ctx["auth_token"] = token
                    ctx["auth_header"] = f"Bearer {token}"
                    break
        for vuln in self.ctx.vulnerabilities:
            evidence = vuln.get("evidence") or vuln.get("proof") or {}
            if isinstance(evidence, dict):
                token = evidence.get("token") or evidence.get("jwt") or evidence.get("auth_token")
                if token and "auth_token" not in ctx:
                    ctx["auth_token"] = token
                    ctx["auth_header"] = f"Bearer {token}"
        return ctx

    async def _jev_auth_possible(self, registered: bool, signals: list) -> None:
        """Ask Jev (opt-in classifier) whether authentication is POSSIBLE on this
        target from the register/login evidence, and record the verdict on ctx.
        Runs whether or not our signup succeeded. Best-effort: with Jev off /
        unavailable it falls back to the concrete signal (a minted cred proves
        auth is possible; otherwise unknown)."""
        verdict = True if registered else None
        prob = 1.0 if registered else 0.0
        try:
            from agents.providers.jev_classifier import get_jev
            jev = get_jev(scan_id=getattr(self, "_scan_id", ""))
            if jev is not None and jev.is_available():
                # Dedup so the evidence isn't flooded with identical repeats
                # (register is attempted per-identity × per-payload), which would
                # otherwise fill the cap with the same 404 and hide login signals.
                seen: set = set()
                uniq = []
                for t in (signals or []):
                    if t not in seen:
                        seen.add(t)
                        uniq.append(t)
                evid = {
                    "self_register_succeeded": registered,
                    # endpoint + HTTP status only — no bodies, no creds
                    "attempts": [{"kind": k, "url": u, "status": s}
                                 for (k, u, s) in uniq[:24]],
                }
                v, p = await jev.noul(
                    evid,
                    "Given these registration/login endpoint attempts (URL + HTTP "
                    "status), is user authentication POSSIBLE on this target — "
                    "i.e. does an auth surface exist that could yield a valid "
                    "session (an open signup, or a login endpoint that accepts "
                    "credentials)? Judge by response shape, not just 2xx: a login "
                    "endpoint answering 400/401/403/405/422 (not 404) EXISTS and "
                    "means an auth surface is present, so authentication is "
                    "possible. A 200/201 on a signup or login is a strong yes. "
                    "Only 404/blocked on every candidate (no responsive auth "
                    "endpoint at all) points to no.",
                    name="auth_possible", site="triage")
                if v is not None:
                    verdict, prob = v, p
        except Exception as e:
            logger.debug("[Auth] Jev auth-possibility check skipped: %s", e)
        try:
            self.ctx.auth_possible = {
                "value": (bool(verdict) if verdict is not None else None),
                "probability": round(float(prob or 0.0), 3),
                "self_register": registered,
            }
        except Exception:
            pass
        logger.info("[Auth] authentication possible? %s (p=%.2f, self_register=%s)",
                    verdict, float(prob or 0.0), registered)

    async def _llm_register_body(self, url: str, email: str, pw: str,
                                 error_text: str) -> dict:
        """Synthesize a registration request body from the server's OWN
        validation error (target-agnostic). Returns {} on any failure so the
        caller falls back gracefully."""
        try:
            prompt = (
                "A JSON account-registration request to a web API was rejected. "
                "Infer the required fields from the server's validation error and "
                "return ONLY a JSON object for a body that would register a new "
                "account. Use minimal valid placeholder values for any extra "
                "required fields.\n"
                f"Endpoint: {url}\n"
                f"Credential fields should use email={email}, password={pw}.\n"
                f"Server error response (truncated):\n{(error_text or '')[:1200]}"
            )
            body = await self.llm.generate_json(prompt, tier=TaskTier.SMALL,
                                                max_tokens=400)
            return body if isinstance(body, dict) and body else {}
        except Exception:
            return {}

    async def _reresolve_login_and_auth(self) -> None:
        """Post-discovery login re-resolution + re-auth.

        Bootstrap self-registration runs at Phase 0, before the app's real login
        endpoint is crawled — so self-seeded credentials can carry an unresolved
        login_url and produce 0 authenticated identities (every authenticated test
        then skips). Once discovery has populated ctx (RECON/ACTIVE_SCANNING), the
        real login endpoint is discoverable content: re-resolve it and re-auth.
        No-op when already authenticated or when there are no seeded creds.
        Best-effort, non-fatal."""
        try:
            creds = getattr(self.ctx, "auth_credentials", None) or []
            if not creds:
                return  # nothing seeded
            # Skip only if a session is genuinely AUTHENTICATED. sessions_map()
            # returns an entry per role with an "authenticated" flag, so the dict
            # is non-empty even when Phase-0 login failed — testing truthiness of
            # the dict alone would wrongly skip re-resolution.
            sess = getattr(self.ctx, "auth_sessions", None) or {}
            if any(isinstance(s, dict) and s.get("authenticated") for s in sess.values()):
                return  # already authenticated
            email = creds[0].get("username")
            pw = creds[0].get("password")
            if not (email and pw):
                return
            from core.common import endpoint_hints
            from core.security.scoped_http import get_scoped_client
            # Content-driven: discovered login endpoints (now populated) + whatever
            # login_url the creds already carry. No app-specific literals.
            cand = list(dict.fromkeys(
                [c.get("login_url") for c in creds if c.get("login_url")]
                + endpoint_hints.discover_endpoints(self.ctx, "login", include_fallback=True)))
            if not cand:
                return
            uname_field = creds[0].get("username_field", "email") or "email"
            pw_field = creds[0].get("password_field", "password") or "password"
            tok_cfg = creds[0].get("token_json_path", "") or ""

            def _dig(o, path):
                cur = o
                for part in (path or "").split("."):
                    cur = cur.get(part) if isinstance(cur, dict) else None
                return cur

            resolved_url = resolved_path = ""
            async with get_scoped_client(timeout=20, follow_redirects=True) as client:
                for url in cand:
                    try:
                        r = await client.post(url, json={uname_field: email, pw_field: pw})
                    except Exception:
                        continue
                    if r.status_code not in (200, 201) or _auth_is_spa_shell(r):
                        continue
                    try:
                        data = r.json()
                    except Exception:
                        continue
                    tok = _dig(data, tok_cfg) if tok_cfg else None
                    if isinstance(tok, str) and len(tok) > 20:
                        resolved_url, resolved_path = url, tok_cfg
                        break
                    found = _auth_find_token(data)
                    if found:
                        resolved_url, resolved_path = url, found[0]
                        break
            if not resolved_url:
                return
            for c in creds:
                c["login_url"] = resolved_url
                if resolved_path:
                    c["token_json_path"] = resolved_path
            self.ctx.auth_credentials = creds
            logger.info(f"[Auth] post-discovery re-resolved login endpoint: {resolved_url} "
                        f"(token path: {resolved_path or tok_cfg or 'auto'}) — re-authenticating")
            await self._setup_auth_session()
        except Exception as e:
            logger.warning(f"[Auth] post-discovery login re-resolution failed (non-fatal): {e}")

    async def _setup_auth_session(self) -> None:
        self.auth_session = None
        self.multi_auth = None
        try:
            # 0. Zero-config auth: when no creds are supplied and self-registration
            # is enabled, create a throwaway account so the authenticated surface
            # (IDOR/JWT/business-logic) is reachable. Best-effort; seeds
            # ctx.auth_credentials which the login machinery below consumes.
            try:
                if not (getattr(self.ctx, "auth_credentials", None)):
                    await self._bootstrap_self_registration()
            except Exception as _e:
                logger.warning(f"[Auth] self-registration bootstrap failed (non-fatal): {_e}")

            # 1. Multi-role credentials supplied by the UI / CLI.
            creds = getattr(self.ctx, "auth_credentials", None) \
                or [c for c in getattr(self.ctx, "harvested_creds", []) if isinstance(c, dict) and c.get("username")]
            if creds:
                from core.authentication.auth_session import MultiIdentityAuthManager
                multi = MultiIdentityAuthManager(creds)
                await multi.authenticate_all()
                self.multi_auth = multi
                # Expose per-role sessions for cross-role (IDOR / access-control) testing.
                self.ctx.auth_sessions = multi.sessions_map()
                default = multi.default_session()
                if default:
                    self.auth_session = default
                    self.ctx.auth_headers = default.auth_headers()
                    self.ctx.auth_cookies = dict(default.cookies)
                self.ctx.auth_summary = multi.summary()
                self.ctx.log_brain(
                    f"Authenticated {len(multi.summary()['authenticated_roles'])} role session(s)", "auth")
                logger.info(f"[Auth] multi-role sessions ready: {multi.summary()['authenticated_roles']}")

                # Connect real role sessions into the access-control / IDOR replay
                # engine so cross-role authorization tests use live credentials.
                try:
                    from core.authentication.identity_bridge import build_replay_sessions
                    bridge = build_replay_sessions(
                        multi_auth=multi,
                        replay_session_manager=getattr(self, "replay_session_manager", None),
                        identity_manager=self.identity_manager,
                        shared_context=self.ctx,
                    )
                    self.ctx.replay_identity_bridge = bridge
                except Exception as e:
                    logger.warning(f"[Auth] replay-engine bridge failed (non-fatal): {e}")
                return

            # 2. Single .env-configured session.
            from core.authentication.auth_session import AuthSessionManager
            mgr = AuthSessionManager()
            if not mgr.enabled:
                return
            ok = await mgr.authenticate()
            self.auth_session = mgr
            self.ctx.auth_headers = mgr.auth_headers()
            self.ctx.auth_cookies = dict(mgr.cookies)
            self.ctx.auth_summary = mgr.summary()
            if ok and mgr.config.probe_url:
                live = await mgr.is_authenticated()
                logger.info(f"[Auth] session live-check on probe url: {'OK' if live else 'FAILED'}")
            if ok:
                logger.info("[Auth] authenticated session active — post-auth surface unlocked")
                self.ctx.log_brain("Authenticated session established", "auth")
        except Exception as e:
            logger.warning(f"[Auth] session setup failed (non-fatal): {e}")
        # Publish the active auth into the process-wide registry so V2 executors
        # that don't hold a reference to shared_context (see
        # core/execution/executors/generic.py::_auth_headers) can pick it up.
        try:
            from core.execution.executors.auth_registry import set_active_auth
            set_active_auth(
                headers=getattr(self.ctx, "auth_headers", {}) or {},
                cookies=getattr(self.ctx, "auth_cookies", {}) or {},
                sessions=getattr(self.ctx, "auth_sessions", {}) or {},
            )
        except Exception as _e:
            logger.debug(f"[Auth] registry publish failed: {_e}")
        # If we obtained a real live session (from UI creds or .env auth), also
        # persist a proof-of-entry so the UI 'Access Gained' panel shows it.
        try:
            hdrs = getattr(self.ctx, "auth_headers", {}) or {}
            authz = hdrs.get("Authorization", "")
            if authz.startswith("Bearer "):
                from core.database.pg_store import AuthBypassRepo
                from urllib.parse import urlparse as _up
                _base = self.ctx.target
                _host = _up(_base if "://" in _base else f"https://{_base}").netloc
                for cred in (getattr(self.ctx, "auth_credentials", None) or [{}])[:1]:
                    AuthBypassRepo.insert(
                        self._scan_id, _host, "credential_replay",
                        cred.get("login_url", "") or _base,
                        method="POST",
                        username=cred.get("username") or cred.get("email") or "",
                        password=cred.get("password") or "",
                        payload="(operator-supplied credentials)",
                        token=authz[len("Bearer "):],
                        response_status=200,
                        response_snippet="Session established via _setup_auth_session",
                        role=cred.get("role") or "", severity="info",
                    )
        except Exception:
            pass

    async def _auto_login_with_harvested_creds(self) -> None:
        creds = getattr(self.ctx, "harvested_creds", []) or []
        candidates = []
        seen = set()
        for c in creds:
            if not isinstance(c, dict):
                continue
            if c.get("token"):
                continue  # already have a session
            user = c.get("username") or c.get("email")
            pw = c.get("password")
            if not (user and pw):
                continue
            key = f"{user}|{pw}"
            if key in seen:
                continue
            seen.add(key)
            candidates.append(c)
        if not candidates:
            return

        # Discover login endpoints from what we've already seen the app expose.
        base = self.ctx.target
        if not base.startswith(("http://", "https://")):
            base = f"https://{base}"
        from urllib.parse import urlparse as _up
        base_host = _up(base).netloc
        # Generic endpoint discovery — reads everything the crawler + ffuf +
        # captured requests found, classifies as "login" role, falls back to a
        # generic industry-standard list (/login, /signin, /oauth/token, ...)
        # only when nothing was discovered on this target.
        from core.common.endpoint_hints import discover_endpoints
        login_urls = set(discover_endpoints(self.ctx, "login", max_results=20))

        logger.info(f"[AutoLogin] Trying {len(candidates)} plaintext cred(s) against {len(login_urls)} login endpoint(s)")
        import httpx as _httpx, json as _json, base64 as _b64
        from core.database.pg_store import AuthBypassRepo
        from core.execution.executors.auth_registry import set_active_auth

        # Expert mode: long-backoff retry so a transient 503/timeout doesn't
        # declare valid creds dead. Retries spread over ~4 minutes total.
        RETRY_DELAYS = [0, 2, 5, 15, 45, 120]  # seconds
        BODY_SHAPES = [
            ("json", {"email": "{U}", "password": "{P}"}),
            ("json", {"username": "{U}", "password": "{P}"}),
            ("json", {"login": "{U}", "password": "{P}"}),
            ("json", {"user": "{U}", "pass": "{P}"}),
            ("json", {"identifier": "{U}", "password": "{P}"}),
            ("json", {"id": "{U}", "pwd": "{P}"}),
            ("form", "email={U}&password={P}"),
            ("form", "username={U}&password={P}"),
            ("form", "j_username={U}&j_password={P}"),
        ]
        import asyncio as _asyncio
        async with _httpx.AsyncClient(follow_redirects=True, timeout=30, verify=False) as client:
            for cred in candidates:
                user = cred.get("username") or cred.get("email")
                pw = cred.get("password")
                logged_in = False
                for lurl in login_urls:
                    if logged_in:
                        break
                    for shape, tmpl in BODY_SHAPES:
                        if logged_in:
                            break
                        for delay in RETRY_DELAYS:
                            if delay:
                                await _asyncio.sleep(delay)
                            try:
                                if shape == "json":
                                    body = {k: (v.replace("{U}", str(user)).replace("{P}", str(pw))
                                                if isinstance(v, str) else v)
                                            for k, v in tmpl.items()}
                                    resp = await client.post(lurl, json=body)
                                else:
                                    from urllib.parse import quote as _q
                                    body_s = tmpl.replace("{U}", _q(str(user))).replace("{P}", _q(str(pw)))
                                    resp = await client.post(
                                        lurl, content=body_s,
                                        headers={"Content-Type": "application/x-www-form-urlencoded"})
                                    body = body_s
                            except Exception:
                                continue
                            # Treat transient errors as retryable
                            if resp.status_code in (429, 500, 502, 503, 504):
                                logger.debug(f"[AutoLogin] {user}@{lurl} shape={shape} -> {resp.status_code}, retrying")
                                continue
                            if resp.status_code not in (200, 201):
                                break  # non-transient failure — try next body shape
                        # Token/session-shape agnostic: accept a JWT, an opaque
                        # bearer token, OR a session cookie — was eyJ-only, which
                        # dropped every non-JWT login and lost credential-replay /
                        # cross-role coverage on cookie/opaque-token apps.
                        from core.common import auth_shape as _ash
                        try:
                            _j = resp.json()
                        except Exception:
                            _j = None
                        _sess = _ash.extract_session(_j, getattr(resp, "headers", None))
                        token = _sess.get("token")
                        if not token:
                            continue
                        _transport = _sess.get("transport", "bearer")
                        _cookie_name = _sess.get("cookie_name", "")
                        # Role from JWT across modern claim shapes (roles[]/scope/
                        # realm_access.roles/cognito:groups/namespaced); "" if opaque.
                        role = _ash.primary_role(token) if _sess.get("is_jwt") else ""
                        # Attach token, publish, persist
                        cred["token"] = token
                        cred["role"] = role
                        cred["login_url"] = lurl
                        cred["transport"] = _transport
                        hdrs = dict(getattr(self.ctx, "auth_headers", {}) or {})
                        cookies = dict(getattr(self.ctx, "auth_cookies", {}) or {})
                        if _transport == "cookie" and _cookie_name:
                            cookies[_cookie_name] = token
                            self.ctx.auth_cookies = cookies
                        else:
                            hdrs["Authorization"] = f"Bearer {token}"
                            self.ctx.auth_headers = hdrs
                        try:
                            set_active_auth(
                                headers=hdrs,
                                cookies=cookies,
                                sessions=getattr(self.ctx, "auth_sessions", {}) or {},
                            )
                        except Exception:
                            pass
                        try:
                            payload_str = _json.dumps(body) if isinstance(body, dict) else str(body)
                            AuthBypassRepo.insert(
                                self._scan_id, _up(lurl).netloc or base_host,
                                "credential_replay", lurl,
                                method="POST", username=user, password=pw,
                                payload=payload_str,
                                token=token, response_status=resp.status_code,
                                response_snippet=(resp.text or "")[:600],
                                role=role,
                                severity=("critical" if "admin" in role.lower() else "high"),
                            )
                        except Exception:
                            pass
                        logger.info(f"[AutoLogin] {user} -> {lurl} (shape={shape}) = 200 (role={role or '?'}) — token attached")
                        logged_in = True
                        break  # break retry loop
