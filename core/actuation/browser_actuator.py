
from __future__ import annotations

import asyncio
import base64
import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_DRIVER = r'''
import sys, json, base64, asyncio
from playwright.async_api import async_playwright

async def main():
    actions = json.loads(base64.b64decode(sys.argv[1]))
    # Optional auth blob (argv[2]): {headers:{}, cookies:[{name,value,url}], local_storage:{k:v}}
    auth = {}
    if len(sys.argv) > 2 and sys.argv[2]:
        try:
            auth = json.loads(base64.b64decode(sys.argv[2]))
        except Exception:
            auth = {}
    logs, results = [], []
    async with async_playwright() as p:
        browser = await p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx_kwargs = {}
        if auth.get("headers"):
            ctx_kwargs["extra_http_headers"] = auth["headers"]
        context = await browser.new_context(**ctx_kwargs)
        if auth.get("cookies"):
            try:
                await context.add_cookies(auth["cookies"])
            except Exception as e:
                logs.append(f"cookie-inject-err: {e}")
        ls = auth.get("local_storage") or {}
        if ls:
            # Seed localStorage BEFORE any page script runs, so SPAs (e.g. token-in-
            # localStorage auth) boot authenticated on the first navigation.
            js = ";".join("localStorage.setItem(%s,%s)" % (json.dumps(k), json.dumps(v))
                          for k, v in ls.items())
            try:
                await context.add_init_script(js)
            except Exception as e:
                logs.append(f"ls-inject-err: {e}")
        page = await context.new_page()
        page.on("console", lambda m: logs.append(f"{m.type}: {m.text}"))
        page.on("pageerror", lambda e: logs.append(f"pageerror: {e}"))
        for a in actions:
            t = a.get("action")
            try:
                if t == "navigate":
                    await page.goto(a["url"], wait_until=a.get("wait_until", "networkidle"),
                                    timeout=int(a.get("timeout", 30000)))
                elif t == "eval":
                    results.append(await page.evaluate(a["script"]))
                elif t == "click":
                    await page.click(a["selector"], timeout=int(a.get("timeout", 8000)))
                elif t == "fill":
                    await page.fill(a["selector"], a.get("value", ""), timeout=int(a.get("timeout", 8000)))
                elif t == "wait":
                    await page.wait_for_timeout(int(a.get("ms", 1000)))
                elif t == "dom":
                    results.append((await page.content())[:4000])
                elif t == "localStorage":
                    results.append(await page.evaluate("JSON.stringify(window.localStorage)"))
                else:
                    results.append(f"unknown action {t}")
            except Exception as e:
                results.append(f"ERR {t}: {e}")
        final_url = page.url
        await browser.close()
    print("RESULT_B64:" + base64.b64encode(json.dumps(
        {"url": final_url, "console": logs[-40:], "results": results}).encode()).decode())

asyncio.run(main())
'''


class BrowserActuator:
    def __init__(self, timeout: int = 120, host_override: Optional[str] = None,
                 scope_validator: Optional[Any] = None,
                 auth: Optional[Dict[str, Any]] = None):
        self.timeout = timeout
        # Optional auth injected into the browser context so SPAs are driven
        # AUTHENTICATED (headers + cookies + localStorage token). Build with
        # BrowserActuator.auth_from_ctx(ctx).
        self.auth = auth or {}
        self._driver_b64 = base64.b64encode(_DRIVER.encode()).decode()
        if host_override is None:
            try:
                from core.common.config import get_config
                host_override = get_config().get("BROWSER_HOST_OVERRIDE", "host.docker.internal")
            except Exception as e:
                logger.debug("config import for BROWSER_HOST_OVERRIDE failed: %s", e)
                host_override = "host.docker.internal"
        self.host_override = host_override
        if scope_validator is None:
            try:
                from core.security.authorization import TargetScopeValidator
                scope_validator = TargetScopeValidator.get()
            except Exception as e:
                logger.debug("TargetScopeValidator import failed: %s", e)
                scope_validator = None
        self.scope_validator = scope_validator

    @classmethod
    def auth_from_ctx(cls, ctx) -> Dict[str, Any]:
        """Build the browser auth blob from a scan context: Authorization/cookie
        headers, cookies, and a localStorage token (SPAs that store the JWT in
        localStorage, e.g. OWASP Juice Shop's `token`). Empty when unauthenticated."""
        if not ctx:
            return {}
        headers = dict(getattr(ctx, "auth_headers", {}) or {})
        cookies_map = dict(getattr(ctx, "auth_cookies", {}) or {})
        target = getattr(ctx, "target", "") or ""
        if target and not target.startswith(("http://", "https://")):
            target = "https://" + target
        origin = ""
        try:
            pu = urlparse(target.split("#")[0])
            if pu.scheme and pu.netloc:
                origin = f"{pu.scheme}://{pu.netloc}"
        except Exception:
            pass
        local_storage = {}
        authz = headers.get("Authorization", "")
        if authz.startswith("Bearer "):
            jwt = authz[len("Bearer "):]
            # Broadened key set so the JWT lands under whatever key the SPA reads.
            keys = ["token", "access_token", "authToken", "jwt",
                    "id_token", "session_token", "accessToken", "auth"]
            # Prefer the observed/captured storage key when known.
            observed = getattr(ctx, "auth_storage_key", None) or getattr(ctx, "token_storage_key", None)
            if observed and observed not in keys:
                keys.insert(0, observed)
            for k in keys:
                local_storage[k] = jwt
        cookies = []
        for name, val in cookies_map.items():
            c = {"name": str(name), "value": str(val)}
            if origin:
                c["url"] = origin
            cookies.append(c)
        ctx_headers = {k: v for k, v in headers.items() if k.lower() != "cookie"}
        blob: Dict[str, Any] = {}
        if ctx_headers:
            blob["headers"] = ctx_headers
        if cookies:
            blob["cookies"] = cookies
        if local_storage:
            blob["local_storage"] = local_storage
        return blob

    def _in_scope(self, url: str) -> bool:
        if not self.scope_validator:
            return True
        try:
            host = urlparse(url).hostname or url
            # localhost is validated as the intended target, not the rewrite host.
            self.scope_validator.validate(host)
            return True
        except Exception as e:
            logger.warning(f"[Browser] BLOCKED out-of-scope navigation '{url}': {e}")
            return False

    def _rewrite(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for a in actions:
            a = dict(a)
            url = a.get("url")
            if isinstance(url, str) and self.host_override:
                host = (urlparse(url).hostname or "").lower()
                # Only local targets need the container-reachable host rewrite;
                # deployed / public URLs are used exactly as given.
                if host in ("localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal"):
                    a["url"] = url.replace("localhost", self.host_override).replace(
                        "127.0.0.1", self.host_override)
            out.append(a)
        return out

    async def run_actions(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        # Drop no-op navigations with a blank URL: an empty target is not a scope
        # violation — validating '' would log a spurious AUTHORIZATION_DENIED and
        # abort the whole batch. Keep every other action.
        actions = [a for a in actions
                   if not (a.get("action") == "navigate"
                           and not str(a.get("url") or "").strip())]
        for a in actions:
            if a.get("action") == "navigate" and not self._in_scope(a.get("url", "")):
                return {"error": "navigation target out of authorized scope", "blocked": True}
        try:
            from agents.kali_executor import KaliDockerExecutor
        except Exception as e:
            return {"error": f"Kali executor unavailable: {e}"}

        actions_b64 = base64.b64encode(json.dumps(self._rewrite(actions)).encode()).decode()
        auth_b64 = base64.b64encode(json.dumps(self.auth or {}).encode()).decode()
        cmd = (
            f"echo {self._driver_b64} | base64 -d > /tmp/bdriver.py && "
            f"python3 /tmp/bdriver.py {actions_b64} {auth_b64}"
        )
        try:
            res = await asyncio.to_thread(KaliDockerExecutor.run, cmd, self.timeout)
        except Exception as e:
            return {"error": f"browser run failed: {e}"}

        stdout = res.get("stdout", "") or ""
        for line in stdout.splitlines():
            if line.startswith("RESULT_B64:"):
                try:
                    return json.loads(base64.b64decode(line[len("RESULT_B64:"):]))
                except Exception as e:
                    return {"error": f"result parse failed: {e}", "raw": stdout[-500:]}
        return {"error": "no browser result", "status": res.get("status"),
                "stderr": (res.get("stderr", "") or "")[-500:]}


BROWSER_TOOL = {
    "type": "function", "function": {
        "name": "browser_run",
        "description": "Drive a real headless Chromium in one session against the authorized "
                       "target (works for deployed/public URLs too). actions is an ordered "
                       'list of: {"action":"navigate","url":...}, {"action":"fill","selector":...,"value":...}, '
                       '{"action":"click","selector":...}, {"action":"eval","script":"JS returning a value"}, '
                       '{"action":"wait","ms":1000}, {"action":"dom"}, {"action":"localStorage"}. '
                       "Use for DOM XSS, CSP, and any client-side/SPA behaviour.",
        "parameters": {"type": "object", "properties": {
            "actions": {"type": "array", "items": {"type": "object"}}}, "required": ["actions"]}}
}
