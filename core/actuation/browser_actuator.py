"""
BrowserActuator — headless Chromium (Playwright) inside the Kali container,
usable against ANY authorized target: a deployed/public URL is reached directly;
only a localhost target is rewritten to a container-reachable host.

Client-side actions (DOM XSS, CSP, SPA routes, client-side logic) need a real
browser executing the app's JavaScript. A batch of actions runs in ONE session
(state preserved), returning a compact observation the agent reasons over. Targets
are scope-validated before navigation.
"""

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
    logs, results = [], []
    async with async_playwright() as p:
        browser = await p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        page = await browser.new_page()
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
                 scope_validator: Optional[Any] = None):
        self.timeout = timeout
        self._driver_b64 = base64.b64encode(_DRIVER.encode()).decode()
        if host_override is None:
            try:
                from core.common.config import get_config
                host_override = get_config().get("BROWSER_HOST_OVERRIDE", "host.docker.internal")
            except Exception:
                host_override = "host.docker.internal"
        self.host_override = host_override
        if scope_validator is None:
            try:
                from core.security.authorization import TargetScopeValidator
                scope_validator = TargetScopeValidator.get()
            except Exception:
                scope_validator = None
        self.scope_validator = scope_validator

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
        """Execute a batch of browser actions in one Chromium session (in-scope only)."""
        for a in actions:
            if a.get("action") == "navigate" and not self._in_scope(a.get("url", "")):
                return {"error": "navigation target out of authorized scope", "blocked": True}
        try:
            from agents.kali_executor import KaliDockerExecutor
        except Exception as e:
            return {"error": f"Kali executor unavailable: {e}"}

        actions_b64 = base64.b64encode(json.dumps(self._rewrite(actions)).encode()).decode()
        cmd = (
            f"echo {self._driver_b64} | base64 -d > /tmp/bdriver.py && "
            f"python3 /tmp/bdriver.py {actions_b64}"
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
