"""Browser-driven crawler (gaps: modern app + DOM + real workflow capture).

Drives the target like a user so the SurfaceClassifier sees REAL requests
(XHR/fetch bodies, headers, cookies), SPA routes, and forms — not just static
links. Two backends:

  * Playwright (preferred) — a real Chromium: executes JS, captures every network
    request (method/url/headers/postData), extracts forms + DOM sink markers,
    follows in-scope links to record a navigation journey (feeds WorkflowRecorder).
  * httpx fallback — no browser available: fetches pages, parses HTML for forms,
    links and script srcs. Still yields captured_requests for forms/endpoints.

Everything is scope-enforced (in-scope hosts only) and best-effort: a missing
browser or a blocked page never breaks the scan.
"""
from __future__ import annotations

import logging
import os
import re
from typing import List, Optional, Set
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

_DOM_SINKS = ("innerHTML", "document.write", "eval(", "setTimeout(", "location.href",
              "insertAdjacentHTML", "dangerouslySetInnerHTML", "postMessage")


def _same_origin(a: str, b: str) -> bool:
    try:
        pa, pb = urlparse(a), urlparse(b)
        return (pa.hostname or "").lower() == (pb.hostname or "").lower()
    except Exception:
        return False


def _in_scope(url: str) -> bool:
    try:
        from core.security.authorization import TargetScopeValidator
        host = urlparse(url).hostname or ""
        return bool(host) and TargetScopeValidator.get().is_authorized(host)
    except Exception:
        return True  # no validator configured → don't over-block a local lab


def _auth_blob(ctx) -> dict:
    """P1-E1: authenticated-crawl blob (headers/cookies/localStorage-JWT) derived
    generically from the scan context via the shared BrowserActuator helper, so
    post-login SPA routes / dashboards / admin panels are crawled too. Empty when
    unauthenticated — the crawl then runs anonymously exactly as before."""
    try:
        from core.actuation.browser_actuator import BrowserActuator
        return BrowserActuator.auth_from_ctx(ctx) or {}
    except Exception:
        return {}


async def crawl_into_context(ctx, base_url: str, max_pages: int = 40) -> int:
    """Populate ctx.captured_requests / endpoints from a crawl. Returns #requests.

    Backend preference:
      1. Playwright inside the Kali container (docker exec) — where the project
         installs Chromium (Tier-8 convention). Real JS/XHR/forms/DOM sinks.
      2. Playwright in the agent-host process (if installed here).
      3. Scoped-httpx fallback (no JS).

    When ctx carries auth (ctx.auth_sessions/auth_headers/auth_cookies), the
    browser backends inject it so the authenticated surface is crawled.
    """
    auth = _auth_blob(ctx)
    if auth:
        logger.info("Crawler: authenticated crawl (headers=%d cookies=%d ls=%d)",
                    len(auth.get("headers", {})), len(auth.get("cookies", [])),
                    len(auth.get("local_storage", {})))
    # 1. container-backed Playwright (preferred — matches the project's setup)
    if os.getenv("CRAWLER_USE_KALI", "true").lower() in ("true", "1", "yes", "on"):
        try:
            n = await _crawl_kali_container(ctx, base_url, max_pages, auth)
            if n:
                logger.info("Crawler(kali-playwright): captured %d requests", n)
                await _harvest_spa_routes(ctx, base_url)
                return n
        except Exception as e:
            logger.info("Crawler: kali-container path unavailable (%s)", e)
    # 2. host Playwright
    try:
        n = await _crawl_playwright(ctx, base_url, max_pages, auth)
        if n:
            logger.info("Crawler(host-playwright): captured %d requests", n)
            await _harvest_spa_routes(ctx, base_url)
            return n
    except Exception as e:
        logger.info("Crawler: host playwright unavailable (%s); using httpx fallback", e)
    # 3. httpx fallback
    n = await _crawl_httpx(ctx, base_url, max_pages)
    logger.info("Crawler(httpx): captured %d requests", n)
    await _harvest_spa_routes(ctx, base_url)
    return n


# ── Kali-container Playwright backend (docker exec) ──────────────────────
_KALI_CRAWL_SCRIPT = r'''
import json, sys
from urllib.parse import urljoin, urlparse
from playwright.sync_api import sync_playwright

BASE = __BASE__
MAX_PAGES = __MAXPAGES__
AUTH = __AUTH__
DOM_SINKS = ["innerHTML","document.write","eval(","setTimeout(","location.href",
             "insertAdjacentHTML","dangerouslySetInnerHTML","postMessage"]

def same_origin(a, b):
    try:
        return (urlparse(a).hostname or "") == (urlparse(b).hostname or "")
    except Exception:
        return False

requests_out, forms_out, sinks_out = [], [], {}
visited, queue = set(), [BASE]
with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
    ctx = browser.new_context(ignore_https_errors=True)
    # P1-E1: authenticated crawl — inject headers/cookies/localStorage JWT so
    # post-login routes are reachable. No-op when AUTH is empty.
    try:
        if AUTH.get("headers"):
            ctx.set_extra_http_headers(AUTH["headers"])
        if AUTH.get("cookies"):
            ctx.add_cookies(AUTH["cookies"])
        if AUTH.get("local_storage"):
            ctx.add_init_script("(() => { const d = " + json.dumps(AUTH["local_storage"]) +
                                "; for (const k in d) { try { localStorage.setItem(k, d[k]); } catch(e){} } })()")
    except Exception:
        pass
    page = ctx.new_page()
    def on_req(req):
        try:
            requests_out.append({"url": req.url, "method": req.method,
                                 "headers": dict(req.headers), "body": req.post_data})
        except Exception:
            pass
    page.on("request", on_req)
    while queue and len(visited) < MAX_PAGES:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            page.goto(url, wait_until="networkidle", timeout=15000)
        except Exception:
            continue
        try:
            forms = page.eval_on_selector_all("form", """els => els.map(f => ({
                action: f.action || '', method: (f.method||'GET').toUpperCase(),
                enctype: f.enctype || '',
                fields: Array.from(f.elements).filter(e=>e.name).map(e=>({name:e.name,type:e.type||'text',value:e.value||''}))}))""")
            for fm in forms or []:
                fm["page"] = url
                forms_out.append(fm)
        except Exception:
            pass
        try:
            html = page.content()
            present = [s for s in DOM_SINKS if s in html]
            if present:
                sinks_out[url] = present
            import re as _re
            for href in _re.findall(r'href=["\']([^"\']+)["\']', html):
                nxt = urljoin(url, href)
                if same_origin(BASE, nxt) and nxt not in visited:
                    queue.append(nxt)
        except Exception:
            pass
    browser.close()
print("__CRAWL_JSON__" + json.dumps({"requests": requests_out, "forms": forms_out, "sinks": sinks_out}))
'''


async def _crawl_kali_container(ctx, base_url: str, max_pages: int, auth: Optional[dict] = None) -> int:
    import asyncio
    import json as _json
    from core.execution.executors.generic import _run_in_kali
    # Gate on PLAYWRIGHT (with its bundled Chromium), not a system `chromium`
    # binary on PATH — Playwright ships its own browser.
    rc, out, _ = await asyncio.to_thread(
        _run_in_kali, "import playwright.sync_api as p; print('PW_OK')", 20)
    if rc != 0 or "PW_OK" not in out:
        raise RuntimeError("playwright not importable in kali container")
    script = (_KALI_CRAWL_SCRIPT
              .replace("__BASE__", _json.dumps(base_url))
              .replace("__MAXPAGES__", str(int(max_pages)))
              .replace("__AUTH__", _json.dumps(auth or {})))
    timeout = int(os.getenv("CRAWLER_TIMEOUT_S", "120"))
    rc, out, err = await asyncio.to_thread(_run_in_kali, script, timeout)
    if rc != 0:
        raise RuntimeError(f"kali crawl rc={rc}: {(err or out)[:200]}")
    marker = "__CRAWL_JSON__"
    idx = out.rfind(marker)
    if idx < 0:
        raise RuntimeError("kali crawl produced no JSON")
    data = _json.loads(out[idx + len(marker):].strip())
    return _ingest_crawl_data(ctx, data)


def _ingest_crawl_data(ctx, data: dict) -> int:
    captured = 0
    for rec in data.get("requests", []):
        if not _in_scope(rec.get("url", "")):
            continue
        try:
            ctx.add_captured_request(rec)
            captured += 1
        except Exception:
            pass
    for fm in data.get("forms", []):
        page_url = fm.get("page") or fm.get("action") or ""
        _record_form(ctx, page_url, fm)
    for url, sinks in (data.get("sinks") or {}).items():
        try:
            store = getattr(ctx, "dom_sinks", None) or {}
            store[url] = sinks
            setattr(ctx, "dom_sinks", store)
        except Exception:
            pass
    return captured


# ── Playwright backend ──────────────────────────────────────────────────
async def _crawl_playwright(ctx, base_url: str, max_pages: int, auth: Optional[dict] = None) -> int:
    from playwright.async_api import async_playwright  # ImportError → fallback
    import json as _json

    captured = 0
    visited: Set[str] = set()
    queue: List[str] = [base_url]
    auth = auth or {}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
        context = await browser.new_context(ignore_https_errors=True)
        # P1-E1: authenticated crawl — inject headers/cookies/localStorage JWT.
        try:
            if auth.get("headers"):
                await context.set_extra_http_headers(auth["headers"])
            if auth.get("cookies"):
                await context.add_cookies(auth["cookies"])
            if auth.get("local_storage"):
                await context.add_init_script(
                    "(() => { const d = " + _json.dumps(auth["local_storage"]) +
                    "; for (const k in d) { try { localStorage.setItem(k, d[k]); } catch(e){} } })()")
        except Exception:
            pass
        page = await context.new_page()

        def _on_request(req):
            nonlocal captured
            try:
                if not _in_scope(req.url):
                    return
                rec = {"url": req.url, "method": req.method,
                       "headers": dict(req.headers), "body": req.post_data}
                ctx.add_captured_request(rec)
                captured += 1
            except Exception:
                pass
        page.on("request", _on_request)

        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited or not _in_scope(url):
                continue
            visited.add(url)
            try:
                await page.goto(url, wait_until="networkidle", timeout=15000)
            except Exception:
                continue
            # forms → synthesize captured submit requests with real field names
            try:
                forms = await page.eval_on_selector_all("form", _FORM_JS)
                for fm in forms or []:
                    _record_form(ctx, url, fm)
            except Exception:
                pass
            # DOM sinks present on the page (client-side XSS surface signal)
            try:
                html = await page.content()
                _flag_dom_sinks(ctx, url, html)
                for href in re.findall(r'href=["\']([^"\']+)["\']', html):
                    nxt = urljoin(url, href)
                    if _same_origin(base_url, nxt) and nxt not in visited:
                        queue.append(nxt)
            except Exception:
                pass
        await browser.close()
    return captured


_FORM_JS = """els => els.map(f => ({
    action: f.action || '',
    method: (f.method || 'GET').toUpperCase(),
    enctype: f.enctype || '',
    fields: Array.from(f.elements).filter(e => e.name).map(e => ({
        name: e.name, type: e.type || 'text', value: e.value || ''}))
}))"""


def _record_form(ctx, page_url: str, form: dict) -> None:
    action = urljoin(page_url, form.get("action") or page_url)
    if not _in_scope(action):
        return
    method = (form.get("method") or "GET").upper()
    fields = {f["name"]: f.get("value", "") for f in form.get("fields", []) if f.get("name")}
    enctype = form.get("enctype") or ""
    rec = {"url": action, "method": method, "headers": {}, "fields": fields}
    if "multipart" in enctype or any(f.get("type") == "file" for f in form.get("fields", [])):
        rec["headers"]["Content-Type"] = "multipart/form-data"
        rec["files"] = {f["name"]: {"filename": ""} for f in form.get("fields", []) if f.get("type") == "file"}
    elif method != "GET":
        from urllib.parse import urlencode
        rec["headers"]["Content-Type"] = "application/x-www-form-urlencoded"
        rec["body"] = urlencode(fields)
    try:
        ctx.add_captured_request(rec)
    except Exception:
        pass


def _flag_dom_sinks(ctx, url: str, html: str) -> None:
    present = [s for s in _DOM_SINKS if s in html]
    if present:
        try:
            store = getattr(ctx, "dom_sinks", None)
            if store is None:
                store = {}
                setattr(ctx, "dom_sinks", store)
            store[url] = present
        except Exception:
            pass


# ── httpx fallback backend ───────────────────────────────────────────────
async def _crawl_httpx(ctx, base_url: str, max_pages: int) -> int:
    from core.security.scoped_http import get_scoped_client
    captured = 0
    visited: Set[str] = set()
    queue: List[str] = [base_url]
    async with get_scoped_client(follow_redirects=True, timeout=10, verify=False) as client:
        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited or not _in_scope(url):
                continue
            visited.add(url)
            try:
                r = await client.get(url)
            except Exception:
                continue
            try:
                ctx.add_captured_request({"url": url, "method": "GET",
                                          "headers": dict(r.request.headers)})
                captured += 1
            except Exception:
                pass
            html = getattr(r, "text", "") or ""
            _flag_dom_sinks(ctx, url, html)
            for fm in _parse_forms_html(url, html):
                _record_form(ctx, url, fm)
                captured += 1
            for href in re.findall(r'href=["\']([^"\']+)["\']', html):
                nxt = urljoin(url, href)
                if _same_origin(base_url, nxt) and nxt not in visited and len(queue) < max_pages:
                    queue.append(nxt)
    return captured


# ── F-X1: SPA client-side route harvesting ───────────────────────────────
# SPA XSS (DOM/reflected) lives on client-side router routes (e.g. #/search?q=),
# not on the JSON API endpoints. The router table ships inside the JS bundles, so
# we fetch every same-origin script and mine route paths. Framework-agnostic:
# Angular/Vue `{ path: 'x' }`, React-Router `<Route path="x">` / `path:"x"`.
_ROUTE_PATTERNS = (
    re.compile(r"""\bpath\s*:\s*['"]([^'"]{0,120})['"]"""),      # Angular/Vue/React config
    re.compile(r"""<Route[^>]*\bpath\s*=\s*['"]([^'"]{0,120})['"]"""),  # JSX
)
# Never treat these as navigable content routes.
_ROUTE_SKIP = re.compile(r"^(?:\*\*?$|https?:|//|\.|#$)")


def _mine_routes(js_text: str) -> Set[str]:
    out: Set[str] = set()
    for pat in _ROUTE_PATTERNS:
        for m in pat.findall(js_text or ""):
            r = m.strip().lstrip("/")
            if not r or _ROUTE_SKIP.match(r) or len(r) > 80:
                continue
            # keep route-shaped tokens (segments, optional :params); drop globs/urls
            # and file-path-ish tokens (a "." → asset path, not a router route).
            if "." not in r and re.fullmatch(r"[A-Za-z0-9_\-:/]+", r):
                out.add(r)
    return out


async def _harvest_spa_routes(ctx, base_url: str, cap: int = 80) -> None:
    """Fetch same-origin JS bundles referenced by the base page, mine router
    paths, and store them on ctx.spa_routes (idempotent, best-effort)."""
    if getattr(ctx, "_spa_routes_done", False):
        return
    setattr(ctx, "_spa_routes_done", True)
    from core.security.scoped_http import get_scoped_client
    routes: Set[str] = set()
    try:
        async with get_scoped_client(follow_redirects=True, timeout=10, verify=False) as client:
            r = await client.get(base_url)
            html = getattr(r, "text", "") or ""
            srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
            # de-dup, resolve, keep in-scope only, cap the number of bundles fetched
            seen: Set[str] = set()
            js_urls: List[str] = []
            for s in srcs:
                ju = urljoin(base_url, s)
                if ju not in seen and _same_origin(base_url, ju) and ju.split("?")[0].endswith(".js"):
                    seen.add(ju); js_urls.append(ju)
            for ju in js_urls[:12]:
                try:
                    jr = await client.get(ju)
                    routes |= _mine_routes(getattr(jr, "text", "") or "")
                except Exception:
                    continue
    except Exception as e:
        logger.debug("[Crawler] SPA route harvest failed: %s", e)
        return
    if routes:
        try:
            existing = set(getattr(ctx, "spa_routes", None) or [])
            merged = sorted(existing | routes)[:cap]
            setattr(ctx, "spa_routes", merged)
            logger.info("[Crawler] harvested %d SPA route(s) from JS bundles", len(merged))
        except Exception:
            pass


def _parse_forms_html(page_url: str, html: str) -> List[dict]:
    forms = []
    for attrs, body in re.findall(r"<form\b([^>]*)>(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
        action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
        method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
        enctype_m = re.search(r'enctype=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
        fields = []
        for inp in re.findall(r'<(?:input|textarea|select)\b[^>]*>', body, re.IGNORECASE):
            nm = re.search(r'name=["\']([^"\']+)["\']', inp, re.IGNORECASE)
            tp = re.search(r'type=["\']([^"\']+)["\']', inp, re.IGNORECASE)
            if nm:
                fields.append({"name": nm.group(1), "type": (tp.group(1) if tp else "text"), "value": ""})
        forms.append({"action": action_m.group(1) if action_m else page_url,
                      "method": (method_m.group(1) if method_m else "GET").upper(),
                      "enctype": enctype_m.group(1) if enctype_m else "",
                      "fields": fields})
    return forms
