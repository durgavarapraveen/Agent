"""
HTTP Request Capture / Interception

Drives a headless Chromium (Playwright, inside the Kali container) across the
site, intercepting EVERY network request each page makes — navigations, XHR/
fetch API calls, form posts, and CORS pre-flight (OPTIONS) requests. Builds a
deduplicated request inventory that exploit agents can replay and fuzz.

Crawl is same-origin and bounded (max_pages / max_depth). The captured requests
(method, URL, headers, body, resource type, response status) are stored in
SharedContext so later phases can reuse real, authenticated requests.

The Playwright script is shipped into the container base64-encoded and piped to
python3 (`echo <b64> | base64 -d | python3`) — quote-free, so it survives
Windows cmd.exe + `bash -c` without escaping problems. A watchdog thread inside
the script guarantees termination.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

from agents.kali_executor import KaliDockerExecutor

logger = logging.getLogger(__name__)


# The interception script that runs INSIDE the container. Placeholders are
# substituted with json.dumps'd literals so no manual quoting is needed.
_CAPTURE_SCRIPT = r'''
import json, sys, threading, os
from urllib.parse import urlparse

START = __START__
MAX_PAGES = __MAX_PAGES__
MAX_DEPTH = __MAX_DEPTH__
NETIDLE_MS = __NETIDLE_MS__
GOTO_MS = __GOTO_MS__
DEADLINE = __DEADLINE__

# Hard watchdog: guarantee the process exits even if the browser wedges.
def _watchdog():
    import time
    time.sleep(DEADLINE)
    try:
        print(json.dumps({"pages": _pages, "requests": _requests,
                          "watchdog": True}))
    except Exception:
        pass
    os._exit(0)

_requests = []
_pages = []
_seen = set()
_status = {}
threading.Thread(target=_watchdog, daemon=True).start()

base_host = urlparse(START).netloc

def same_origin(u):
    try:
        return urlparse(u).netloc == base_host
    except Exception:
        return False

try:
    from playwright.sync_api import sync_playwright
except Exception as e:
    print(json.dumps({"error": "playwright not available: %s" % e,
                     "pages": [], "requests": []}))
    os._exit(0)

def on_request(req):
    try:
        body = req.post_data or ""
        key = (req.method, req.url, body[:200])
        if key in _seen:
            return
        _seen.add(key)
        _requests.append({
            "method": req.method,
            "url": req.url,
            "resource_type": req.resource_type,
            "is_preflight": req.method == "OPTIONS",
            "headers": dict(req.headers),
            "post_data": body[:4000],
        })
    except Exception:
        pass

def on_response(resp):
    try:
        _status[resp.url] = resp.status
    except Exception:
        pass

with sync_playwright() as p:
    b = p.chromium.launch(headless=True,
                          args=["--no-sandbox", "--ignore-certificate-errors"])
    ctx = b.new_context(ignore_https_errors=True)
    ctx.on("request", on_request)
    ctx.on("response", on_response)

    visited = set()
    queue = [(START, 0)]
    while queue and len(visited) < MAX_PAGES:
        url, depth = queue.pop(0)
        if url in visited or depth > MAX_DEPTH:
            continue
        visited.add(url)
        page = ctx.new_page()
        try:
            page.goto(url, timeout=GOTO_MS, wait_until="domcontentloaded")
            try:
                page.wait_for_load_state("networkidle", timeout=NETIDLE_MS)
            except Exception:
                pass
            _pages.append(url)
            try:
                hrefs = page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)")
            except Exception:
                hrefs = []
            for h in hrefs:
                if same_origin(h) and h not in visited:
                    queue.append((h, depth + 1))
        except Exception:
            pass
        finally:
            try:
                page.close()
            except Exception:
                pass

    for r in _requests:
        r["status"] = _status.get(r["url"], 0)
    try:
        b.close()
    except Exception:
        pass

print(json.dumps({"pages": _pages, "requests": _requests}))
'''


@dataclass
class CapturedRequest:
    method: str
    url: str
    resource_type: str = ""
    is_preflight: bool = False
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    post_data: str = ""

    def to_dict(self) -> Dict:
        return {
            "method": self.method, "url": self.url,
            "resource_type": self.resource_type, "is_preflight": self.is_preflight,
            "status": self.status, "headers": self.headers,
            "post_data": self.post_data,
        }


@dataclass
class CaptureResult:
    start_url: str
    pages: List[str] = field(default_factory=list)
    requests: List[CapturedRequest] = field(default_factory=list)
    error: str = ""

    def api_requests(self) -> List[CapturedRequest]:
        """Just the interesting (XHR/fetch/API/non-GET/preflight) requests."""
        out = []
        for r in self.requests:
            if (r.resource_type in ("xhr", "fetch")
                    or r.method not in ("GET",)
                    or r.is_preflight):
                out.append(r)
        return out

    def to_dict(self) -> Dict:
        return {"start_url": self.start_url, "pages": self.pages,
                "requests": [r.to_dict() for r in self.requests],
                "api_requests": len(self.api_requests()), "error": self.error}


class RequestCapturer:
    """Crawls a site and intercepts all network requests via Playwright."""

    def __init__(self, max_pages: int = 12, max_depth: int = 2,
                 netidle_ms: int = 2500, goto_ms: int = 12000):
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.netidle_ms = netidle_ms
        self.goto_ms = goto_ms

    def _build_command(self, start_url: str, deadline_s: int) -> str:
        script = (_CAPTURE_SCRIPT
                  .replace("__START__", json.dumps(start_url))
                  .replace("__MAX_PAGES__", str(self.max_pages))
                  .replace("__MAX_DEPTH__", str(self.max_depth))
                  .replace("__NETIDLE_MS__", str(self.netidle_ms))
                  .replace("__GOTO_MS__", str(self.goto_ms))
                  .replace("__DEADLINE__", str(deadline_s)))
        b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
        # Quote-free command: survives Windows cmd.exe + container bash -c.
        return f"echo {b64} | base64 -d | python3"

    def capture(self, start_url: str) -> CaptureResult:
        """Run the crawl+intercept (blocking). Safe to call via asyncio.to_thread."""
        # Total budget: per-page worst case, capped; watchdog fires just under it.
        budget = min(600, self.max_pages * (self.goto_ms + self.netidle_ms) // 1000 + 20)
        deadline = max(20, budget - 8)
        cmd = self._build_command(start_url, deadline)
        logger.info(f"[capture] Intercepting requests on {start_url} "
                    f"(max_pages={self.max_pages}, depth={self.max_depth})")
        r = KaliDockerExecutor.run(cmd, timeout=budget, auto_install=True)
        stdout = (r.get("stdout") or "").strip()
        if not stdout:
            err = r.get("stderr") or r.get("error") or "no output"
            logger.warning(f"[capture] no data from {start_url}: {str(err)[:200]}")
            return CaptureResult(start_url, error=str(err)[:300])

        # The JSON object is the last line printed.
        payload = None
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    payload = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
        if payload is None:
            return CaptureResult(start_url, error="could not parse capture output")
        if payload.get("error"):
            return CaptureResult(start_url, error=str(payload["error"])[:300])

        reqs = [CapturedRequest(
            method=q.get("method", "GET"), url=q.get("url", ""),
            resource_type=q.get("resource_type", ""),
            is_preflight=bool(q.get("is_preflight")),
            status=int(q.get("status", 0) or 0),
            headers=q.get("headers", {}) or {},
            post_data=q.get("post_data", "") or "",
        ) for q in payload.get("requests", [])]
        result = CaptureResult(start_url, payload.get("pages", []), reqs)
        logger.info(f"[capture] {start_url}: {len(result.pages)} pages, "
                    f"{len(reqs)} requests ({len(result.api_requests())} API/XHR)")
        return result

    def store(self, result: CaptureResult, ctx) -> None:
        """Persist captured requests into SharedContext for reuse in exploits."""
        if not result.requests:
            return
        if hasattr(ctx, "add_captured_requests"):
            ctx.add_captured_requests([r.to_dict() for r in result.requests],
                                      pages=result.pages)
        # Also surface API/XHR endpoints into the standard endpoint list.
        endpoints = []
        for r in result.api_requests():
            endpoints.append({"url": r.url, "method": r.method,
                              "params": "", "status": r.status})
        if endpoints and hasattr(ctx, "add_endpoints"):
            ctx.add_endpoints(endpoints, source="request_capture")
