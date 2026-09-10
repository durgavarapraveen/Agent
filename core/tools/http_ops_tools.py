from __future__ import annotations

import json
import logging
from typing import Any, Dict

from core.tools.tool_registry import Tool, ToolResult
from core.tools.http_ops import (
    http_get, http_post, extract_links, extract_api_routes,
    extract_file_links, extract_regex, parse_html, parse_json,
    compare_responses, extract_headers,
)

logger = logging.getLogger(__name__)


def _ok(data: Dict[str, Any]) -> ToolResult:
    return ToolResult(
        success=True,
        output=json.dumps(data, default=str)[:20000],
        error="",
        data=data if isinstance(data, dict) else {"result": data},
    )


def _fail(msg: str) -> ToolResult:
    return ToolResult(success=False, output="", error=msg, data={"error": msg})


class _HttpFetchTool(Tool):
    def __init__(self):
        super().__init__("http_fetch",
                          "Structured HTTP GET/POST. Returns status, headers, body, size.",
                          "util")

    def run(self, target: str = "", url: str = "", method: str = "GET",
            body: str = "", headers: Any = None, timeout: int = 15,
            **kwargs) -> ToolResult:
        u = url or target or kwargs.get("uri", "")
        if not u:
            return _fail("http_fetch requires 'url' or 'target'")
        hdrs = headers if isinstance(headers, dict) else None
        try:
            m = (method or "GET").upper()
            if m == "POST":
                resp = http_post(u, body=(body or "").encode("utf-8"),
                                 headers=hdrs, timeout=timeout)
            else:
                resp = http_get(u, headers=hdrs, timeout=timeout)
            return _ok(resp)
        except Exception as e:
            return _fail(f"http_fetch error: {e}")


class _ExtractLinksTool(Tool):
    def __init__(self):
        super().__init__("extract_links",
                          "Extract every href / <script src> / <form action> from HTML.",
                          "util")

    def run(self, html: str = "", base_url: str = "", target: str = "",
            timeout: int = 15, **kwargs) -> ToolResult:
        h = html
        base = base_url or target
        if not h and (target or base_url):
            resp = http_get(target or base_url, timeout=timeout)
            h = resp.get("body", "")
            base = base or resp.get("url", "")
        if not h:
            return _fail("extract_links requires 'html' or 'target'")
        return _ok(extract_links(h, base_url=base or ""))


class _ExtractApiRoutesTool(Tool):
    def __init__(self):
        super().__init__("extract_api_routes",
                          "Regex out `/api/...`, `/v1/...`, `/rest/...`, `/graphql` "
                          "routes from arbitrary text (HTML, JS, JSON).", "util")

    def run(self, text: str = "", target: str = "", timeout: int = 15,
            **kwargs) -> ToolResult:
        t = text
        if not t and target:
            t = http_get(target, timeout=timeout).get("body", "")
        if not t:
            return _fail("extract_api_routes requires 'text' or 'target'")
        return _ok({"routes": extract_api_routes(t)})


class _ExtractFileLinksTool(Tool):
    def __init__(self):
        super().__init__("extract_file_links",
                          "Find downloadable-file URLs (.zip/.sql/.env/.bak/…) in text.",
                          "util")

    def run(self, text: str = "", target: str = "", timeout: int = 15,
            **kwargs) -> ToolResult:
        t = text
        if not t and target:
            t = http_get(target, timeout=timeout).get("body", "")
        if not t:
            return _fail("extract_file_links requires 'text' or 'target'")
        return _ok({"files": extract_file_links(t)})


class _ExtractRegexTool(Tool):
    def __init__(self):
        super().__init__("extract_regex",
                          "Apply a regex to text. Regex is sandboxed via python `re`. "
                          "Returns deduplicated matches.", "util")

    def run(self, text: str = "", pattern: str = "", flags: int = 0,
            target: str = "", timeout: int = 15, **kwargs) -> ToolResult:
        if not pattern:
            return _fail("extract_regex requires 'pattern'")
        t = text
        if not t and target:
            t = http_get(target, timeout=timeout).get("body", "")
        if not t:
            return _fail("extract_regex requires 'text' or 'target'")
        return _ok({"matches": extract_regex(t, pattern, flags=int(flags or 0))})


class _ParseHtmlTool(Tool):
    def __init__(self):
        super().__init__("parse_html",
                          "Extract title, forms, meta tags, and a text sample "
                          "from an HTML document.", "util")

    def run(self, html: str = "", target: str = "", timeout: int = 15,
            **kwargs) -> ToolResult:
        h = html
        if not h and target:
            h = http_get(target, timeout=timeout).get("body", "")
        if not h:
            return _fail("parse_html requires 'html' or 'target'")
        return _ok(parse_html(h))


class _ParseJsonTool(Tool):
    def __init__(self):
        super().__init__("parse_json",
                          "Parse JSON text into a structured value.", "util")

    def run(self, text: str = "", target: str = "", timeout: int = 15,
            **kwargs) -> ToolResult:
        t = text
        if not t and target:
            t = http_get(target, timeout=timeout).get("body", "")
        if not t:
            return _fail("parse_json requires 'text' or 'target'")
        parsed = parse_json(t)
        if parsed is None:
            return _fail("parse_json: invalid JSON")
        return _ok({"parsed": parsed})


class _CompareResponsesTool(Tool):
    def __init__(self):
        super().__init__("compare_responses",
                          "Diff two http_fetch results (status, size, body-hash). "
                          "Use for IDOR / authz confirmation.", "util")

    def run(self, url_a: str = "", url_b: str = "", a: Any = None, b: Any = None,
            headers_a: Any = None, headers_b: Any = None,
            timeout: int = 15, **kwargs) -> ToolResult:
        ra = a if isinstance(a, dict) else None
        rb = b if isinstance(b, dict) else None
        if ra is None and url_a:
            ra = http_get(url_a,
                          headers=headers_a if isinstance(headers_a, dict) else None,
                          timeout=timeout)
        if rb is None and url_b:
            rb = http_get(url_b,
                          headers=headers_b if isinstance(headers_b, dict) else None,
                          timeout=timeout)
        if ra is None or rb is None:
            return _fail("compare_responses requires 'url_a'+'url_b' or 'a'+'b' dicts")
        return _ok(compare_responses(ra, rb))


class _ExtractHeadersTool(Tool):
    def __init__(self):
        super().__init__("extract_headers",
                          "Parse a raw HTTP response header block into a dict.", "util")

    def run(self, text: str = "", target: str = "", timeout: int = 15,
            **kwargs) -> ToolResult:
        if target and not text:
            resp = http_get(target, timeout=timeout)
            return _ok({"headers": resp.get("headers", {})})
        if not text:
            return _fail("extract_headers requires 'text' or 'target'")
        return _ok({"headers": extract_headers(text)})


# Public list — one instance per adapter.
def build_structured_http_tools():
    return [
        _HttpFetchTool(),
        _ExtractLinksTool(),
        _ExtractApiRoutesTool(),
        _ExtractFileLinksTool(),
        _ExtractRegexTool(),
        _ParseHtmlTool(),
        _ParseJsonTool(),
        _CompareResponsesTool(),
        _ExtractHeadersTool(),
    ]


def register_structured_http_tools(registry) -> int:
    n = 0
    for t in build_structured_http_tools():
        try:
            if not registry.get(t.name):
                registry.register(t)
                n += 1
        except Exception as e:
            logger.warning(f"register {t.name} failed: {e}")
    logger.info(f"[StructuredHTTP] registered {n} structured HTTP tools")
    return n
