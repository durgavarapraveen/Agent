from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import urllib.request
import urllib.error


DEFAULT_TIMEOUT = 15
DEFAULT_UA = "Mozilla/5.0 (pentest-agent structured-http/1.0)"


def _request(method: str, url: str, headers: Optional[Dict[str, str]] = None,
             body: Optional[bytes] = None, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    hdrs = {"User-Agent": DEFAULT_UA}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, method=method.upper(), headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read()
            return {
                "status": resp.status,
                "headers": {k: v for k, v in resp.getheaders()},
                "body": raw.decode("utf-8", errors="replace"),
                "url": resp.geturl(),
                "content_type": resp.headers.get_content_type(),
                "size": len(raw),
            }
    except urllib.error.HTTPError as e:
        raw = e.read() if hasattr(e, "read") else b""
        return {
            "status": e.code,
            "headers": dict(e.headers) if e.headers else {},
            "body": raw.decode("utf-8", errors="replace") if raw else "",
            "url": url, "content_type": (e.headers.get_content_type() if e.headers else ""),
            "size": len(raw), "error": str(e),
        }
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "url": url,
                "content_type": "", "size": 0, "error": str(e)}


def http_get(url: str, headers: Optional[Dict[str, str]] = None,
             timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    return _request("GET", url, headers=headers, timeout=timeout)


def http_post(url: str, body: bytes = b"", headers: Optional[Dict[str, str]] = None,
              timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    return _request("POST", url, headers=headers, body=body, timeout=timeout)


class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.scripts: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        d = dict(attrs)
        if tag in ("a", "link") and d.get("href"):
            self.links.append(d["href"])
        elif tag == "script" and d.get("src"):
            self.scripts.append(d["src"])
        elif tag in ("img", "iframe", "form") and d.get("src"):
            self.links.append(d["src"])
        elif tag == "form" and d.get("action"):
            self.links.append(d["action"])


def extract_links(html: str, base_url: str = "") -> Dict[str, List[str]]:
    p = _LinkExtractor()
    try:
        p.feed(html or "")
    except Exception:
        pass
    def _abs(u: str) -> str:
        return urljoin(base_url, u) if base_url else u
    return {
        "links": [_abs(u) for u in dict.fromkeys(p.links)],
        "scripts": [_abs(u) for u in dict.fromkeys(p.scripts)],
    }


_API_RE = re.compile(r"[\"']?(/(?:api|v\d+|rest|graphql)[\w/\-\.]*)[\"']?")


def extract_api_routes(text: str) -> List[str]:
    return list(dict.fromkeys(m.group(1) for m in _API_RE.finditer(text or "")))


_FILE_LINK_RE = re.compile(r"https?://\S+\.(?:zip|tar|gz|7z|rar|bak|sql|env|log|pem|key|pdf|xlsx?|docx?)",
                           re.I)


def extract_file_links(text: str) -> List[str]:
    return list(dict.fromkeys(_FILE_LINK_RE.findall(text or "")))


def extract_regex(text: str, pattern: str, flags: int = 0) -> List[str]:
    try:
        return list(dict.fromkeys(re.compile(pattern, flags).findall(text or "")))
    except re.error:
        return []


def parse_html(html: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"title": "", "forms": [], "meta": {}, "text_sample": ""}
    m = re.search(r"<title[^>]*>([^<]{0,300})</title>", html or "", re.I | re.S)
    if m:
        out["title"] = m.group(1).strip()
    for f in re.findall(r"<form[^>]*>(.*?)</form>", html or "", re.I | re.S):
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', f, re.I)
        action_m = re.search(r'action=["\']([^"\']*)["\']', f, re.I)
        method_m = re.search(r'method=["\']([^"\']*)["\']', f, re.I)
        out["forms"].append({
            "action": action_m.group(1) if action_m else "",
            "method": (method_m.group(1) if method_m else "GET").upper(),
            "inputs": inputs,
        })
    for m in re.finditer(r'<meta[^>]*name=["\']([^"\']+)["\'][^>]*content=["\']([^"\']*)["\']',
                          html or "", re.I):
        out["meta"][m.group(1).lower()] = m.group(2)
    text = re.sub(r"<[^>]+>", " ", html or "")
    out["text_sample"] = re.sub(r"\s+", " ", text)[:512]
    return out


def parse_json(text: str) -> Optional[Any]:
    try:
        return json.loads(text)
    except Exception:
        return None


def compare_responses(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    import hashlib
    def _h(t: str) -> str:
        return hashlib.sha256((t or "").encode("utf-8", "ignore")).hexdigest()[:16]
    return {
        "status_a": a.get("status"), "status_b": b.get("status"),
        "size_a": a.get("size"), "size_b": b.get("size"),
        "body_hash_a": _h(a.get("body", "")),
        "body_hash_b": _h(b.get("body", "")),
        "same_status": a.get("status") == b.get("status"),
        "same_body": _h(a.get("body", "")) == _h(b.get("body", "")),
        "size_delta": (b.get("size") or 0) - (a.get("size") or 0),
    }


def extract_headers(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        out[k.strip().lower()] = v.strip()
    return out


# Registry the tool_router can advertise these as first-class ops.
STRUCTURED_OPS: Dict[str, Any] = {
    "http_get": http_get,
    "http_post": http_post,
    "extract_links": extract_links,
    "extract_api_routes": extract_api_routes,
    "extract_file_links": extract_file_links,
    "extract_regex": extract_regex,
    "parse_html": parse_html,
    "parse_json": parse_json,
    "compare_responses": compare_responses,
    "extract_headers": extract_headers,
}
