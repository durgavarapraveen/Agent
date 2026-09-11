from __future__ import annotations
import re
from typing import Any, Dict, List, Set

# Keyword classifiers — each role has a set of substrings we look for in the
# lower-cased path. Multi-word hits ("user/login") count as one role assignment.
_ROLE_KEYWORDS: Dict[str, List[str]] = {
    "login": [
        "/login", "/signin", "/sign-in", "/logon", "/log-in",
        "/user/login", "/users/login", "/account/login", "/session",
        "/auth/login", "/authenticate", "/oauth/token", "/oauth2/token",
        "/token", "/api/login", "/rest/login", "/rest/user/login",
        "/api/auth", "/api/authenticate", "/api/session",
    ],
    "register": [
        "/register", "/signup", "/sign-up", "/create-account", "/users/new",
        "/api/register", "/api/signup", "/api/users", "/users/create",
        "/rest/user/register",
    ],
    "logout": [
        "/logout", "/signout", "/sign-out", "/api/logout",
    ],
    "password_reset": [
        "/reset", "/forgot", "/password/forgot", "/password/reset",
        "/account/recover", "/user/reset",
    ],
    "user_profile": [
        "/me", "/whoami", "/profile", "/account", "/user", "/users/",
        "/api/me", "/api/user", "/api/users", "/api/account", "/rest/user",
    ],
    "admin": [
        "/admin", "/administration", "/administrator", "/api/admin",
        "/rest/admin", "/manage", "/dashboard/admin", "/backend",
        "/api/v1/admin", "/console",
    ],
    "captcha": [
        "/captcha", "/rest/captcha", "/api/captcha", "/challenge",
        "/verify-captcha", "/turnstile", "/recaptcha", "/hcaptcha",
    ],
    "upload": [
        "/upload", "/files", "/attachments", "/api/upload", "/media",
    ],
    "search": [
        "/search", "/api/search", "/query", "/find",
    ],
    "redirect": [
        "/redirect", "/redir", "/goto", "/link", "/url", "/out",
        "/api/redirect",
    ],
}


def _base_or_scheme(ctx, path: str) -> str:
    if path.startswith(("http://", "https://")):
        return path
    t = getattr(ctx, "target", "") or ""
    if not t:
        return path
    if not t.startswith(("http://", "https://")):
        t = f"https://{t}"
    if not path.startswith("/"):
        path = "/" + path
    return t.rstrip("/") + path


def _lower_paths_from_ctx(ctx) -> Set[str]:
    out: Set[str] = set()
    # 1. Captured HTTP requests + LLM-planned endpoint catalog
    for src in ("captured_requests", "endpoint_catalog"):
        for r in (getattr(ctx, src, None) or []):
            u = None
            if isinstance(r, dict):
                u = r.get("url") or r.get("uri")
            elif hasattr(r, "url"):
                u = getattr(r, "url", None)
            elif isinstance(r, str):
                u = r
            if u and u.startswith(("http://", "https://")):
                out.add(u.split("?")[0].lower())
    # 2. Endpoints written by the LLM extractor / tool result parsers
    for e in (getattr(ctx, "endpoints", None) or []):
        u = e if isinstance(e, str) else (e.get("url") if isinstance(e, dict) else None)
        if u:
            u_full = _base_or_scheme(ctx, u)
            if u_full.startswith(("http://", "https://")):
                out.add(u_full.split("?")[0].lower())
    # 3. Directory bruteforce discoveries (ffuf, gobuster, dirsearch, feroxbuster,
    #    dirb, nikto) land in ctx.directories as {path, status} dicts or bare
    #    path strings. Also katana crawl fills ctx.crawled_pages.
    for src in ("directories", "crawled_pages", "urls", "discovered_urls"):
        for r in (getattr(ctx, src, None) or []):
            u = None
            if isinstance(r, str):
                u = r
            elif isinstance(r, dict):
                u = r.get("url") or r.get("path") or r.get("uri")
            if u:
                u_full = _base_or_scheme(ctx, u)
                if u_full.startswith(("http://", "https://")):
                    out.add(u_full.split("?")[0].lower())
    # 4. Endpoint discoveries stored inside tool_results by tool name
    for tool_name, res in (getattr(ctx, "tool_results", {}) or {}).items():
        if not isinstance(res, dict):
            continue
        for key in ("endpoints", "paths", "urls", "found"):
            for u in (res.get(key) or []):
                if isinstance(u, dict):
                    u = u.get("url") or u.get("path")
                if isinstance(u, str) and u:
                    u_full = _base_or_scheme(ctx, u)
                    if u_full.startswith(("http://", "https://")):
                        out.add(u_full.split("?")[0].lower())
    return out


def _matches_role(path: str, role: str) -> bool:
    kws = _ROLE_KEYWORDS.get(role, [])
    return any(k in path for k in kws)


def _base_url(ctx) -> str:
    t = getattr(ctx, "target", "") or ""
    if t and not t.startswith(("http://", "https://")):
        t = f"https://{t}"
    return t.rstrip("/")


def discover_endpoints(ctx, role: str, *,
                        include_fallback: bool = True,
                        max_results: int = 50) -> List[str]:
    discovered = _lower_paths_from_ctx(ctx)
    matched = [u for u in discovered if _matches_role(u, role)]
    if matched:
        return sorted(set(matched))[:max_results]
    if not include_fallback:
        return []
    base = _base_url(ctx)
    if not base:
        return []
    return [base + p for p in _ROLE_KEYWORDS.get(role, [])[:max_results]]


def discover_authenticated_endpoints(ctx, *, limit: int = 40) -> List[str]:
    return list(dict.fromkeys(
        discover_endpoints(ctx, "user_profile") +
        discover_endpoints(ctx, "admin")
    ))[:limit]


def discover_json_post_endpoints(ctx, *, limit: int = 40) -> List[str]:
    out: Set[str] = set()
    for r in (getattr(ctx, "captured_requests", None) or []):
        if not isinstance(r, dict):
            r = getattr(r, "__dict__", {}) or {}
        method = (r.get("method") or "GET").upper()
        u = r.get("url") or ""
        if u and method in ("POST", "PUT", "PATCH"):
            out.add(u.split("?")[0])
    return sorted(out)[:limit]


def looks_like_captcha_response(text: str) -> bool:
    if not text:
        return False
    sig = re.compile(
        r"(g-recaptcha|hcaptcha|cf-turnstile|captcha\s+(required|challenge|failed|invalid|answer)|"
        r"solve.*captcha|captchaId|captchaAnswer)",
        re.IGNORECASE)
    return bool(sig.search(text))


def looks_like_captcha_disclosure(json_body: Any) -> Dict[str, Any]:
    if not isinstance(json_body, dict):
        return {}
    answer = (json_body.get("answer") or json_body.get("solution")
              or json_body.get("captcha") or json_body.get("captchaAnswer"))
    cid = (json_body.get("captchaId") or json_body.get("id")
           or json_body.get("challenge_id"))
    if answer is not None and cid is not None:
        return {"captcha_id": cid, "answer": str(answer)}
    return {}
