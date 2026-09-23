"""Discovery-driven target-shape classifiers.

Replaces the hardcoded path/param **substring gates** scattered across the probes
and the coverage engine (e.g. `"/api/" in path`, `"file" in param_name`,
`"login" in url`, numeric-only id regexes, role literals `"administrator"`). Those
gates silently skip whole test classes on any target that names things
differently — the modern default.

Everything here is deterministic and signal-based, so it is safe to call on
per-endpoint hot loops (no network, no LLM). Where a decision is genuinely
ambiguous AND the caller is async, the `jev_*` helpers offer an optional Jev
(System-One) classifier fallback — opt-in, best-effort, returns None on any
failure.
"""
from __future__ import annotations

import os
import re
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse


def _env_names(var: str) -> Set[str]:
    """Operator-supplied extra names (comma/space separated) for the truly
    unknowable naming conventions — e.g. NEO_ADMIN_ROLES=wizard,level5. Lets a
    target with a non-standard convention be declared without code changes."""
    raw = os.getenv(var, "") or ""
    return {t.strip().lower() for t in re.split(r'[,\s]+', raw) if t.strip()}


def _path_of(url: str) -> str:
    u = str(url or "")
    if "://" in u:
        return urlparse(u).path or ""
    return u if u.startswith("/") else "/" + u


# ── ID shapes ──────────────────────────────────────────────────────────────
_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
_OBJECTID_RE = re.compile(r'^[0-9a-f]{24}$', re.I)
_ULID_RE = re.compile(r'^[0-9A-HJKMNP-TV-Z]{26}$')          # Crockford base32
_NUM_RE = re.compile(r'^\d{1,19}$')
_HEXID_RE = re.compile(r'^[0-9a-f]{16,64}$', re.I)
_SLUGID_RE = re.compile(r'^[A-Za-z0-9]{8,}[-_][A-Za-z0-9\-_]{4,}$')  # hashid/nanoid-ish


def looks_like_id(value: str) -> bool:
    """True if `value` looks like an object identifier: numeric, UUID, Mongo
    ObjectId, ULID, long hex, or hashid/nanoid — not just a sequential int."""
    v = str(value or "").strip()
    if not v or len(v) > 128:
        return False
    return bool(_NUM_RE.match(v) or _UUID_RE.match(v) or _OBJECTID_RE.match(v)
                or _ULID_RE.match(v) or _HEXID_RE.match(v) or _SLUGID_RE.match(v))


def is_numeric_id(value: str) -> bool:
    return bool(_NUM_RE.match(str(value or "").strip()))


def id_path_segments(url: str) -> List[Tuple[int, str]]:
    """Return [(segment_index, value)] for path segments that look like an id."""
    segs = [s for s in _path_of(url).split("/") if s]
    return [(i, s) for i, s in enumerate(segs) if looks_like_id(s)]


# ── parameter semantic classes (name OR value shape) ────────────────────────
_REDIRECT_NAMES = {
    "url", "redirect", "redir", "next", "goto", "dest", "destination", "return",
    "returnurl", "return_url", "returnto", "rurl", "callback", "continue",
    "target", "forward", "successurl", "success_url", "back", "out", "link",
    "to", "u", "redirect_uri", "redirect_url", "checkout_url", "image_url",
}
_FILE_NAMES = {
    "file", "filename", "path", "filepath", "file_path", "doc", "document",
    "download", "template", "page", "include", "load", "view", "attachment",
    "img", "image", "photo", "avatar", "media", "f", "name", "resource",
    "asset", "dir", "folder", "read", "content", "src", "location", "pg",
}
_CMD_NAMES = {
    "cmd", "command", "exec", "execute", "run", "host", "ip", "ping", "domain",
    "query", "q", "action", "func", "do", "op", "system", "shell", "proc",
    "process", "task", "job", "script", "code", "eval", "expr", "target", "url",
}
_SEARCH_NAMES = {"q", "s", "search", "query", "keyword", "term", "find", "lookup", "filter", "text"}


def _has_url_value(v: str) -> bool:
    return bool(re.search(r'https?://|^//|%2f%2f|\.\./', str(v or ""), re.I))


def _has_path_value(v: str) -> bool:
    return bool(re.search(
        r'\.\./|\.\.\\|/etc/|/proc/|\\windows\\|'
        r'\.(php|txt|log|conf|ini|xml|json|ya?ml|env|bak|pem|key)\b|^/[a-z]',
        str(v or ""), re.I))


# Operator overrides for non-standard param naming conventions.
_REDIRECT_NAMES |= _env_names("NEO_REDIRECT_PARAMS")
_FILE_NAMES |= _env_names("NEO_FILE_PARAMS")
_CMD_NAMES |= _env_names("NEO_CMD_PARAMS")
_SEARCH_NAMES |= _env_names("NEO_SEARCH_PARAMS")


def is_redirect_param(name: str, value: str = "") -> bool:
    # Value shape (a URL) is authoritative regardless of the param's name, so a
    # non-standard name like "backTo"/"nextPage" is still caught when it carries
    # a URL. Name-set is the booster.
    return _has_url_value(value) or str(name or "").lower() in _REDIRECT_NAMES


def is_file_param(name: str, value: str = "") -> bool:
    # Path-like value is authoritative → unknown names holding a path still hit.
    return _has_path_value(value) or str(name or "").lower() in _FILE_NAMES


def is_cmd_param(name: str, value: str = "") -> bool:
    """Weak hint only — command injection can live in ANY param. Callers should
    treat a False here as "still worth testing in non-FAST modes", not "skip"."""
    return str(name or "").lower() in _CMD_NAMES


def is_search_param(name: str, value: str = "") -> bool:
    return str(name or "").lower() in _SEARCH_NAMES


# ── endpoint role classifiers (discovery-signal, not path-only) ─────────────
_API_PATH_RE = re.compile(
    r'/(api|rest|v\d+|graphql|gql|bff|svc|service|services|backend|rpc|gateway|'
    r'ajax|xhr|internal|data)\b', re.I)
_LOGIN_PATH_RE = re.compile(
    r'/(login|log-in|log_in|logon|signin|sign-in|sign_in|authenticate|auth|'
    r'session|sessions|oauth/token|oauth2/token|connect/token|token|'
    r'account/sign_in)\b', re.I)
_PRIV_PATH_RE = re.compile(
    r'/(admin|administrat|manage|management|backend|backoffice|back-office|'
    r'console|staff|ops|internal|superuser|super-admin|superadmin|moderat|'
    r'dashboard|roles?|permissions?|grants?|config|settings|billing|'
    r'wp-admin|phpmyadmin)\b', re.I)


def _resp_content_type(resp) -> str:
    try:
        h = getattr(resp, "headers", None) or {}
        get = getattr(h, "get", None)
        if get:
            return str(get("content-type") or get("Content-Type") or "")
    except Exception:
        pass
    return ""


def resp_is_json(resp) -> bool:
    ct = _resp_content_type(resp).lower()
    return "json" in ct or "graphql" in ct or "+json" in ct


def is_api_endpoint(url: str, resp=None, ctx=None) -> bool:
    """API iff any signal fires: API-ish path, api.* host, JSON/GraphQL response,
    or a captured XHR/fetch to this URL. Not path-prefix only."""
    u = str(url or "")
    if _API_PATH_RE.search(_path_of(u)):
        return True
    host = urlparse(u).netloc.lower() if "://" in u else ""
    if host.startswith(("api.", "api-", "gql.", "graphql.")) or ".api." in host:
        return True
    if resp is not None and resp_is_json(resp):
        return True
    if ctx is not None and _captured_json_hit(ctx, u):
        return True
    return False


def _captured_json_hit(ctx, url: str) -> bool:
    try:
        base = url.split("?")[0].lower()
        for r in (getattr(ctx, "captured_requests", None) or []):
            d = r if isinstance(r, dict) else getattr(r, "__dict__", {}) or {}
            ru = str(d.get("url") or "").split("?")[0].lower()
            if ru and ru == base:
                ct = str(d.get("content_type") or d.get("response_content_type") or "")
                if "json" in ct.lower() or (d.get("xhr") or d.get("is_xhr")):
                    return True
    except Exception:
        pass
    return False


def is_login_endpoint(url: str, method: str = "", body: str = "", resp=None) -> bool:
    """Login iff path hint, OR a credential body (password / grant_type), OR a
    POST that sets a session cookie."""
    if _LOGIN_PATH_RE.search(_path_of(url)):
        return True
    b = str(body or "").lower()
    if "password" in b or "passwd" in b or "grant_type" in b or '"pwd"' in b:
        return True
    if str(method or "").upper() == "POST" and resp is not None:
        try:
            h = getattr(resp, "headers", None) or {}
            sc = ""
            if hasattr(h, "get_list"):
                sc = " ".join(h.get_list("set-cookie"))
            else:
                sc = str((h.get("set-cookie") if hasattr(h, "get") else "") or "")
            if re.search(r'(sess|sid|auth|token|jwt)', sc, re.I):
                return True
        except Exception:
            pass
    return False


def is_privileged_path(url: str, ctx=None) -> bool:
    """Privileged/admin surface by broadened keyword set (covers backoffice,
    console, staff, ops, internal, superuser, localized-agnostic stems)."""
    return bool(_PRIV_PATH_RE.search(_path_of(url)))


# ── role ranking (relative privilege, not fixed literals) ───────────────────
_ADMIN_TOKENS = ("admin", "administrat", "superuser", "super-admin", "superadmin",
                 "root", "owner", "staff", "ops", "moderator", "manager",
                 "supervisor", "operator", "sysadmin", "backoffice", "elevated",
                 "privileged", "poweruser", "power-user", "maintainer")
_ANON_TOKENS = ("anon", "anonymous", "guest", "public", "unauth", "visitor", "none")
# Operator overrides for non-standard role naming (e.g. NEO_ADMIN_ROLES=wizard,l5).
_ADMIN_ENV = _env_names("NEO_ADMIN_ROLES")
_ANON_ENV = _env_names("NEO_ANON_ROLES")
# Shape hints for custom conventions: "level5"/"tier-4"/"lvl9" — a high numeric
# rank usually means elevated privilege.
_HIGH_TIER_RE = re.compile(r'(?:level|lvl|tier|rank|grade)[\s_\-]?([4-9]|\d{2,})', re.I)


def role_rank(role: str) -> int:
    """0 = anonymous/unauth, 1 = authenticated non-privileged, 2 = privileged.

    Unknown role names default to 1 (authenticated), which is the SAFE default:
    horizontal (peer-vs-peer) access-control tests still run. To have a custom
    admin/anon convention ranked correctly, declare it via NEO_ADMIN_ROLES /
    NEO_ANON_ROLES, or rely on the built-in token/tier heuristics below."""
    r = str(role or "").strip().lower()
    if not r:
        return 0
    if r in _ANON_ENV or any(t in r for t in _ANON_TOKENS):
        return 0
    if r in _ADMIN_ENV or any(t in r for t in _ADMIN_TOKENS) or _HIGH_TIER_RE.search(r):
        return 2
    return 1


def is_admin_role(role: str) -> bool:
    return role_rank(role) >= 2


def is_anonymous_role(role: str) -> bool:
    return role_rank(role) == 0


# ── optional Jev fallbacks (async, opt-in, best-effort) ─────────────────────
async def _jev_noul(state, instructions: str, name: str, scan_id: str = "") -> Optional[bool]:
    try:
        from agents.providers.jev_classifier import get_jev
        j = get_jev(scan_id=scan_id)
        if not j:
            return None
        b, _p = await j.noul(state, instructions, name=name, site="target_shape")
        return b
    except Exception:
        return None


async def jev_is_api(url: str, content_type: str = "", scan_id: str = "") -> Optional[bool]:
    return await _jev_noul(
        {"url": url, "content_type": content_type},
        "Is this HTTP endpoint a machine/API endpoint (JSON, GraphQL, or REST) "
        "rather than a human HTML page?", "is_api", scan_id)


async def jev_is_login(url: str, body: str = "", scan_id: str = "") -> Optional[bool]:
    return await _jev_noul(
        {"url": url, "body": str(body)[:400]},
        "Is this request an authentication / login endpoint (it accepts "
        "credentials and returns a session or token)?", "is_login", scan_id)


async def jev_is_privileged(url: str, scan_id: str = "") -> Optional[bool]:
    return await _jev_noul(
        {"url": url},
        "Is this URL an administrative or privileged area that a normal "
        "unprivileged user should not be able to access?", "is_privileged", scan_id)
