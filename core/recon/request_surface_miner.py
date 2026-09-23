"""Generic request-surface miner (recon enrichment).

The surface classifier can only build query/body/form injection points from
endpoints that actually carry parameters or request bodies. Crawlers that only
collect bare URLs (common for SPAs, where the real requests are XHR calls made by
client JS) leave the classifier with nothing but header/path points — so the
injection engine has nowhere to place SQLi/XSS/NoSQL/SSTI/… payloads.

This module recovers the real request surface *structurally*, with no app- or
framework-specific knowledge and nothing hardcoded:

  * HTML <form> → method + action + field names  → a captured request whose body
    (or query) carries those fields as injectable points.
  * Any URL bearing a query string (href/src/JS string literals) → an endpoint
    with query-parameter points.
  * JS fetch()/axios/XHR/$.ajax calls → the request URL, method, and JSON body
    keys → captured requests with body points.
  * Quoted API-looking path literals in JS ("/api/…", "/rest/…", "/v1/…",
    "/graphql", …) → endpoints (so they at least enter the attack surface).

Everything is regex/structure based (no bs4/JS-engine dependency), bounded, and
best-effort — a parse failure never breaks recon. The extracted items are added
to ctx via add_captured_request / add_endpoints so the existing SurfaceClassifier
turns them into real injection points.
"""
from __future__ import annotations

import json
import logging
import re
import secrets
from html import unescape
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.common.auth_ctx import auth_headers_from_ctx
from urllib.parse import urljoin, urlparse, urlsplit, parse_qsl

logger = logging.getLogger(__name__)

# Path prefixes that generically signal an API/route (not a static asset). No
# specific product routes — just the conventional API namespaces.
_API_HINT = re.compile(r"^/(?:api|rest|graphql|v\d+|service|services|internal|"
                       r"gql|rpc|ajax|json|data|query|search)(?:/|$|\?)", re.I)
_STATIC_EXT = re.compile(r"\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|"
                         r"mp4|webm|webp|pdf|zip|gz|wasm)(?:\?|$)", re.I)

_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_FIELD_RE = re.compile(r"<(?:input|textarea|select)\b([^>]*)>", re.I)
_ATTR_RE = re.compile(r"""(\w[\w:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
_SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*['"]([^'"]+)['"]""", re.I)
_HREF_SRC_RE = re.compile(r"""(?:href|src|action|data-url)\s*=\s*['"]([^'"]+)['"]""", re.I)
# Quoted URL/path string literals anywhere (HTML or JS).
_URL_LITERAL_RE = re.compile(r"""['"]([./][^'"\s]{1,300}?)['"]""")
_ABS_URL_RE = re.compile(r"""['"](https?://[^'"\s]{1,400}?)['"]""", re.I)
# fetch("url", { ... method ... body ... }) / axios.post("url", {..}) / $.ajax
_FETCH_RE = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?|\$\.(?:ajax|get|post)|http\.\w+|request)\s*\(\s*"""
    r"""['"`]([^'"`]+)['"`]""", re.I)


def _attrs(s: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _ATTR_RE.finditer(s or ""):
        out[m.group(1).lower()] = unescape(m.group(2) or m.group(3) or m.group(4) or "")
    return out


def _same_origin(url: str, base: str) -> bool:
    try:
        a, b = urlsplit(url), urlsplit(base)
        return (not a.netloc) or (a.netloc == b.netloc)
    except Exception:
        return False


# ── HTML forms → captured requests ─────────────────────────────────────────
def extract_forms(html: str, base_url: str) -> List[Dict[str, Any]]:
    reqs: List[Dict[str, Any]] = []
    for fm in _FORM_RE.finditer(html or ""):
        fattr = _attrs(fm.group(1))
        action = fattr.get("action") or base_url
        url = urljoin(base_url, action)
        method = (fattr.get("method") or "GET").upper()
        enctype = (fattr.get("enctype") or "").lower()
        fields: List[Tuple[str, str]] = []
        has_file = False
        for fmatch in _FIELD_RE.finditer(fm.group(2)):
            a = _attrs(fmatch.group(1))
            name = a.get("name")
            if not name:
                continue
            if a.get("type", "").lower() == "file":
                has_file = True
            fields.append((name, a.get("value", "")))
        if not fields:
            continue
        if method == "GET":
            # GET form → params ride the query string
            qs = "&".join(f"{n}={v}" for n, v in fields)
            joiner = "&" if urlsplit(url).query else "?"
            reqs.append({"url": url + joiner + qs, "method": "GET",
                         "source": "form", "content_type": ""})
        elif "multipart" in enctype or has_file:
            reqs.append({"url": url, "method": method, "source": "form",
                         "content_type": "multipart/form-data",
                         "files": {n: v for n, v in fields}})
        else:
            body = "&".join(f"{n}={v}" for n, v in fields)
            reqs.append({"url": url, "method": method, "source": "form",
                         "content_type": "application/x-www-form-urlencoded",
                         "body": body})
    return reqs


# ── URLs bearing a query string → endpoints ────────────────────────────────
def extract_query_endpoints(text: str, base_url: str) -> List[str]:
    out: List[str] = []
    seen = set()
    for rx in (_HREF_SRC_RE, _URL_LITERAL_RE, _ABS_URL_RE):
        for m in rx.finditer(text or ""):
            raw = m.group(1)
            if "?" not in raw or "=" not in raw.split("?", 1)[1]:
                continue
            url = urljoin(base_url, unescape(raw))
            if _STATIC_EXT.search(url) or not _same_origin(url, base_url):
                continue
            # keep only URLs that actually parse a param
            if not parse_qsl(urlsplit(url).query):
                continue
            if url not in seen:
                seen.add(url)
                out.append(url)
    return out


# ── JS fetch/axios/route literals → endpoints + captured requests ──────────
def extract_js_requests(js: str, base_url: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    reqs: List[Dict[str, Any]] = []
    paths: List[str] = []
    seen_p = set()

    # fetch/axios/ajax call targets
    for m in _FETCH_RE.finditer(js or ""):
        raw = m.group(1)
        if not raw or raw.startswith(("data:", "blob:", "mailto:", "javascript:")):
            continue
        if not (raw.startswith(("/", "http")) or _API_HINT.match("/" + raw.lstrip("/"))):
            continue
        url = urljoin(base_url, raw)
        if _STATIC_EXT.search(url) or not _same_origin(url, base_url):
            continue
        # A request body only exists if THIS call has a second argument, i.e. the
        # char right after the URL literal is a comma. Otherwise it's a bare
        # fetch(url) with no body (guard against grabbing a later call's object).
        tail = js[m.end(): m.end() + 500]
        stripped = tail.lstrip()
        obj_text = ""
        if stripped[:1] == ",":
            obj_text = _first_object(stripped)
        body_keys = _object_keys(obj_text) if obj_text else []
        if body_keys:
            body = "{" + ",".join(f'"{k}":""' for k in body_keys) + "}"
            reqs.append({"url": url, "method": _method_from_opts(obj_text),
                         "source": "js", "content_type": _ctype_from_opts(obj_text),
                         "body": body})
        elif url not in seen_p:
            seen_p.add(url)
            paths.append(url)

    # quoted API-looking path literals (routes referenced but not called inline)
    for m in _URL_LITERAL_RE.finditer(js or ""):
        raw = m.group(1)
        if not raw.startswith("/") or _STATIC_EXT.search(raw):
            continue
        if not _API_HINT.match(raw):
            continue
        url = urljoin(base_url, raw)
        if _same_origin(url, base_url) and url not in seen_p:
            seen_p.add(url)
            paths.append(url)
    return reqs, paths


def extract_ambiguous_paths(text: str, base_url: str) -> List[str]:
    """Same-origin, non-static, path-like quoted literals that do NOT match the
    _API_HINT prefixes — i.e. candidate endpoints the hardcoded prefix list can't
    recognise. These are handed to Jev (when available) to decide endpoint-ness,
    so discovery is not limited to a fixed set of API namespaces."""
    out: List[str] = []
    seen = set()
    for m in _URL_LITERAL_RE.finditer(text or ""):
        raw = m.group(1)
        if not raw.startswith("/") or _STATIC_EXT.search(raw):
            continue
        if _API_HINT.match(raw):       # already accepted deterministically
            continue
        if len(raw) < 2 or raw.count("/") > 8 or " " in raw:
            continue
        # Reject JS/code fragments mined from minified bundles — regex literals
        # and template pieces like `/g,").replace(/` or `/>`,w=`viewBox=` start
        # with "/" but are not URLs. A real path never contains code punctuation.
        _p = raw.split("?", 1)[0]
        if not re.match(r'^/[A-Za-z0-9/_.\-~%]*$', _p):
            continue
        if "?" in raw and re.search(r'[`()<>"\'{}$\\;]|&quot;|&amp;|&lt;|&gt;', raw.split("?", 1)[1]):
            continue
        url = urljoin(base_url, raw)
        if _same_origin(url, base_url) and url not in seen:
            seen.add(url)
            out.append(url)
    return out


async def _jev_recover_endpoints(candidates: List[str], scan_id: str = "") -> List[str]:
    """Use Jev to keep only the candidates that are genuine server endpoints.
    Opt-in + fail-open: with no Jev key / on any error, returns [] (the regex
    prefix path already captured the confident ones). One request classifies up
    to 24 candidates in parallel (Jev evaluates every question at once)."""
    try:
        from core.llm.jev_config import jev_enabled
        if not candidates or not jev_enabled():
            return []
        from agents.providers.jev_classifier import get_jev
        jev = get_jev(scan_id=scan_id)
        if jev is None:
            return []
        batch = candidates[:24]
        questions = {
            f"q{i}": {"type": "noul",
                      "instructions": (f"Is the path '{p}' a server-side API/HTTP "
                                       "endpoint that accepts requests (NOT a static "
                                       "asset, client-side route, or translation key)?")}
            for i, p in enumerate(batch)
        }
        from agents.providers.jev_classifier import JevClassifier
        answers = await jev.classify({"paths": batch}, questions, site="surface_miner")
        kept = []
        for i, p in enumerate(batch):
            # Parse via the shared extractor (choice/probabilities/confidence),
            # not the legacy value/probability keys.
            val, prob = JevClassifier._value_prob(answers.get(f"q{i}") or {})
            yes = val is True or (isinstance(val, str) and val.strip().lower() in ("true", "yes", "1"))
            if yes and prob >= 0.6:
                kept.append(p)
        if kept:
            logger.info("[SurfaceMiner] Jev recovered %d/%d endpoints beyond the "
                        "prefix heuristic", len(kept), len(batch))
        return kept
    except Exception as e:
        logger.debug("[SurfaceMiner] Jev endpoint recovery skipped: %s", e)
        return []


def _first_object(text: str) -> str:
    """Return the first balanced {...} object literal in `text`, or ''."""
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            depth += 1
            if depth == 1:
                start = i
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                return text[start: i + 1]
    return ""


# Keys that are fetch/ajax OPTIONS, not payload fields — never fuzz these.
_OPT_KEYS = {"method", "headers", "credentials", "mode", "cache", "redirect",
             "referrer", "referrerpolicy", "signal", "body", "params", "url",
             "keepalive", "integrity", "window", "data", "timeout", "responsetype",
             "withcredentials", "contenttype"}


def _object_keys(obj: str) -> List[str]:
    """Keys of an object literal, minus fetch/ajax option keys. When the object
    is a fetch-options object (has method/headers/body), descend into its `body`/
    `data` sub-object for the real payload keys."""
    if not obj:
        return []
    inner = re.search(r"""\b(?:body|data)\s*:\s*(\{.*)""", obj, re.S)
    scope = _first_object(inner.group(1)) if inner else obj
    keys = re.findall(r"""[{,\s]([A-Za-z_$][\w$]*)\s*:""", scope or obj)
    return [k for k in dict.fromkeys(keys) if k.lower() not in _OPT_KEYS][:20]


def _method_from_opts(obj: str) -> str:
    """Read method from a fetch-options object literal (defaults to POST when a
    body-bearing call gives no explicit method — that's the common case)."""
    m = re.search(r"""\bmethod\s*:\s*['"]([A-Za-z]+)['"]""", obj or "")
    if m:
        return m.group(1).upper()
    return "POST"


def _ctype_from_opts(obj: str) -> str:
    """Real request Content-Type from fetch options, so a non-JSON body (XML →
    XXE, x-yaml / serialized → deserialization) is tagged for the specialist
    probes rather than assumed JSON. Generic — reads whatever the header says."""
    m = re.search(r"""['"]?content-type['"]?\s*:\s*['"]([^'";]+)""", obj or "", re.I)
    if m:
        return m.group(1).strip().lower()
    o = (obj or "").lower()
    if "xml" in o:
        return "application/xml"
    if "yaml" in o or "yml" in o:
        return "application/x-yaml"
    return "application/json"


# ── well-known paths + API-spec seeding (F2 + F3) ──────────────────────────
# Framework-agnostic. Discovery paths reveal API specs / more routes; sensitive
# paths reveal file exposures. Nothing app-specific.
_WK_DISCOVERY = (
    "robots.txt", "sitemap.xml", ".well-known/security.txt",
    "openapi.json", "openapi.yaml", "swagger.json", "swagger/v1/swagger.json",
    "api-docs", "v2/api-docs", "v3/api-docs", "api/swagger.json", "api.json",
)
# Standard well-known filenames (real conventions, not app-specific guesses).
_CONF_FILES = (
    ".env", ".env.local", ".env.production", ".env.dev", ".git/config",
    ".svn/entries", ".hg/store", ".DS_Store", ".htaccess", ".htpasswd",
    "web.config", ".aws/credentials", "config.php", "config.json",
    "configuration.php", "settings.py", "phpinfo.php", "info.php",
    "server-status", "credentials.json", ".npmrc", "id_rsa", ".ssh/id_rsa",
    "docker-compose.yml", "Dockerfile", ".dockercfg",
)
# Generic backup/temp EXTENSIONS applied to context-derived stems (below), so we
# catch mysite.sql / app_2024.zip / db.tar.gz — not just a fixed filename list.
# Highest-signal extensions first, so the candidate cap gives good coverage.
_BACKUP_EXTS = (".sql", ".zip", ".tar.gz", ".bak", ".gz", ".sql.gz", ".tar",
                ".dump", ".old", ".backup", "~", ".7z", ".rar", ".save", ".orig",
                ".swp", ".tgz", ".copy")
# Generic stems that appear across sites regardless of app (kept small).
_GENERIC_STEMS = ("backup", "www", "db", "database", "dump", "site", "web",
                  "app", "data", "config")

# Content signatures by kind (dotfile name → sig; else by extension).
_CONF_SIG = {
    ".env": re.compile(r"(?m)^[A-Z][A-Z0-9_]*="),
    ".git/config": re.compile(r"\[core\]|\[remote ", re.I),
    ".svn/entries": re.compile(r"(?m)^\d+\s*$|svn://"),
    "web.config": re.compile(r"<configuration\b", re.I),
    ".htaccess": re.compile(r"RewriteEngine|AuthType|Order\s+(allow|deny)", re.I),
    ".htpasswd": re.compile(r"(?m)^[^:\s]+:[^\s]+$"),
    "phpinfo.php": re.compile(r"phpinfo\(\)|PHP Version", re.I),
    "info.php": re.compile(r"phpinfo\(\)|PHP Version", re.I),
    "server-status": re.compile(r"Apache Server Status", re.I),
    "id_rsa": re.compile(r"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY"),
    ".ssh/id_rsa": re.compile(r"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY"),
    ".npmrc": re.compile(r"_authToken|registry="),
    ".aws/credentials": re.compile(r"aws_access_key_id|aws_secret", re.I),
}
_SQL_SIG = re.compile(r"(?i)(INSERT INTO|CREATE TABLE|DROP TABLE|-- .*dump|PRIMARY KEY)")
_PHP_SIG = re.compile(r"<\?php|\$[A-Za-z_]")
_ARCHIVE_MAGIC = ("PK\x03\x04", "\x1f\x8b", "Rar!", "7z\xbc\xaf", "BZh", "ustar")


def _context_stems(ctx, root: str) -> List[str]:
    """Stems derived from the actual target: host labels + discovered file
    basenames. This is what makes backup discovery generic per-site."""
    stems: List[str] = []
    host = (urlsplit(root).hostname or "")
    labels = [p for p in host.split(".") if p and p not in
              ("www", "com", "net", "org", "io", "co", "app", "dev")]
    stems += labels
    if host:
        stems.append(host)               # full host, e.g. app.example.com.zip
        stems.append(host.replace(".", "_"))
    for ep in (getattr(ctx, "endpoints", {}) or {}):
        url = ep if isinstance(ep, str) else ""
        base = url.split("?")[0].rstrip("/").rsplit("/", 1)[-1]
        stem = base.rsplit(".", 1)[0]
        if stem and 2 <= len(stem) <= 40 and stem.isascii():
            stems.append(stem)
    return list(dict.fromkeys(s for s in stems if s))[:8]


_EID_METHOD = re.compile(r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS):(?!//)", re.I)


def _eid_to_url(raw: str) -> str:
    """Strip a leading 'METHOD:' from a canonical endpoint id → plain URL."""
    return _EID_METHOD.sub("", raw or "").strip()


def _sensitive_candidates(ctx, root: str, cap: int = 100) -> List[str]:
    cands = list(_CONF_FILES)
    stems = _context_stems(ctx, root) + list(_GENERIC_STEMS)
    # Extension-major: try each stem with the most common backup extensions first,
    # so the cap gives BREADTH across stems rather than exhausting one stem's exts.
    for ext in _BACKUP_EXTS:
        for st in stems:
            cands.append(st + ext)
    return list(dict.fromkeys(cands))[:cap]


_API_BASES = ("api", "rest", "graphql", "gql", "service", "services", "rpc",
              "v1", "v2", "v3", "v4")
_API_DOC_NAMES = ("openapi.json", "swagger.json", "api-docs", "v3/api-docs")


def _discovery_candidates(ctx, root: str, cap: int = 32) -> List[str]:
    """Conventional spec/discovery paths PLUS API-doc paths derived from the app's
    OWN discovered API base prefixes (so a spec at /myapi/openapi.json is found,
    not just the standard locations). Generic — bases come from the target."""
    cands = list(_WK_DISCOVERY)
    bases = set()
    for ep in (getattr(ctx, "endpoints", {}) or {}):
        raw = _eid_to_url(ep if isinstance(ep, str) else getattr(ep, "url", ""))
        try:
            segs = [s for s in urlsplit(raw).path.split("/") if s]
        except Exception:
            continue
        for i, seg in enumerate(segs[:2]):
            if seg.lower() in _API_BASES:
                bases.add("/".join(segs[: i + 1]))
    for b in list(bases)[:6]:
        for name in _API_DOC_NAMES:
            cands.append(f"{b}/{name}")
    return list(dict.fromkeys(cands))[:cap]


def _confirm_sensitive(path: str, body: str) -> bool:
    """True when the response is genuinely a sensitive file (by dotfile name, or
    by extension/content) — not an HTML shell or soft-404. Generic."""
    if not body:
        return False
    head = body[:600]
    if head.lstrip()[:1] == "<" and "html" in head[:200].lower():
        return False
    sig = _CONF_SIG.get(path)
    if sig:
        return bool(sig.search(body))
    low = path.lower()
    if low.endswith((".sql", ".sql.gz", ".dump")):
        return bool(_SQL_SIG.search(body))
    if low.endswith((".zip", ".tar.gz", ".tgz", ".gz", ".tar", ".7z", ".rar")):
        return any(body[:8].startswith(m) for m in _ARCHIVE_MAGIC)
    if low.endswith((".php",)) or "config" in low or "settings" in low:
        return bool(_PHP_SIG.search(body)) or "=" in body[:400]
    # backups of source (.bak/.old/~ …): real if it has code/config, not HTML
    return "=" in head or ";" in head or "{" in head or "function" in head


def _parse_openapi(spec: Any, base_url: str) -> List[Dict[str, Any]]:
    """Turn an OpenAPI/Swagger doc into captured requests carrying each operation's
    path params, query params and request-body fields as injectable points. Fully
    generic — the spec itself defines the API."""
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    server = ""
    try:
        if isinstance(spec.get("servers"), list) and spec["servers"]:
            server = spec["servers"][0].get("url", "") or ""
        elif spec.get("basePath"):
            server = spec["basePath"]
    except Exception:
        server = ""
    root = urljoin(base_url, server) if server else base_url
    out: List[Dict[str, Any]] = []
    for raw_path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete") or not isinstance(op, dict):
                continue
            url = urljoin(root.rstrip("/") + "/", str(raw_path).lstrip("/"))
            qparams, body_keys = [], []
            for p in (op.get("parameters") or item.get("parameters") or []):
                if isinstance(p, dict) and p.get("in") in ("query", "path") and p.get("name"):
                    qparams.append(str(p["name"]))
            rb = op.get("requestBody") or {}
            try:
                schema = (((rb.get("content") or {}).get("application/json") or {}).get("schema") or {})
                body_keys = list((schema.get("properties") or {}).keys())
            except Exception:
                body_keys = []
            req: Dict[str, Any] = {"url": url, "method": method.upper(), "source": "openapi"}
            if qparams:
                req["url"] = url + ("&" if "?" in url else "?") + "&".join(f"{n}=" for n in qparams)
            if body_keys:
                req["content_type"] = "application/json"
                req["body"] = "{" + ",".join(f'"{k}":""' for k in body_keys) + "}"
            out.append(req)
    return out


async def mine_well_known(ctx, fetch: Optional[Callable] = None) -> Dict[str, int]:
    """F2/F3: probe framework-agnostic well-known paths. Seeds endpoints from API
    specs / robots / sitemap and records sensitive-file exposures as findings.
    Best-effort; never raises."""
    base = getattr(ctx, "target", "") or ""
    if not base:
        return {}
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    sp = urlsplit(base)
    root = f"{sp.scheme}://{sp.netloc}/"
    if fetch is None:
        fetch = _make_fetch(_auth_headers(ctx)) if _auth_headers(ctx) else _default_fetch

    seeded = 0
    exposures = 0
    # A random path baseline to reject soft-404/SPA shells.
    try:
        catch = await fetch(urljoin(root, secrets.token_hex(8)))
    except Exception:
        catch = ""

    for path in _discovery_candidates(ctx, root):
        try:
            body = await fetch(urljoin(root, path))
        except Exception:
            body = ""
        if not body or body == catch:
            continue
        spec = None
        s = body.lstrip()
        if s[:1] == "{":
            try:
                spec = json.loads(body)
            except Exception:
                spec = None
        if isinstance(spec, dict) and (spec.get("openapi") or spec.get("swagger") or spec.get("paths")):
            reqs = _parse_openapi(spec, root)
            for r in reqs:
                try:
                    ctx.add_captured_request(r); seeded += 1
                except Exception:
                    pass
        elif path == "robots.txt" or path == "sitemap.xml":
            found = []
            for m in re.finditer(r"(?im)^\s*(?:Disallow|Allow)\s*:\s*(\S+)", body):
                found.append(urljoin(root, m.group(1)))
            for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", body, re.I):
                found.append(m.group(1))
            if found:
                try:
                    ctx.add_endpoints(list(dict.fromkeys(found)), source="well_known")
                    seeded += len(found)
                except Exception:
                    pass

    for path in _sensitive_candidates(ctx, root):
        try:
            body = await fetch(urljoin(root, path))
        except Exception:
            body = ""
        if not body or body == catch:
            continue
        if not _confirm_sensitive(path, body):
            continue
        _pl = path.lower()
        _high = any(h in _pl for h in (".env", ".git", ".sql", ".dump", "id_rsa",
                                       "credential", ".aws", ".npmrc", ".htpasswd",
                                       "key", ".ssh", "docker"))
        try:
            ctx.add_vulnerability({
                "type": "sensitive_data_exposure", "title": f"Exposed file: /{path}",
                "severity": "HIGH" if _high else "MEDIUM",
                "location": urljoin(root, path), "tool": "well_known_probe",
                "proof": (body or "")[:400], "confirmed": True, "status": "CONFIRMED",
                "remediation": f"Remove or restrict access to /{path}; it should not be web-reachable.",
            })
            exposures += 1
        except Exception:
            pass

    logger.info("[WellKnown] seeded %d endpoints (API spec/robots), %d file exposures",
                seeded, exposures)
    return {"seeded": seeded, "exposures": exposures}


# ── orchestration ──────────────────────────────────────────────────────────
def _auth_headers(ctx) -> Dict[str, str]:
    """Pull the active session's auth headers from ctx, if any, so the miner can
    fetch login-gated pages/JS and discover the authenticated surface (A4)."""
    return auth_headers_from_ctx(ctx)


def _make_fetch(headers: Optional[Dict[str, str]] = None) -> Callable:
    async def _fetch(url: str, timeout: float = 15.0) -> str:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                         headers=headers or None) as c:
                r = await c.get(url)
                return r.text or ""
        except Exception as e:
            logger.debug("[SurfaceMiner] fetch %s failed: %s", url, e)
            return ""
    return _fetch


async def _default_fetch(url: str, timeout: float = 15.0) -> str:
    return await _make_fetch()(url, timeout)


async def mine_request_surface(ctx, fetch: Optional[Callable] = None,
                               max_scripts: int = 8, use_auth: bool = True) -> Dict[str, int]:
    """Enrich ctx with the target's real request surface. Best-effort; returns
    counts. ``fetch`` is an async ``(url) -> text`` (injectable for tests). When
    ``use_auth`` and ctx carries session headers, fetches authenticated so the
    login-gated surface is discovered too (A4)."""
    base = getattr(ctx, "target", "") or ""
    if not base:
        return {}
    if fetch is None and use_auth:
        _ah = _auth_headers(ctx)
        if _ah:
            fetch = _make_fetch(_ah)
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    # normalise to origin root for fetching (drop SPA fragment/path)
    sp = urlsplit(base)
    root = f"{sp.scheme}://{sp.netloc}/"
    fetch = fetch or _default_fetch

    captured: List[Dict[str, Any]] = []
    endpoints: List[str] = []
    ambiguous: List[str] = []          # path-like literals Jev can adjudicate
    try:
        html = await fetch(root)
    except Exception:
        html = ""
    if html:
        captured += extract_forms(html, root)
        endpoints += extract_query_endpoints(html, root)
        ambiguous += extract_ambiguous_paths(html, root)
        # Register same-origin JS/CSS assets as endpoints so the vulnerable-
        # component probe (retire.js-style version detection) has bundles to scan.
        for m in _HREF_SRC_RE.finditer(html):
            au = urljoin(root, unescape(m.group(1)))
            if _same_origin(au, root) and au.split("?")[0].lower().endswith((".js", ".css")):
                endpoints.append(au)
        scripts = []
        for m in _SCRIPT_SRC_RE.finditer(html):
            su = urljoin(root, m.group(1))
            if _same_origin(su, root) and su.split("?")[0].lower().endswith(".js"):
                scripts.append(su)
        for su in list(dict.fromkeys(scripts))[:max_scripts]:
            js = await fetch(su)
            if not js:
                continue
            jr, jp = extract_js_requests(js, root)
            captured += jr
            endpoints += jp
            endpoints += extract_query_endpoints(js, root)
            ambiguous += extract_ambiguous_paths(js, root)

    # Jev adjudicates the ambiguous path literals the prefix heuristic can't
    # classify — generic endpoint discovery without a hardcoded namespace list.
    if ambiguous:
        scan_id = getattr(ctx, "scan_id", "") or getattr(ctx, "_scan_id", "") or ""
        recovered = await _jev_recover_endpoints(list(dict.fromkeys(ambiguous)), scan_id)
        endpoints += recovered

    # de-dup
    seen_c = set()
    uniq_c = []
    for r in captured:
        k = f"{r.get('method')} {r.get('url')} {r.get('content_type')} {r.get('body') or r.get('files')}"
        if k not in seen_c:
            seen_c.add(k)
            uniq_c.append(r)
    uniq_e = list(dict.fromkeys(e for e in endpoints if e))

    added_c = added_e = 0
    for r in uniq_c:
        try:
            ctx.add_captured_request(r)
            added_c += 1
        except Exception:
            pass
    if uniq_e:
        try:
            ctx.add_endpoints(uniq_e, source="surface_miner")
            added_e = len(uniq_e)
        except Exception:
            pass

    logger.info("[SurfaceMiner] enriched surface: +%d captured requests, +%d endpoints "
                "(from %s)", added_c, added_e, root)
    return {"captured_requests": added_c, "endpoints": added_e}
