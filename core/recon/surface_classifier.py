"""SurfaceClassifier (gaps §2, §4) — name-agnostic surface + injection-point
derivation from observed data.

Nothing is guessed from paths/field-names. Every injection point and every
applicable vuln class is derived from the SHAPE/BEHAVIOUR of what was actually
observed (crawl endpoints + captured requests + detected tech). A renamed
`/x7f2` upload is still classed as an upload because it carries a multipart
file field, not because it is called "upload".

Output feeds the Dispatcher (core/orchestration/dispatcher.py), which runs the
unified injection engine (§0) against the real points.

Cold-start: when no captured requests exist yet, points are derived from the
endpoint inventory (query params + path segments). Hardcoded hints are
fallback only.
"""
from __future__ import annotations

import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set

logger = logging.getLogger(__name__)

# Injection-point locations (matches Payload.context where relevant).
LOC_QUERY = "query"
LOC_JSON = "json_body"
LOC_FORM = "form"
LOC_HEADER = "header"
LOC_COOKIE = "cookie"
LOC_PATH = "path"
LOC_MULTIPART = "multipart"
LOC_WS = "ws_message"
LOC_GRAPHQL = "graphql_arg"

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_NUM_RE = re.compile(r"^\d+$")
# A path segment following one of these (or any plural-looking segment) is treated
# as a resource id even when it's a slug/username, not just numeric/UUID — so
# /users/jdoe and /orders/ab-99 become IDOR/injection points.
_COLLECTION_RE = re.compile(r"^[a-z][a-z0-9_-]*s$", re.I)
_KNOWN_COLLECTIONS = {
    "user", "users", "account", "accounts", "order", "orders", "post", "posts",
    "item", "items", "product", "products", "file", "files", "project", "projects",
    "invoice", "invoices", "profile", "profiles", "doc", "docs", "document",
    "documents", "group", "groups", "team", "teams", "org", "orgs", "customer",
    "customers", "ticket", "tickets", "message", "messages", "comment", "comments",
}
_PATH_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                    ".woff", ".woff2", ".map", ".json", ".xml", ".webp", ".txt")
_PATH_ACTION_WORDS = {"new", "edit", "create", "update", "delete", "list", "search",
                      "login", "logout", "register", "index", "home", "about", "api"}
# Non-actionable URLs that must NEVER become attack surfaces: JS build internals
# and source-parse artifacts crawlers mine from bundles. They carry no server-side
# injection surface, but each one still multiplies the coverage matrix
# (endpoints × classes) and burns probe budget — the coverage-denominator
# explosion. High-precision only: framework internals + obvious code fragments,
# NOT every static asset (a real handler ending in .js is left alone).
_NON_ACTIONABLE_MARKERS = (
    "/node_modules/", ".routeConfig", "route.js", "$1", "this.",
    "rolldown-", "/webpack/", "runtime.js", "polyfills",
)


def _is_non_actionable_url(url: str) -> bool:
    try:
        low = str(url).lower()
    except Exception:
        return False
    if low.endswith(".map"):
        return True
    return any(m.lower() in low for m in _NON_ACTIONABLE_MARKERS)


_URL_VALUE_RE = re.compile(r"^(https?|ftp|gopher|file)://|^//|%2f%2f", re.I)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_JWT_RE = re.compile(r"^ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")

# id-shaped / url-shaped / file-shaped param NAME hints (cold-start only; value
# shape always wins over name).
_ID_NAME_HINT = ("id", "uid", "user", "account", "order", "doc", "file", "num", "no", "pid", "gid")
_URL_NAME_HINT = ("url", "uri", "link", "redirect", "next", "return", "dest", "callback", "target", "domain", "host", "path", "continue", "image", "img", "fetch", "load", "src")
_FILE_NAME_HINT = ("file", "upload", "attachment", "photo", "image", "avatar", "document", "media")
_PASSWORD_HINT = ("password", "passwd", "pwd", "pass", "secret")


@dataclass
class InjectionPoint:
    location: str                 # LOC_*
    name: str                     # param / field / header / path-index
    sample_value: str = ""
    signals: Set[str] = field(default_factory=set)   # url_valued / numeric / file / ...
    # Reflection context observed for this point (html/attr/js/uri/json/none) —
    # set by the reflection/oracle step so payload selection can be context-aware.
    reflection_context: str = ""

    def key(self) -> str:
        return f"{self.location}:{self.name}"


@dataclass
class Surface:
    url: str
    method: str = "GET"
    kind: str = "generic"         # login / upload / api / graphql / websocket / cart / generic
    content_type: str = ""
    injection_points: List[InjectionPoint] = field(default_factory=list)
    signals: Set[str] = field(default_factory=set)
    applicable_classes: List[str] = field(default_factory=list)   # OracleEngine keys
    raw: Dict[str, Any] = field(default_factory=dict)             # original captured request
    # Identity/context the surface was observed under — drives per-identity retest
    # and authz differential. Populated from the captured request when available.
    auth_state: str = "unknown"   # anonymous | authenticated | unknown
    role: str = ""                # identity/role the request was captured as
    tech: str = ""                # detected framework/stack hint
    baseline_digest: str = ""     # digest of the baseline response (diff oracles)

    def point_by_key(self, key: str) -> Optional[InjectionPoint]:
        for p in self.injection_points:
            if p.key() == key:
                return p
        return None


class SurfaceClassifier:
    """Derive Surfaces (with real injection points + applicable classes) from ctx."""

    def classify(self, ctx) -> List[Surface]:
        surfaces: List[Surface] = []
        seen: Set[str] = set()

        # 1. Captured requests are the richest source (real bodies/headers/cookies).
        for req in (getattr(ctx, "captured_requests", None) or []):
            try:
                s = self._surface_from_request(req)
            except Exception as e:
                logger.debug("surface from request failed: %s", e)
                continue
            if s and s.url:
                dk = f"{s.method} {s.url}"
                if dk not in seen:
                    seen.add(dk)
                    surfaces.append(s)

        # 2. Endpoint inventory (cold-start / not-yet-captured).
        try:
            endpoints = ctx.get_endpoints() if hasattr(ctx, "get_endpoints") else []
        except Exception:
            endpoints = []
        for ep in endpoints:
            try:
                s = self._surface_from_endpoint(ep)
            except Exception as e:
                logger.debug("surface from endpoint failed: %s", e)
                continue
            if s and s.url:
                dk = f"{s.method} {s.url}"
                if dk not in seen:
                    seen.add(dk)
                    surfaces.append(s)

        # 3. SPA routes mined from JS bundles (crawler F-X1 → ctx.spa_routes).
        # These never enter captured_requests or the endpoint inventory, so
        # without this step the whole server-side injection battery
        # (SQLI/SSTI/SSRF/IDOR/...) never reaches JS-only routes — they'd get
        # DOM-XSS + route-disclosure only (P0-2 chaining gap). Each route is
        # concretised into a requestable URL and classified like any surface.
        spa_routes = getattr(ctx, "spa_routes", None) or []
        base = getattr(ctx, "target", "") or ""
        n_spa = 0
        for route in spa_routes:
            try:
                s = self._surface_from_spa_route(str(route), base)
            except Exception as e:
                logger.debug("surface from spa route failed: %s", e)
                continue
            if s and s.url:
                dk = f"{s.method} {s.url}"
                if dk not in seen:
                    seen.add(dk)
                    surfaces.append(s)
                    n_spa += 1

        # Drop non-actionable surfaces (JS build internals, source-parse artifacts)
        # BEFORE enrichment/coverage so they neither inflate the coverage matrix
        # (endpoints × classes → denominator explosion) nor waste probe budget.
        _before = len(surfaces)
        surfaces = [s for s in surfaces if not _is_non_actionable_url(s.url)]
        _dropped = _before - len(surfaces)
        if _dropped:
            logger.info("[SurfaceClassifier] dropped %d non-actionable surface(s) "
                        "(JS internals / source-parse artifacts)", _dropped)

        # 4. Globally-discovered parameter NAMES (arjun/recon mining → ctx
        # "parameters"). These are names with no captured request and no endpoint
        # association, so they never became injection points — starving the whole
        # injection battery (SSRF from url-named params like redirect_uri/callback,
        # NoSQLi/SQLi from generic text params) whenever the browser captured no
        # live API traffic. Attach them as query injection points to param-less
        # endpoint/SPA surfaces so the battery actually runs on them.
        disc = self._discovered_params(ctx)
        n_param_pts = 0
        if disc:
            _INJECTABLE = (LOC_QUERY, LOC_JSON, LOC_FORM, LOC_MULTIPART)
            enriched = 0
            for s in surfaces:
                if enriched >= 40:
                    break  # bound the injection matrix on param-rich targets
                # ONLY synthetic endpoint/SPA surfaces — never captured requests
                # (whose raw is the request dict and may carry an "endpoint" key).
                if not (s.raw.get("endpoint") is True or "spa_route" in s.raw):
                    continue
                if any(p.location in _INJECTABLE for p in s.injection_points):
                    continue  # already has its own injectable points
                for name in disc:
                    s.injection_points.append(self._point(LOC_QUERY, name, ""))
                    n_param_pts += 1
                s.injection_points = self._dedup_points(s.injection_points)
                enriched += 1

        tech = self._tech(ctx)
        for s in surfaces:
            self._assign_classes(s, tech)
        logger.info("SurfaceClassifier: %d surfaces (%d captured, %d endpoints, %d spa-routes, "
                    "%d discovered-param points)",
                    len(surfaces), len(getattr(ctx, "captured_requests", []) or []),
                    len(endpoints), n_spa, n_param_pts)
        return surfaces

    @staticmethod
    def _discovered_params(ctx, cap: int = 30) -> List[str]:
        """Flat list of discovered parameter NAMES (ctx 'parameters'), filtered to
        plausible param names (drops HTTP verbs / junk tokens), deduped, capped."""
        raw = None
        try:
            raw = ctx.get("parameters") if hasattr(ctx, "get") else None
        except Exception:
            raw = None
        if raw is None:
            raw = getattr(ctx, "parameters", None)
        out: List[str] = []
        seen: Set[str] = set()
        _VERBS = {"get", "post", "put", "patch", "delete", "head", "options"}
        for item in (raw or []):
            name = item.get("name") if isinstance(item, dict) else item
            name = str(name or "").strip()
            # Allow single-char params (e.g. Juice Shop search `q`); cap length.
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,39}$", name):
                continue
            if name.lower() in _VERBS or name.lower() in seen:
                continue
            seen.add(name.lower())
            out.append(name)
            if len(out) >= cap:
                break
        return out

    # ── request → surface ──────────────────────────────────────────────
    def _surface_from_request(self, req: Dict[str, Any]) -> Optional[Surface]:
        url = req.get("url") or req.get("endpoint") or ""
        if not url:
            return None
        method = str(req.get("method", "GET")).upper()
        headers = {str(k).lower(): v for k, v in (req.get("headers") or {}).items()}
        ctype = str(headers.get("content-type", req.get("content_type", ""))).lower()
        body = req.get("body") if req.get("body") is not None else req.get("data")

        s = Surface(url=url, method=method, content_type=ctype, raw=req)
        # Identity/context this request was captured under (drives per-identity
        # retest + authz differential). Ambient credentials → authenticated.
        if ("authorization" in headers) or headers.get("cookie"):
            s.auth_state = "authenticated"
            s.role = str(req.get("role") or req.get("identity") or "")
        else:
            s.auth_state = "anonymous"
        pts: List[InjectionPoint] = []

        # query params
        pts += self._points_from_query(url)
        # path segments
        pts += self._points_from_path(url)
        # cookies
        cookie = headers.get("cookie", "")
        if cookie:
            for name, val in self._parse_cookie(cookie):
                pts.append(self._point(LOC_COOKIE, name, val))
        # injectable headers (host / forwarded / referer / origin / ua)
        _std_hdrs = ("host", "x-forwarded-for", "x-forwarded-host", "referer",
                     "origin", "user-agent", "x-original-url", "x-rewrite-url")
        for hname in _std_hdrs:
            if hname in headers:
                pts.append(self._point(LOC_HEADER, hname, str(headers[hname])))
        # custom headers actually seen on this request (X-Tenant-Id, X-Api-Version,
        # X-User-Id, …) — derive the fuzz-list from real traffic, not a fixed
        # allowlist. Skips standard/noise x- headers already covered or irrelevant.
        _skip = set(_std_hdrs) | {"x-requested-with", "x-csrf-token", "x-xsrf-token",
                                  "x-content-type-options", "x-frame-options"}
        _added = 0
        for hname in list(headers.keys()):
            hl = str(hname).lower()
            if hl.startswith("x-") and hl not in _skip and _added < 8:
                pts.append(self._point(LOC_HEADER, hl, str(headers[hname])))
                _added += 1

        # multipart / file upload (may be carried as files/fields, not a raw body)
        is_multipart = "multipart" in ctype or self._has_file_field(req)
        if is_multipart:
            s.kind = "upload"
            s.signals.add("multipart")
            for name, val, is_file in self._multipart_fields(req, body):
                p = self._point(LOC_MULTIPART, name, val)
                if is_file:
                    p.signals.add("file")
                pts.append(p)
        # body
        if not is_multipart and body is not None and body != "":
            if "json" in ctype or self._looks_json(body):
                for name, val in self._flatten_json(body):
                    pts.append(self._point(LOC_JSON, name, val))
            elif "x-www-form-urlencoded" in ctype or "=" in str(body):
                for name, val in self._parse_form(str(body)):
                    pts.append(self._point(LOC_FORM, name, val))

        # protocol / kind refinement
        if url.startswith("ws://") or url.startswith("wss://") or headers.get("upgrade", "").lower() == "websocket":
            s.kind = "websocket"
            s.signals.add("websocket")
            for name, val in self._flatten_json(body) if body else []:
                pts.append(self._point(LOC_WS, name, val))
        if "/graphql" in url.lower() or (body and "query" in str(body) and "{" in str(body)):
            s.kind = "graphql"
            s.signals.add("graphql")
        if any(p.name.lower() in _PASSWORD_HINT or "password" in str(p.name).lower() for p in pts):
            s.kind = "login"
            s.signals.add("auth")

        s.injection_points = self._dedup_points(pts)
        return s

    # ── endpoint → surface (cold-start) ────────────────────────────────
    def _surface_from_endpoint(self, ep) -> Optional[Surface]:
        url = self._attr(ep, "url") or (ep if isinstance(ep, str) else "")
        if not url:
            return None
        methods = self._attr(ep, "method_set") or [self._attr(ep, "method") or "GET"]
        method = (methods[0] if isinstance(methods, list) and methods else str(methods)).upper()
        ctype = str(self._attr(ep, "content_type") or "").lower()
        s = Surface(url=url, method=method, content_type=ctype, raw={"endpoint": True})
        pts = self._points_from_query(url) + self._points_from_path(url)
        # declared parameters (domain Endpoint.parameters or attack-surface list)
        for prm in (self._attr(ep, "parameters") or []):
            name = self._attr(prm, "name") if not isinstance(prm, str) else prm
            if name:
                loc = LOC_JSON if ("json" in ctype or method in ("POST", "PUT", "PATCH")) else LOC_QUERY
                pts.append(self._point(loc, str(name), str(self._attr(prm, "example") or "")))
        if "/graphql" in url.lower():
            s.kind = "graphql"; s.signals.add("graphql")
        s.injection_points = self._dedup_points(pts)
        return s

    # ── spa route → surface (JS-bundle-mined client routes) ────────────
    def _surface_from_spa_route(self, route: str, base: str) -> Optional[Surface]:
        r = (route or "").strip().lstrip("#")
        if not r:
            return None
        absolute = r.startswith(("http://", "https://"))
        if not absolute and not r.startswith("/"):
            r = "/" + r
        path_part, _, query = r.partition("?")
        if absolute:
            full = path_part
        else:
            # Concretise route templates (:id, {id}, <id>, *) so the path is a
            # real, requestable URL and the templated segment is picked up as an
            # id-shaped injection point by _points_from_path.
            segs = [seg for seg in path_part.split("/") if seg != ""]
            concrete = [
                "1" if (seg.startswith((":", "{", "<")) or seg == "*") else seg
                for seg in segs
            ]
            path = "/" + "/".join(concrete) if concrete else "/"
            full = urllib.parse.urljoin((base or "").rstrip("/") + "/", path.lstrip("/"))
        if query:
            full = f"{full}?{query}"
        if not full.startswith(("http://", "https://")):
            return None
        # Scope guard: an absolute route to a DIFFERENT registrable domain (e.g. a
        # CDN) must never mint an on-target surface — the probe layer would
        # otherwise be handed an off-scope host. Same-domain (incl. subdomains) OK.
        if absolute and base:
            def _reg(h: str) -> str:
                parts = (h or "").lower().strip(".").split(".")
                return ".".join(parts[-2:]) if len(parts) >= 2 else (h or "").lower()
            _bh = urllib.parse.urlparse(base if "://" in base else "http://" + base).hostname or ""
            _fh = urllib.parse.urlparse(full).hostname or ""
            if _bh and _fh and _reg(_fh) != _reg(_bh):
                return None
        s = Surface(url=full, method="GET", raw={"spa_route": route})
        s.injection_points = self._dedup_points(
            self._points_from_query(full) + self._points_from_path(full)
        )
        return s

    # ── point builders ─────────────────────────────────────────────────
    def _point(self, location: str, name: str, value: str = "") -> InjectionPoint:
        p = InjectionPoint(location=location, name=str(name), sample_value=str(value or ""))
        p.signals |= self._value_signals(name, value)
        return p

    def _value_signals(self, name: str, value: str) -> Set[str]:
        sig: Set[str] = set()
        v = str(value or "").strip()
        n = str(name or "").lower()
        if v:
            if _URL_VALUE_RE.search(v):
                sig.add("url_valued")
            if _NUM_RE.match(v):
                sig.add("numeric_id")
            if _UUID_RE.match(v):
                sig.add("uuid_id")
            if _EMAIL_RE.match(v):
                sig.add("email")
            if _JWT_RE.match(v):
                sig.add("jwt")
            if v.startswith("<") or "<?xml" in v.lower():
                sig.add("xml")
        # name hints (fallback signal — value shape above is stronger)
        if any(h in n for h in _URL_NAME_HINT):
            sig.add("url_valued")
        if any(h == n or n.endswith(h) or n.startswith(h) for h in _ID_NAME_HINT):
            sig.add("id_like")
        if any(h in n for h in _FILE_NAME_HINT):
            sig.add("file_like")
        if any(h in n for h in _PASSWORD_HINT):
            sig.add("password")
        return sig

    def _points_from_query(self, url: str) -> List[InjectionPoint]:
        try:
            q = urllib.parse.urlparse(url).query
            return [self._point(LOC_QUERY, k, v) for k, v in urllib.parse.parse_qsl(q)]
        except Exception:
            return []

    def _points_from_path(self, url: str) -> List[InjectionPoint]:
        out: List[InjectionPoint] = []
        try:
            path = urllib.parse.urlparse(url).path
            segs = [seg for seg in path.split("/") if seg]
            for i, seg in enumerate(segs):
                if _NUM_RE.match(seg) or _UUID_RE.match(seg):  # id-shaped path segment
                    out.append(self._point(LOC_PATH, str(i), seg))
                    continue
                low = seg.lower()
                if any(low.endswith(ext) for ext in _PATH_STATIC_EXT) or low in _PATH_ACTION_WORDS:
                    continue
                # slug/username id: a non-numeric segment right after a collection
                # noun (users/<slug>, orders/<code>) — a real IDOR/injection point.
                prev = segs[i - 1].lower() if i > 0 else ""
                if prev and (prev in _KNOWN_COLLECTIONS or _COLLECTION_RE.match(prev)):
                    p = self._point(LOC_PATH, str(i), seg)
                    p.signals.add("id_like")
                    out.append(p)
        except Exception:
            pass
        return out

    # ── class assignment (signals → OracleEngine keys) ─────────────────
    def _assign_classes(self, s: Surface, tech: List[str]) -> None:
        classes: Set[str] = set()
        psigs: Set[str] = set()
        for p in s.injection_points:
            psigs |= p.signals

        text_points = [p for p in s.injection_points
                       if p.location in (LOC_QUERY, LOC_JSON, LOC_FORM, LOC_MULTIPART, LOC_WS, LOC_GRAPHQL)]

        # every text-bearing input point gets the generic injection battery
        if text_points:
            classes.update(["SQLI", "NOSQLI", "XSS", "SSTI", "RCE", "LFI", "XXE"])
        # url-valued → SSRF + open redirect
        if "url_valued" in psigs:
            classes.update(["SSRF", "OPEN_REDIRECT"])
        # id-shaped → IDOR
        if psigs & {"numeric_id", "uuid_id", "id_like"}:
            classes.add("IDOR")
        # json body → mass assignment + prototype pollution
        if any(p.location == LOC_JSON for p in s.injection_points):
            classes.update(["MASS_ASSIGNMENT", "PROTOTYPE_POLLUTION"])
        # multipart w/ file field → upload
        if "multipart" in s.signals or "file" in psigs or "file_like" in psigs:
            classes.add("FILE_UPLOAD")
        # xml body → XXE
        if "xml" in psigs or "xml" in s.content_type:
            classes.add("XXE")
        # headers present → host-header / cache / smuggling / CORS
        if any(p.location == LOC_HEADER for p in s.injection_points):
            classes.update(["HOST_HEADER_INJECTION", "CACHE_POISONING", "HTTP_SMUGGLING", "CORS_MISCONFIGURATION"])
        # cookies present → session
        if any(p.location == LOC_COOKIE for p in s.injection_points):
            classes.add("SESSION_HIJACKING")
        # jwt observed → JWT battery
        if "jwt" in psigs:
            classes.add("JWT")
        # email field → email/CRLF injection
        if "email" in psigs:
            classes.add("EMAIL_INJECTION")
        # kind-driven
        if s.kind == "login":
            classes.update(["AUTH_BYPASS", "CREDENTIAL_BRUTE_FORCE", "JWT", "SQLI"])
        if s.kind == "graphql":
            classes.update(["GRAPHQL", "IDOR", "BUSINESS_LOGIC"])
        if s.kind == "websocket":
            classes.update(["WEBSOCKET_HIJACKING", "IDOR"])
        if s.kind == "upload":
            classes.update(["FILE_UPLOAD", "XSS"])
        # state-changing methods → CSRF + business logic
        if s.method in ("POST", "PUT", "PATCH", "DELETE"):
            classes.update(["CSRF", "BUSINESS_LOGIC", "RACE_CONDITION"])
        # every surface: always cheap-check redirect + clickjacking + info leak on the page itself
        classes.update(["INFORMATION_DISCLOSURE"])

        s.applicable_classes = sorted(classes)

    # ── helpers ────────────────────────────────────────────────────────
    @staticmethod
    def _attr(obj, name):
        if isinstance(obj, dict):
            return obj.get(name)
        return getattr(obj, name, None)

    @staticmethod
    def _tech(ctx) -> List[str]:
        try:
            techs = getattr(ctx, "technologies", {}) or {}
            flat: List[str] = []
            for v in (techs.values() if isinstance(techs, dict) else techs):
                flat.extend(v if isinstance(v, list) else [v])
            return [str(t).lower() for t in flat]
        except Exception:
            return []

    @staticmethod
    def _looks_json(body) -> bool:
        if isinstance(body, (dict, list)):
            return True
        b = str(body).strip()
        return b.startswith("{") or b.startswith("[")

    def _flatten_json(self, body, prefix: str = "") -> Iterable:
        import json
        obj = body
        if isinstance(body, str):
            try:
                obj = json.loads(body)
            except Exception:
                return []
        out = []

        def walk(o, pfx):
            if isinstance(o, dict):
                for k, v in o.items():
                    walk(v, f"{pfx}.{k}" if pfx else str(k))
            elif isinstance(o, list):
                for i, v in enumerate(o):
                    walk(v, f"{pfx}[{i}]")
            else:
                out.append((pfx, "" if o is None else str(o)))
        walk(obj, prefix)
        return out

    @staticmethod
    def _parse_form(body: str):
        try:
            return urllib.parse.parse_qsl(body)
        except Exception:
            return []

    @staticmethod
    def _parse_cookie(cookie: str):
        out = []
        for part in cookie.split(";"):
            if "=" in part:
                k, _, v = part.strip().partition("=")
                out.append((k, v))
        return out

    @staticmethod
    def _has_file_field(req: Dict[str, Any]) -> bool:
        files = req.get("files") or req.get("multipart")
        return bool(files)

    def _multipart_fields(self, req: Dict[str, Any], body):
        # prefer a structured files/fields dict if the capture provides one
        files = req.get("files") or {}
        fields = req.get("fields") or req.get("form") or {}
        out = []
        if isinstance(files, dict):
            for name, meta in files.items():
                fn = meta.get("filename", "") if isinstance(meta, dict) else str(meta)
                out.append((name, fn, True))
        if isinstance(fields, dict):
            for name, val in fields.items():
                out.append((name, str(val), False))
        if out:
            return out
        # else parse Content-Disposition names from the raw body
        for m in re.finditer(r'name="([^"]+)"(?:;\s*filename="([^"]*)")?', str(body)):
            out.append((m.group(1), m.group(2) or "", bool(m.group(2)) or m.group(2) == ""))
        return out

    @staticmethod
    def _dedup_points(pts: List[InjectionPoint]) -> List[InjectionPoint]:
        seen: Set[str] = set()
        out: List[InjectionPoint] = []
        for p in pts:
            if p.name == "":
                continue
            k = p.key()
            if k not in seen:
                seen.add(k)
                out.append(p)
        return out


_classifier: Optional[SurfaceClassifier] = None


def get_surface_classifier() -> SurfaceClassifier:
    global _classifier
    if _classifier is None:
        _classifier = SurfaceClassifier()
    return _classifier
