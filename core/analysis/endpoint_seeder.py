"""SAST→DAST endpoint seeding.

DAST can only test what it can reach. A crawler starting at `/` misses routes
that have no inbound link (typical for APIs and vulnerable-by-design apps whose
sinks sit behind `?id=`/`?cmd=` params). This module reads the *source* — the
same tree SAST scanned — extracts declared routes + the request params each file
touches, and emits ready-to-inject captured-request dicts so the dispatcher's
SurfaceClassifier sees those endpoints as real injection surfaces.

Routes discovered in files that SAST flagged are seeded first (they're the ones
most likely to correlate into CONFIRMED findings).

Framework coverage: Flask / FastAPI / Django (Python) and Express (JS/TS). Pure,
regex-based, bounded — no imports of the target code, no execution.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)

_SRC_EXT = (".py", ".js", ".ts", ".mjs", ".cjs")
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__",
              "dist", "build", "site-packages", ".tox", "migrations", "tests",
              "test", "static", "assets", "public"}
_MAX_FILES = 400

# ── route declarations ────────────────────────────────────────────────
_RE_FLASK_ROUTE = re.compile(
    r"""@\w+\.route\(\s*['"]([^'"]+)['"](?:[^)]*methods\s*=\s*\[([^\]]*)\])?""", re.I)
_RE_VERB_DECORATOR = re.compile(
    r"""@\w+\.(get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]""", re.I)
_RE_DJANGO = re.compile(r"""(?:path|re_path|url)\(\s*r?['"]\^?([^'"$]+)['"]""")
_RE_EXPRESS = re.compile(
    r"""\b(?:app|router)\.(get|post|put|delete|patch|all)\(\s*['"`]([^'"`]+)['"`]""", re.I)

# ── request-param access ──────────────────────────────────────────────
_RE_PY_PARAM = re.compile(
    r"""request\.(?:args|form|values|GET|POST|json)(?:\.get\(\s*|\[\s*)['"]([^'"]+)['"]""")
_RE_JS_PARAM = re.compile(
    r"""req\.(?:query|params|body)(?:\.(\w+)|\[\s*['"]([^'"]+)['"]\s*\])""")
# path-embedded params: <int:id> / <id> / {id} / :id
_RE_PATH_PARAM = re.compile(r"""<(?:[^:>]+:)?([^>]+)>|\{(\w+)\}|:(\w+)""")

_PARAM_STOP = {"self", "request", "req", "res", "next"}


def _norm_route(path: str) -> str:
    if not path:
        return ""
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    # substitute path params with a probe-friendly value
    path = _RE_PATH_PARAM.sub("1", path)
    # collapse regex leftovers
    path = path.replace("$", "").replace("(?P", "").replace(")", "")
    return path


def _extract_from_file(text: str) -> Dict[str, Any]:
    routes: List[Dict[str, Any]] = []
    for m in _RE_FLASK_ROUTE.finditer(text):
        methods = [x.strip().strip("'\"").upper() for x in (m.group(2) or "").split(",") if x.strip()]
        routes.append({"path": m.group(1), "methods": methods or ["GET"]})
    for m in _RE_VERB_DECORATOR.finditer(text):
        routes.append({"path": m.group(2), "methods": [m.group(1).upper()]})
    for m in _RE_EXPRESS.finditer(text):
        verb = m.group(1).upper()
        routes.append({"path": m.group(2), "methods": ["GET"] if verb == "ALL" else [verb]})
    for m in _RE_DJANGO.finditer(text):
        routes.append({"path": m.group(1), "methods": ["GET", "POST"]})

    params: Set[str] = set()
    for m in _RE_PY_PARAM.finditer(text):
        params.add(m.group(1))
    for m in _RE_JS_PARAM.finditer(text):
        params.add(m.group(1) or m.group(2))
    params = {p for p in params if p and p not in _PARAM_STOP and len(p) < 40}
    return {"routes": routes, "params": params}


def _flagged_files(sast_findings: List[Dict[str, Any]]) -> Set[str]:
    out: Set[str] = set()
    for f in sast_findings or []:
        fp = str(f.get("file", "") or "")
        if fp:
            out.add(os.path.basename(fp))
    return out


def seed_requests_from_source(path: str, base_url: str,
                              sast_findings: List[Dict[str, Any]] | None = None,
                              max_routes: int = 60,
                              max_params_per_route: int = 8) -> List[Dict[str, Any]]:
    """Return captured-request dicts (url/method/headers/body) for routes+params
    declared in the source under `path`, resolved against `base_url`. Routes in
    SAST-flagged files come first. Bounded by `max_routes`."""
    if not path or not os.path.isdir(path) or not base_url:
        return []
    flagged = _flagged_files(sast_findings or [])
    base = base_url.rstrip("/")

    flagged_reqs: List[Dict[str, Any]] = []
    other_reqs: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    files_scanned = 0

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIRS]
        for fn in files:
            if not fn.endswith(_SRC_EXT):
                continue
            if files_scanned >= _MAX_FILES:
                break
            files_scanned += 1
            fpath = os.path.join(root, fn)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except Exception:
                continue
            info = _extract_from_file(text)
            if not info["routes"]:
                continue
            params = sorted(info["params"])[:max_params_per_route]
            bucket = flagged_reqs if fn in flagged else other_reqs
            for r in info["routes"]:
                route = _norm_route(r["path"])
                if not route or any(route.endswith(x) for x in (".css", ".js", ".png", ".ico", ".map")):
                    continue
                for method in r["methods"][:2]:
                    for req in _build_requests(base, route, method, params):
                        key = f"{req['method']} {req['url']}|{req.get('body','')}"
                        if key in seen:
                            continue
                        seen.add(key)
                        bucket.append(req)

    ordered = (flagged_reqs + other_reqs)[:max_routes]
    if ordered:
        logger.info("endpoint_seeder: seeded %d candidate requests from source "
                    "(%d from SAST-flagged files, %d files scanned)",
                    len(ordered), len([r for r in flagged_reqs if r in ordered]), files_scanned)
    return ordered


def _build_requests(base: str, route: str, method: str,
                    params: List[str]) -> List[Dict[str, Any]]:
    url = base + route
    if method in ("POST", "PUT", "PATCH") and params:
        body = "&".join(f"{p}=1" for p in params)
        return [{"url": url, "method": method,
                 "headers": {"content-type": "application/x-www-form-urlencoded"},
                 "body": body, "source": "sast_seed"}]
    # GET (or param-less) — put params in the query string so query points appear
    if params:
        url = url + ("&" if "?" in url else "?") + "&".join(f"{p}=1" for p in params)
    return [{"url": url, "method": method or "GET", "headers": {}, "source": "sast_seed"}]
