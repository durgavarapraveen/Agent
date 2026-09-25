"""Package-reputation feed — deterministic, offline typosquat / malicious-dependency
detection for software-composition analysis.

Given a dependency NAME (+ optional ecosystem) it returns a verdict without any
network call by default:
  - "malicious"  : name is in the curated known-bad set (documented malicious /
                   typosquat packages) → high-confidence, confirmed.
  - "typosquat"  : name is a Damerau-Levenshtein distance 1 look-alike of a
                   popular package it is NOT (catches transposition + homoglyph
                   lower-casing, e.g. jeIlyfish→jellyfish, crossenv→cross-env).
  - "suspect"    : distance 2 look-alike → advisory.
  - "ok"         : no match.

The feed is data, not code: it ships a curated baseline and additionally loads
an optional JSON override at ``data/package_reputation.json`` (or the path in
``PACKAGE_REPUTATION_FILE``) so it can be updated without editing this module.
An OPTIONAL online enrichment (OSV.dev) is gated behind
``PACKAGE_REPUTATION_ONLINE=1`` and off by default (it would send dependency
names to a third party — keep it off under data-residency constraints).
"""
from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# --- curated known-bad set (real, documented npm/PyPI incidents) -------------
# name(lowercased) -> the legit package it impersonates (or "" if standalone bad)
KNOWN_MALICIOUS: Dict[str, str] = {
    # npm
    "crossenv": "cross-env", "cross-env.js": "cross-env", "mongose": "mongoose",
    "mysqljs": "mysql", "nodesqlite": "sqlite3", "sqlite.js": "sqlite3",
    "sqliter": "sqlite3", "node-sqlite": "sqlite3", "mssql-node": "mssql",
    "mssql.js": "mssql", "babelcli": "babel-cli", "jquery.js": "jquery",
    "node-fabric": "fabric", "fabric-js": "fabric", "node-opencv": "opencv",
    "node-opensl": "openssl", "node-tkinter": "", "nodemailer-js": "nodemailer",
    "nodemailer.js": "nodemailer", "nodefabric": "fabric", "shadersloader": "",
    "proxy.js": "proxy", "discord.js-user": "discord.js", "discordi.js": "discord.js",
    "electorn": "electron", "loadyaml": "js-yaml", "lodahs": "lodash",
    "twilio-npm": "twilio", "ffmepg": "ffmpeg", "gruntcli": "grunt-cli",
    "http-proxy.js": "http-proxy", "coffescript": "coffeescript",
    "d3.js": "d3", "fabric-js2": "fabric", "smrequest": "request",
    "event-stream-fix": "event-stream", "flatmap-stream": "",
    # PyPI
    "colourama": "colorama", "djanga": "django", "diango": "django",
    "requestts": "requests", "reqests": "requests", "beautifulsup4": "beautifulsoup4",
    "python-sqlite": "", "python3-dateutil": "python-dateutil",
    "jeilyfish": "jellyfish",  # historical homoglyph (jeIlyfish)
    "python-mysql": "", "urllib": "urllib3", "numpycython": "numpy",
    "libpeshka": "", "setup-tools": "setuptools", "pytprint": "",
}

# --- popular baselines for distance-based typosquat detection ----------------
POPULAR_NPM = {
    "react", "react-dom", "lodash", "express", "axios", "chalk", "commander",
    "request", "moment", "async", "debug", "bluebird", "underscore", "jquery",
    "vue", "angular", "webpack", "babel-cli", "cross-env", "typescript", "eslint",
    "prettier", "jest", "mocha", "chai", "socket.io", "mongoose", "mysql", "mssql",
    "pg", "redis", "dotenv", "cors", "body-parser", "morgan", "helmet", "passport",
    "jsonwebtoken", "bcrypt", "node-fetch", "uuid", "nodemailer", "sqlite3",
    "sequelize", "graphql", "next", "nuxt", "vite", "rollup", "d3", "three",
    "electron", "grunt-cli", "gulp", "coffeescript", "http-proxy", "ffmpeg",
    "discord.js", "twilio", "openssl", "fabric", "js-yaml", "ws", "ioredis",
}
POPULAR_PYPI = {
    "requests", "numpy", "pandas", "flask", "django", "colorama", "jellyfish",
    "urllib3", "beautifulsoup4", "setuptools", "pip", "boto3", "scipy",
    "python-dateutil", "pyyaml", "six", "certifi", "idna", "click", "jinja2",
    "werkzeug", "sqlalchemy", "pytest", "wheel", "cryptography", "pillow",
    "matplotlib", "scikit-learn", "torch", "tensorflow", "keras", "fastapi",
    "uvicorn", "pydantic", "aiohttp", "httpx", "lxml", "openpyxl", "redis",
    "celery", "gunicorn", "psycopg2", "pymysql", "markupsafe", "attrs",
}
POPULAR = {"npm": POPULAR_NPM, "pypi": POPULAR_PYPI}


def _damerau_levenshtein(a: str, b: str) -> int:
    """Edit distance with transpositions (bounded, small strings)."""
    la, lb = len(a), len(b)
    if abs(la - lb) > 2:
        return 3
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


@lru_cache(maxsize=1)
def _feed() -> Tuple[Dict[str, str], Dict[str, set]]:
    """Curated baseline extended by an optional JSON override file."""
    malicious = dict(KNOWN_MALICIOUS)
    popular = {"npm": set(POPULAR_NPM), "pypi": set(POPULAR_PYPI)}
    path = os.getenv("PACKAGE_REPUTATION_FILE") or os.path.join("data", "package_reputation.json")
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                ext = json.load(fh)
            for k, v in (ext.get("malicious") or {}).items():
                malicious[str(k).lower()] = str(v or "")
            for eco, names in (ext.get("popular") or {}).items():
                popular.setdefault(eco, set()).update(str(n).lower() for n in names)
            logger.info("[PkgRep] loaded feed override from %s", path)
    except Exception as e:
        logger.debug("[PkgRep] feed override skipped: %s", e)
    return malicious, popular


def _norm(name: str) -> str:
    name = (name or "").strip().lower()
    # strip a scoped npm prefix ("@scope/pkg" -> "pkg") for comparison
    if name.startswith("@") and "/" in name:
        name = name.split("/", 1)[1]
    return name


def evaluate(name: str, ecosystem: Optional[str] = None) -> Dict[str, object]:
    """Return {'verdict','name','legit','distance','severity','confirmed'}."""
    n = _norm(name)
    if not n or len(n) < 2:
        return {"verdict": "ok", "name": name}
    malicious, popular = _feed()

    if n in malicious:
        return {"verdict": "malicious", "name": name, "legit": malicious[n] or None,
                "distance": 0, "severity": "critical", "confirmed": True}

    ecos = [ecosystem] if ecosystem in popular else list(popular.keys())
    # an exact popular name is legit — never flag it
    for eco in ecos:
        if n in popular[eco]:
            return {"verdict": "ok", "name": name}

    best_name, best_d = None, 99
    for eco in ecos:
        for legit in popular[eco]:
            if len(legit) < 4:
                continue
            d = _damerau_levenshtein(n, legit)
            if d < best_d:
                best_d, best_name = d, legit
                if d == 1:
                    break
    if best_name and best_d == 1 and len(n) >= 4:
        return {"verdict": "typosquat", "name": name, "legit": best_name,
                "distance": 1, "severity": "high", "confirmed": True}
    if best_name and best_d == 2 and len(n) >= 5:
        return {"verdict": "suspect", "name": name, "legit": best_name,
                "distance": 2, "severity": "medium", "confirmed": False}
    return {"verdict": "ok", "name": name}


async def enrich_online(names: List[str]) -> Dict[str, dict]:
    """OPTIONAL OSV.dev lookup, OFF unless PACKAGE_REPUTATION_ONLINE=1 (sends
    names to a third party — respect data residency)."""
    if os.getenv("PACKAGE_REPUTATION_ONLINE", "0") not in ("1", "true", "yes", "on"):
        return {}
    out: Dict[str, dict] = {}
    try:
        import aiohttp
        async with aiohttp.ClientSession() as s:
            for nm in names[:40]:
                try:
                    async with s.post("https://api.osv.dev/v1/query",
                                      json={"package": {"name": nm}},
                                      timeout=aiohttp.ClientTimeout(total=10)) as r:
                        data = await r.json()
                    vulns = data.get("vulns") or []
                    if vulns:
                        out[nm] = {"osv_ids": [v.get("id") for v in vulns[:5]]}
                except Exception:
                    continue
    except Exception:
        pass
    return out
