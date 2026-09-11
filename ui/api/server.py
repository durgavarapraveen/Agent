
import asyncio
import json
import logging
import os
import subprocess
import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List

# ── Observability bootstrap ─────────────────────────────────────────────
# Structured JSON logging with global PII redaction, Prometheus metrics, and
# OpenTelemetry tracing (all with graceful no-op fallbacks). Installed BEFORE
# any other logger is instantiated so every downstream log line goes through
# the JSON formatter and PII filter.
from core.observability import logging as _ag_logging
_ag_logging.configure_root(level=os.environ.get("LOG_LEVEL", "INFO"))
from core.observability import metrics as _metrics
from core.observability import tracing as _tracing

# Phase 6.4 — install egress firewall guard on httpx so every outbound
# request (from server or from any imported library) is scope-checked.
try:
    from core.security.egress_firewall import install_httpx_guard as _install_egress
    _install_egress()
except Exception as _egress_err:
    __import__("logging").getLogger(__name__).warning(
        "SECURITY: egress guard install failed: %s", _egress_err)

logger = logging.getLogger("antigravity.api")

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="AntiGravity Dashboard API", version="1.0.0")

# ── Rate limiting ─────────────────────────────────────────────────────────
# `slowapi` is a soft dependency. When installed, it caps the abuse-prone
# endpoints (scan launch, kill-all, RAG ingest) per-IP; when absent, the app
# still boots but rate limiting is a no-op. Install with `pip install slowapi`.
_LIMITER = None
try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware

    _LIMITER = Limiter(key_func=get_remote_address, default_limits=[])
    app.state.limiter = _LIMITER

    @app.exception_handler(RateLimitExceeded)
    async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
        return JSONResponse(
            {"error": "rate_limit_exceeded", "detail": str(exc)},
            status_code=429,
            headers={"Retry-After": "60"},
        )

    app.add_middleware(SlowAPIMiddleware)
except ImportError:
    logger.warning(
        "slowapi not installed — rate limiting disabled. "
        "Install with `pip install slowapi` before deploying.")


def _rate_limit(limit: str):
    if _LIMITER is None:
        def _noop(fn):
            return fn
        return _noop
    return _LIMITER.limit(limit)


# ── Simple built-in per-route rate limiter ────────────────────────────────
# Backstop that works even without slowapi. A rolling window per (client, route)
# guards the abuse-prone endpoints listed in `_ROUTE_LIMITS` below. This is
# best-effort in-memory; behind a reverse proxy the real primary rate limiter
# should live at the proxy.
import time as _time
from collections import deque as _deque, defaultdict as _defaultdict, OrderedDict

_ROUTE_LIMITS = {
    "/api/scans/run":         (5, 60),
    "/api/scans/kill-all":    (10, 60),
    "/api/rag/ingest/file":   (10, 60),
    "/api/rag/ingest/url":    (10, 60),
    "/api/rag/ingest/search": (10, 60),
    "/api/rag/ingest/uploaded": (10, 60),
    "/api/campaigns/run":     (3, 60),
}
_rl_buckets: dict = _defaultdict(_deque)
_rl_lock = threading.Lock()


@app.middleware("http")
async def _builtin_rate_limit(request: Request, call_next):
    path = request.url.path or ""
    for prefix, (limit, window) in _ROUTE_LIMITS.items():
        if path.startswith(prefix):
            client = (request.client.host if request.client else "unknown")
            key = f"{client}|{prefix}"
            now = _time.monotonic()
            with _rl_lock:
                q = _rl_buckets[key]
                # Drop timestamps outside the rolling window.
                while q and q[0] <= now - window:
                    q.popleft()
                if len(q) >= limit:
                    return JSONResponse(
                        {"error": "rate_limit_exceeded",
                         "detail": f"max {limit} requests per {window}s per client"},
                        status_code=429,
                        headers={"Retry-After": str(window)},
                    )
                q.append(now)
            break
    return await call_next(request)

# ── HTTP metrics middleware ─────────────────────────────────────────────
@app.middleware("http")
async def _http_metrics(request: Request, call_next):
    response = await call_next(request)
    try:
        route = getattr(request.scope.get("route"), "path", None) or "unknown"
        status_class = f"{response.status_code // 100}xx"
        _metrics.HTTP_REQUEST.labels(
            method=request.method,
            route=route,
            status_class=status_class,
        ).inc()
    except Exception:
        pass
    return response


# ── Environment mode ──────────────────────────────────────────────────────
# `ANTIGRAVITY_ENV` selects the runtime mode. Values: `development` (dev-friendly
# defaults), `production` (strict; refuses to boot without auth+CORS).
_ENV_MODE = os.getenv("ANTIGRAVITY_ENV", "development").strip().lower()
_IS_PROD = _ENV_MODE in ("production", "prod")

# ── CORS ──────────────────────────────────────────────────────────────────
# In production, an explicit `CORS_ORIGINS` allowlist is required. `*` is
# refused at boot. In development, defaults to common localhost origins.
_cors_origins_env = os.getenv("CORS_ORIGINS", "").strip()
if _cors_origins_env:
    _cors_origins = [o.strip() for o in _cors_origins_env.split(",") if o.strip()]
elif _IS_PROD:
    raise RuntimeError(
        "ANTIGRAVITY_ENV=production requires explicit CORS_ORIGINS allowlist "
        "(e.g. CORS_ORIGINS=https://ui.example.com). Refusing to start with `*`.")
else:
    _cors_origins = [
        "http://localhost:5173", "http://127.0.0.1:5173",  # Vite dev
        "http://localhost:8903", "http://127.0.0.1:8903",
    ]

if _IS_PROD and "*" in _cors_origins:
    raise RuntimeError(
        "CORS_ORIGINS=`*` is not permitted in production. Provide an allowlist.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=("*" not in _cors_origins),
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)

# ── API-key auth ──────────────────────────────────────────────────────────
# `API_KEY` env is REQUIRED in production. In development, if unset, we
# auto-generate a random key on first boot and write it to `.antigravity/
# dev_api_key` so the dev flow keeps working — the operator can copy the
# printed key into their SPA config. The key is NEVER accepted via query
# string (leaks to logs / Referer / proxy caches). Header only.
_API_KEY = os.getenv("API_KEY", "").strip()
if not _API_KEY:
    if _IS_PROD:
        raise RuntimeError(
            "ANTIGRAVITY_ENV=production requires API_KEY to be set. "
            "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'")
    # Dev auto-key
    _dev_key_path = Path(__file__).resolve().parent.parent.parent / ".antigravity" / "dev_api_key"
    try:
        if _dev_key_path.exists():
            _API_KEY = _dev_key_path.read_text().strip()
        else:
            import secrets
            _API_KEY = secrets.token_urlsafe(32)
            _dev_key_path.parent.mkdir(parents=True, exist_ok=True)
            _dev_key_path.write_text(_API_KEY)
            try:
                os.chmod(_dev_key_path, 0o600)
            except Exception:
                pass  # Windows
        logger.warning(
            "DEV MODE: auto-generated API key at %s. "
            "Set API_KEY explicitly and ANTIGRAVITY_ENV=production before deploying.",
            _dev_key_path)
    except Exception as e:
        logger.error("Failed to persist dev API key (%s); auth still enforced in-memory.", e)
        import secrets
        _API_KEY = secrets.token_urlsafe(32)

_AUTH_EXEMPT_PATHS = {"/", "/docs", "/openapi.json", "/redoc",
                       "/api/health", "/favicon.ico"}


def _constant_time_eq(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# Download-style GETs — the browser cannot set custom headers on a top-level
# navigation (window.open / <a href>) so we accept `?api_key=` on this narrow
# allowlist only. Everything else must use the X-API-Key header.
_QUERY_AUTH_SUFFIXES = (
    "/logs-download",
    "/report",
    "/sarif",
    "/gitlab-dast",
)
_QUERY_AUTH_PREFIXES = (
    "/api/evidence/",
)


def _accepts_query_auth(path: str, method: str) -> bool:
    if method.upper() != "GET":
        return False
    if any(path.endswith(s) for s in _QUERY_AUTH_SUFFIXES):
        return True
    if any(path.startswith(p) for p in _QUERY_AUTH_PREFIXES):
        return True
    return False


@app.middleware("http")
async def _require_api_key(request: Request, call_next):
    path = request.url.path or ""
    if path in _AUTH_EXEMPT_PATHS or path.startswith(("/assets/", "/static/")):
        return await call_next(request)
    provided = request.headers.get("x-api-key") or ""
    if not _constant_time_eq(provided, _API_KEY):
        # Allow `?api_key=` on download-style GETs only.
        if _accepts_query_auth(path, request.method):
            qp = request.query_params.get("api_key") or ""
            if _constant_time_eq(qp, _API_KEY):
                return await call_next(request)
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return await call_next(request)

# Serve built frontend in production
_FRONTEND_DIR = Path(__file__).resolve().parent.parent / "web" / "dist"
if _FRONTEND_DIR.exists():
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse as _FR

    @app.get("/", include_in_schema=False)
    async def _serve_index():
        return _FR(str(_FRONTEND_DIR / "index.html"))

    # Mount after all API routes are registered (see bottom of file)

BASE = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE))
# reports/ is opt-in via REPORTS_ENABLED. When disabled, this directory is
# a placeholder — scan-log endpoints degrade gracefully (return "").
from core.common.reports_config import reports_enabled as _reports_enabled, reports_dir as _reports_dir
REPORTS_DIR = BASE / _reports_dir()
# Scan logs: subprocess writes to logs/scans/*.txt during the run (needs a real
# file handle), then on scan completion we flush the full log to `scan_artifacts`
# (kind='scan_log') and delete the tempfile. Log endpoints read DB first, fall
# back to the live tempfile while a scan is running.
SCAN_LOGS_DIR = BASE / "logs" / "scans"
SCAN_LOGS_DIR.mkdir(parents=True, exist_ok=True)


def _scan_log_path(job_id: str) -> Path:
    return SCAN_LOGS_DIR / f"scan_log_{job_id}.txt"


def _flush_scan_log_to_db(job_id: str) -> int:
    try:
        p = _scan_log_path(job_id)
        if not p.exists() or not p.is_file():
            return 0
        content = p.read_bytes()
        if not content:
            return 0
        from core.database.pg_store import ScanArtifactRepo
        # Delete any previous log artefact for this scan so we replace it
        existing = ScanArtifactRepo.list_by_scan(job_id, kind="scan_log")
        aid = ScanArtifactRepo.insert(
            job_id, "scan_log", "scan_log.txt", content,
            mime_type="text/plain",
            metadata={"lines": content.count(b"\n"), "size_bytes": len(content),
                      "replaces_ids": [r["id"] for r in existing]})
        try:
            p.unlink()
        except Exception:
            pass
        return aid
    except Exception:
        return 0


def _read_scan_log(job_id: str) -> bytes:
    try:
        from core.database.pg_store import ScanArtifactRepo
        rows = ScanArtifactRepo.list_by_scan(job_id, kind="scan_log")
        if rows:
            full = ScanArtifactRepo.get(rows[0]["id"])
            if full and full.get("content"):
                return bytes(full["content"])
    except Exception:
        pass
    p = _scan_log_path(job_id)
    if p.exists() and p.is_file():
        try:
            return p.read_bytes()
        except Exception:
            pass
    return b""

# ── PostgreSQL initialization ──────────────────────────────────────────────
sys.path.insert(0, str(BASE))
from core.database.pg_store import (
    _init_schema, TargetRepo, ScanRepo, VulnRepo, LiveDataRepo,
    FindingV2Repo, DedupRepo, AuditRepo, ScheduleRepo, CampaignRepo,
    ExploitResultRepo, ScanArtifactRepo, AuthBypassRepo, LiveAgentRepo, make_run_id,
)
try:
    _init_schema()
except Exception as _e:
    import logging as _log
    _log.getLogger(__name__).warning(f"PG schema init failed (will retry on first query): {_e}")

# Reconcile any scan rows left in `running/starting/stopping` from a previous
# API/process crash. Without this, a crashed scan blocks new scans of the same
# target forever and the UI shows a stuck progress bar. Best-effort — never
# raises.
try:
    ScanRepo.bootstrap_recover()
except Exception as _e:
    import logging as _log
    _log.getLogger(__name__).warning(f"bootstrap_recover skipped: {_e}")


# ── Models ──────────────────────────────────────────────────────────────────
from pydantic import Field, field_validator
from urllib.parse import urlparse as _urlparse
import ipaddress as _ipaddress


_ALLOWED_TIERS = {"PASSIVE", "SAFE_ACTIVE", "DEEP", "POC"}
_ALLOWED_PHASES = {
    "RECON", "OSINT", "DISCOVERY", "SCANNING", "ACTIVE_SCANNING",
    "EXPLOITATION", "POSTEX", "POST_EXPLOIT", "REPORTING",
}
# URL schemes accepted on user-facing inputs. `file://`, `gopher://`, `dict://`
# and other non-HTTP schemes are blocked to prevent SSRF via RAG/URL ingest.
_ALLOWED_SCHEMES = {"http", "https"}


def _validate_target_url(v: str) -> str:
    if not v or not isinstance(v, str):
        raise ValueError("target must be a non-empty string")
    v = v.strip()
    if len(v) > 2048:
        raise ValueError("target too long (max 2048)")
    parsed = _urlparse(v if "://" in v else "http://" + v)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"scheme must be one of {sorted(_ALLOWED_SCHEMES)}")
    if parsed.username or parsed.password:
        raise ValueError("credentials in URL are not allowed")
    if not parsed.hostname:
        raise ValueError("hostname required")
    # Allow IPs and hostnames; reject only obviously-malformed characters.
    import re as _re
    if not _re.match(
        r'^[A-Za-z0-9._\-:%\[\]]+$',  # []: for IPv6 literals
        parsed.hostname,
    ):
        raise ValueError("hostname contains invalid characters")
    return v


class TargetCreate(BaseModel):
    url: str = Field(..., max_length=2048)
    scope: str = Field("", max_length=8192)
    notes: str = Field("", max_length=8192)

    @field_validator("url")
    @classmethod
    def _v_url(cls, v: str) -> str:
        return _validate_target_url(v)


class ScanRequest(BaseModel):
    target: str = Field(..., max_length=2048)
    tier: str = "POC"
    auto_approve: bool = False
    skip_osint: bool = False
    reset_dedup: bool = False
    # Operator opt-in (decided at scan start): allow tool arguments to carry
    # shell metacharacters as literal data (shlex-quoted, never raw shell).
    # Default False = safe reject. See core.utils.scan_flags.allow_shell_operators.
    allow_shell_operators: bool = False
    # Operator opt-in: reuse a captured/active bearer token for requests that do
    # NOT declare a session. Default False = anonymous-by-default (P0.2), so a
    # captured JWT cannot silently authenticate later anonymous/authz tests.
    allow_ambient_auth: bool = False
    phases: List[str] = Field(default_factory=list, max_length=16)
    credentials: List[dict] = Field(default_factory=list, max_length=32)
    # Grey-box / mobile inputs (Phases 4.4 / 4.5). Paths are server-side (from the
    # /api/uploads/scan-input endpoint); source_repo is a git URL. Passed to
    # main.py as list args (no shell), so no injection surface.
    mobile_app: str = Field(default="", max_length=1024)
    ipa_app: str = Field(default="", max_length=1024)
    source_repo: str = Field(default="", max_length=2048)
    source_path: str = Field(default="", max_length=1024)

    @field_validator("target")
    @classmethod
    def _v_target(cls, v: str) -> str:
        return _validate_target_url(v)

    @field_validator("tier")
    @classmethod
    def _v_tier(cls, v: str) -> str:
        v = str(v or "").strip().upper()
        if v not in _ALLOWED_TIERS:
            raise ValueError(f"tier must be one of {sorted(_ALLOWED_TIERS)}")
        return v

    @field_validator("phases")
    @classmethod
    def _v_phases(cls, v: List[str]) -> List[str]:
        out = []
        for p in v or []:
            p_norm = str(p or "").strip().upper()
            if p_norm and p_norm not in _ALLOWED_PHASES:
                raise ValueError(f"phase '{p}' not one of {sorted(_ALLOWED_PHASES)}")
            if p_norm:
                out.append(p_norm)
        return out



# ── Scan Process Tracker ────────────────────────────────────────────────────

_active_scans: dict = {}  # in-memory cache, synced to PG


def _persist_scan_state():
    for job_id, job in _active_scans.items():
        try:
            ScanRepo.update_status(job_id, job.get("status", "unknown"),
                                   pid=job.get("pid"), exit_code=job.get("exit_code"),
                                   error=job.get("error", ""), command=job.get("command", ""),
                                   log_file=job.get("log_file", ""))
        except Exception:
            pass


_SECRET_PATTERNS = None


def _scrub_secrets(text: str) -> str:
    global _SECRET_PATTERNS
    if _SECRET_PATTERNS is None:
        import re as _re
        _SECRET_PATTERNS = [
            # Authorization / Cookie headers
            (_re.compile(r'(?i)(authorization\s*[:=]\s*)(bearer\s+)?\S+'),
             r'\1\2[REDACTED]'),
            (_re.compile(r'(?i)(cookie\s*[:=]\s*)[^\r\n]+'),
             r'\1[REDACTED]'),
            (_re.compile(r'(?i)(set-cookie\s*[:=]\s*)[^\r\n]+'),
             r'\1[REDACTED]'),
            # password / api_key / token / secret in key=value form
            (_re.compile(r'(?i)(pass(?:word)?|api[_-]?key|token|secret|access[_-]?token'
                          r'|refresh[_-]?token|session[_-]?id)\s*[:=]\s*[\'"]?([^\s\'";,]{4,})[\'"]?'),
             r'\1=[REDACTED]'),
            # AWS
            (_re.compile(r'AKIA[0-9A-Z]{16}'), '[REDACTED_AWS_KEY]'),
            # JWT (3 dot-separated base64url segments; head is usually eyJ...)
            (_re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
             '[REDACTED_JWT]'),
        ]
    out = text
    for pat, repl in _SECRET_PATTERNS:
        out = pat.sub(repl, out)
    return out


def _redact_command(cmd: list) -> str:
    redacted = []
    skip_next = False
    for tok in cmd:
        if skip_next:
            redacted.append("[REDACTED]")
            skip_next = False
            continue
        if tok in ("--credentials", "--credentials-file", "--password", "--token"):
            redacted.append(tok)
            skip_next = True
            continue
        redacted.append(str(tok))
    return " ".join(redacted)


def _is_pid_alive(pid: int) -> bool:
    try:
        import psutil
        return psutil.pid_exists(pid)
    except ImportError:
        pass
    try:
        if os.name == "nt":
            import subprocess
            cmd = ["tasklist", "/FI", f"PID eq {pid}", "/NH"]
            r = subprocess.run(cmd, shell=False,
                               capture_output=True, encoding="utf-8", timeout=5)
            return str(pid) in r.stdout
        else:
            os.kill(pid, 0)
            return True
    except (OSError, Exception):
        return False


def _load_scan_state():
    global _active_scans
    try:
        for scan in ScanRepo.get_active():
            sid = scan["scan_id"]
            pid = scan.get("pid")
            status = scan["status"]
            if pid and not _is_pid_alive(pid) and status in ("running", "starting", "stopping"):
                status = "stopped" if status == "stopping" else "completed"
                ScanRepo.update_status(sid, status)
            if status in ("cancelled", "completed", "failed"):
                continue
            _active_scans[sid] = {
                "job_id": sid, "target": scan["target"], "tier": scan.get("tier", "POC"),
                "status": status, "started_at": str(scan.get("started_at", "")),
                "finished_at": str(scan.get("finished_at", "")), "pid": pid,
                "exit_code": scan.get("exit_code"), "error": scan.get("error", ""),
                "log_file": scan.get("log_file") or str(_scan_log_path(sid)),
                "command": scan.get("command", ""),
            }
    except Exception:
        _active_scans = {}


_load_scan_state()


# ── Health, metrics, and lifecycle ─────────────────────────────────────
def _kali_container_healthy() -> tuple[bool, str]:
    import shutil as _sh
    import subprocess as _sp
    if not _sh.which("docker"):
        return True, "docker_cli_missing"
    container = os.getenv("KALI_CONTAINER", os.getenv("DOCKER_CONTAINER", "kali-pentesting"))
    try:
        r = _sp.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", container],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return False, f"container_missing:{container}"
        state = (r.stdout or "").strip().lower()
        return state == "running", f"state:{state or 'unknown'}"
    except Exception as e:
        return False, f"probe_error:{e}"


@app.get("/api/source-ip", include_in_schema=True)
def source_ip():
    import os
    from core.security.anon_gate import _vpn_configured, _fetch_direct_ip
    mode = "vpn" if _vpn_configured() else "direct"
    if mode == "vpn":
        try:
            from core.security.anon_gate import check_exit_ip
            ip, is_tor = check_exit_ip()
            return {"mode": "vpn", "ip": ip, "is_tor": is_tor,
                    "chain_up": True,
                    "proxy": os.getenv("HTTPS_PROXY") or os.getenv("ALL_PROXY") or ""}
        except Exception as e:
            return {"mode": "vpn", "ip": None, "is_tor": False,
                    "chain_up": False, "error": str(e)}
    return {"mode": "direct", "ip": _fetch_direct_ip() or None,
            "is_tor": False, "chain_up": True}


@app.get("/api/health", include_in_schema=True)
def health():
    checks: dict = {"status": "ok", "checks": {}}
    http_code = 200

    # Postgres
    try:
        from core.memory.database import DatabaseManager
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        checks["checks"]["postgres"] = "ok"
    except Exception as e:
        checks["checks"]["postgres"] = f"unavailable: {e}"
        checks["status"] = "degraded"
        http_code = 503

    # Kali container (soft — degrades to "warn" so lifecycle probes can
    # still start the API while the Kali container comes up).
    ok, detail = _kali_container_healthy()
    checks["checks"]["kali_container"] = detail if ok else f"down ({detail})"
    if not ok:
        checks["status"] = "degraded" if checks["status"] == "ok" else checks["status"]

    # LLM harness (informational only)
    try:
        from agents.llm_harness_adapter import get_llm
        checks["checks"]["llm_harness"] = "initialised" if get_llm() else "not_initialised"
    except Exception as e:
        checks["checks"]["llm_harness"] = f"error: {e}"

    # Metrics adapter
    checks["checks"]["metrics"] = "prometheus" if _metrics.is_available() else "noop"
    checks["checks"]["tracing"] = "otel" if _tracing.is_available() else "noop"

    return JSONResponse(checks, status_code=http_code)


@app.get("/api/metrics", include_in_schema=False)
def metrics_endpoint():
    from fastapi.responses import Response
    body, content_type = _metrics.render()
    if not _metrics.is_available():
        return Response(
            body,
            status_code=501,
            media_type=content_type,
            headers={"X-Metrics-Backend": "noop"},
        )
    return Response(body, media_type=content_type)


@app.on_event("startup")
async def _on_startup():
    # Report which IP will be used (direct or VPN exit). Aborts the API
    # process only when VPN mode is on and the chain isn't up.
    try:
        from core.security.anon_gate import enforce_or_die
        enforce_or_die()
    except SystemExit:
        raise
    except Exception as _e:
        logger.warning(f"[AnonGate] skipped in API startup: {_e}")

    _metrics.SCAN_ACTIVE.set(len(_active_scans))
    logger.info("API startup complete", extra={
        "active_scans": len(_active_scans),
        "metrics_backend": "prometheus" if _metrics.is_available() else "noop",
        "tracing_backend": "otel" if _tracing.is_available() else "noop",
    })


@app.on_event("shutdown")
async def _on_shutdown():
    logger.info("API shutdown starting", extra={
        "active_scans": len(_active_scans),
        "ws_push_tasks": len(_ws_push_tasks) if "_ws_push_tasks" in globals() else 0,
    })

    # 1. Cancel every WS push task. Each has its own asyncio.CancelledError
    # handler that closes the sockets cleanly.
    if "_ws_push_tasks" in globals():
        import asyncio as _aio
        tasks = list(_ws_push_tasks.values())
        for t in tasks:
            try:
                t.cancel()
            except Exception:
                pass
        if tasks:
            try:
                await _aio.wait(tasks, timeout=3.0)
            except Exception:
                pass
        _ws_push_tasks.clear()

    # 2. Mark active scans `stopping` so the next boot's bootstrap_recover
    # sweep can pick them up. Never terminate the subprocess here — supervisor
    # restart may want to hand off to the same PID.
    try:
        for job_id, job in list(_active_scans.items()):
            if job.get("status") in ("running", "starting"):
                job["status"] = "stopping"
        _persist_scan_state()
    except Exception as e:
        logger.warning("Shutdown scan-state persistence failed: %s", e)

    logger.info("API shutdown complete")


def _run_scan_process(job_id: str, target: str, tier: str,
                      auto_approve: bool, skip_osint: bool, reset_dedup: bool,
                      resume: bool = False, phases: list = None,
                      credentials: dict = None, allow_shell_operators: bool = False,
                      allow_ambient_auth: bool = False,
                      mobile_app: str = "", ipa_app: str = "",
                      source_repo: str = "", source_path: str = ""):
    log_file = _scan_log_path(job_id)
    cmd = [sys.executable, str(BASE / "main.py"), "--target", target, "--tier", tier]
    if auto_approve:
        cmd.append("--auto-approve")
    if skip_osint:
        cmd.append("--skip-osint")
    if reset_dedup:
        cmd.append("--reset-dedup")
    if resume:
        cmd.append("--resume")
    if phases:
        cmd.extend(["--phases", ",".join(phases)])
    # Grey-box / mobile inputs (Phases 4.4 / 4.5).
    if mobile_app:
        cmd.extend(["--mobile-app", mobile_app])
    if ipa_app:
        cmd.extend(["--ipa-app", ipa_app])
    if source_repo:
        cmd.extend(["--source-repo", source_repo])
    if source_path:
        cmd.extend(["--source-path", source_path])
    # Credentials must NEVER be passed as command-line arguments — argv is
    # world-readable via /proc/<pid>/cmdline and would echo through every
    # `/api/scans/job/{id}` response (see #046/#047). Instead we write them
    # to a locked temporary file under `.antigravity/scan_creds/<job_id>.json`
    # with restrictive permissions and hand the child process the path. The
    # child (main.py) reads and unlinks. On any failure the file is unlinked.
    creds_path: Optional[Path] = None
    if credentials:
        import json as _json
        import stat as _stat
        creds_dir = BASE / ".antigravity" / "scan_creds"
        creds_dir.mkdir(parents=True, exist_ok=True)
        creds_path = creds_dir / f"{job_id}.json"
        creds_path.write_text(_json.dumps(credentials), encoding="utf-8")
        try:
            os.chmod(creds_path, _stat.S_IRUSR | _stat.S_IWUSR)  # 0600
        except Exception:
            pass  # Windows: NTFS ACL applies
        cmd.extend(["--credentials-file", str(creds_path)])

    # The run's identity is the job_id — pass it so the brain persists every row
    # (scan, vulns, review queue) under this exact id and never merges with another run.
    cmd.extend(["--scan-id", job_id])

    _active_scans[job_id]["status"] = "running"
    # Store a REDACTED representation of the command in the active-scans dict
    # so `/api/scans/job/{job_id}` can't leak credential contents (the value
    # displayed to the operator is just the argv skeleton). The `--credentials-file`
    # path itself does not contain the secret.
    _active_scans[job_id]["command"] = _redact_command(cmd)
    _persist_scan_state()

    # Metrics: increment scans-started; bump active-scans gauge.
    try:
        _metrics.SCAN_STARTED.labels(tier=tier or "unknown").inc()
        _metrics.SCAN_ACTIVE.set(len(_active_scans))
    except Exception:
        pass
    _scan_start_wall = datetime.utcnow()

    # Propagate the current OpenTelemetry span context to the child via
    # a `traceparent` env var so all child spans link back to this scan.
    _child_env = os.environ.copy()
    # Per-scan operator policy: propagate the shell-operator decision to the
    # scan subprocess (read by core.utils.scan_flags.allow_shell_operators).
    _child_env["ALLOW_SHELL_OPERATORS"] = "1" if allow_shell_operators else "0"
    # Per-scan operator policy: ambient (undeclared-session) token reuse.
    _child_env["ALLOW_AMBIENT_AUTH"] = "1" if allow_ambient_auth else "0"
    try:
        _child_env.update({k.upper(): v for k, v in _tracing.inject_headers().items()})
    except Exception:
        pass

    # Clean any leftover stop signal from a previous kill-all
    slug = target.replace("://", "_").replace("/", "_").replace(":", "_")
    old_signal = BASE / ".antigravity" / f"stop_{slug}.signal"
    if old_signal.exists():
        try:
            old_signal.unlink()
        except Exception:
            pass

    try:
        with open(log_file, "w", encoding="utf-8") as lf:
            proc = subprocess.Popen(
                cmd, stdout=lf, stderr=subprocess.STDOUT,
                cwd=str(BASE), encoding="utf-8", errors="replace",
                env=_child_env,
            )
            _active_scans[job_id]["pid"] = proc.pid
            _persist_scan_state()
            proc.wait()
            _active_scans[job_id]["exit_code"] = proc.returncode
            if _active_scans[job_id]["status"] == "stopping":
                _active_scans[job_id]["status"] = "stopped"
            else:
                _active_scans[job_id]["status"] = "completed" if proc.returncode == 0 else "failed"
    except Exception as e:
        _active_scans[job_id]["status"] = "failed"
        _active_scans[job_id]["error"] = str(e)
    finally:
        # Record terminal metrics regardless of how we exited.
        try:
            elapsed = max(0.0, (datetime.utcnow() - _scan_start_wall).total_seconds())
            terminal_status = _active_scans[job_id].get("status", "unknown")
            _metrics.SCAN_FINISHED.labels(tier=tier or "unknown", status=terminal_status).inc()
            _metrics.SCAN_DURATION_SECONDS.labels(tier=tier or "unknown").observe(elapsed)
            _metrics.SCAN_ACTIVE.set(len(_active_scans))
        except Exception:
            pass
        # Always unlink the credentials file, even if the child crashed before
        # reading it. Keeps the on-disk lifetime bounded.
        if creds_path is not None:
            try:
                creds_path.unlink(missing_ok=True)
            except Exception:
                pass

    _active_scans[job_id]["finished_at"] = datetime.utcnow().isoformat()
    _persist_scan_state()

    # Flush the runtime scan-log to Postgres (scan_artifacts.kind='scan_log')
    # so the Execution Log tab has data even after the tempfile is cleaned up.
    try:
        _flush_scan_log_to_db(job_id)
    except Exception:
        pass

    # Update last_scanned on the target
    try:
        TargetRepo.update_last_scanned(target)
    except Exception:
        pass


# ── Helpers ─────────────────────────────────────────────────────────────────

def _get_scans() -> list:
    scans = []
    try:
        db_scans = ScanRepo.list_all()
        for s in db_scans:
            report = s.get("report_data") or {}
            vulns = report.get("vulnerabilities", [])
            if not vulns:
                vulns = VulnRepo.get_by_scan(s["scan_id"])
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            status_counts = {"CONFIRMED": 0, "REJECTED": 0, "UNCONFIRMED": 0}
            for v in vulns:
                sev = (v.get("severity") or "INFO").upper()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                st = (v.get("status") or "UNCONFIRMED").upper()
                status_counts[st] = status_counts.get(st, 0) + 1
            dur = s.get("duration_seconds") or 0
            if not dur and s.get("started_at") and s.get("finished_at"):
                try:
                    dur = (s["finished_at"] - s["started_at"]).total_seconds()
                except Exception:
                    dur = 0
            scans.append({
                "scan_id": s["scan_id"],
                "target": s.get("target", "unknown"),
                "timestamp": str(s.get("started_at", "")),
                "status": s.get("status", "unknown"),
                "duration_seconds": dur,
                "agents_used": s.get("agents_used", 0),
                "total_vulns": len(vulns),
                "severity_counts": severity_counts,
                "status_counts": status_counts,
            })
    except Exception:
        pass
    return scans


# ── Routes ──────────────────────────────────────────────────────────────────

@app.get("/api/targets")
def list_targets():
    targets = TargetRepo.list_all()
    scans = ScanRepo.list_all()
    for t in targets:
        url = t.get("url", "")
        matching = [s for s in scans if s.get("target", "") == url
                    or url.endswith(s.get("target", "\x00"))]
        t["scan_count"] = len(matching)
        t["added"] = str(t.get("added_at", "")) if t.get("added_at") else None
        if matching:
            latest = max(matching, key=lambda s: s.get("started_at") or "")
            t["last_scan"] = str(latest.get("started_at", ""))
        else:
            t["last_scan"] = None
    return targets


@app.post("/api/targets")
def add_target(body: TargetCreate):
    result = TargetRepo.add(body.url, body.scope, body.notes)
    if result.get("status") == "error":
        raise HTTPException(400, result["detail"])
    return result


@app.delete("/api/targets/{target_id}")
def delete_target(target_id: int):
    TargetRepo.delete(target_id)
    return {"status": "ok"}


@app.get("/api/scans")
def list_scans():
    return _get_scans()


@app.get("/api/scans/compare")
def compare_scans(a: str, b: str):
    return VulnRepo.compare_scans(a, b)


def _empty_live_results():
    return {
        "recon": {"subdomains": [], "endpoints": [], "technologies": {}, "ports": [], "ips": []},
        "vulnerabilities": [], "exploits": [], "captured_requests": [],
    }


def _live_singleton_scan_id() -> str:
    try:
        from core.database.pg_store import DatabaseManager
        import psycopg2.extras
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT scan_id FROM live_results WHERE id = 1")
                row = cur.fetchone()
                return (row or {}).get("scan_id") or ""
    except Exception:
        return ""


@app.get("/api/scans/live-progress")
def get_live_progress(scan_id: str = ""):
    try:
        data = LiveDataRepo.get_progress()
        if not data:
            return {}
        if scan_id:
            stored = _live_singleton_scan_id()
            if stored and stored != scan_id:
                return {}
        return data
    except Exception:
        return {}


@app.get("/api/scans/live-results")
def get_live_results(scan_id: str = ""):
    try:
        singleton_scan = _live_singleton_scan_id() if scan_id else ""
        if scan_id and singleton_scan and singleton_scan != scan_id:
            data = _empty_live_results()
        else:
            data = LiveDataRepo.get_results() or _empty_live_results()

        existing_titles = {(v.get("title") or "").strip().lower() for v in data.get("vulnerabilities", [])}

        if scan_id:
            try:
                db_vulns = VulnRepo.get_by_scan(scan_id)
                for v in (db_vulns or []):
                    vd = v if isinstance(v, dict) else (v.__dict__ if hasattr(v, '__dict__') else {})
                    t = (vd.get("title") or "").strip().lower()
                    if t and t not in existing_titles:
                        data.setdefault("vulnerabilities", []).append(vd)
                        existing_titles.add(t)
            except Exception:
                pass
        else:
            try:
                v2 = FindingV2Repo.list_confirmed()
                for f in v2:
                    t = (f.get("title") or "").strip().lower()
                    if t and t not in existing_titles:
                        data.setdefault("vulnerabilities", []).append(f)
                        existing_titles.add(t)
            except Exception:
                pass
            try:
                db_vulns = VulnRepo.get_all()
                for v in (db_vulns or []):
                    vd = v if isinstance(v, dict) else (v.__dict__ if hasattr(v, '__dict__') else {})
                    t = (vd.get("title") or "").strip().lower()
                    if t and t not in existing_titles:
                        data.setdefault("vulnerabilities", []).append(vd)
                        existing_titles.add(t)
            except Exception:
                pass
        return data
    except Exception:
        return _empty_live_results()


@app.get("/api/scans/active")
def list_active_scans():
    dirty = False
    for job in _active_scans.values():
        pid = job.get("pid")
        if pid and not _is_pid_alive(pid) and job["status"] in ("running", "starting", "stopping"):
            job["status"] = "stopped" if job["status"] == "stopping" else "completed"
            dirty = True
    # Auto-clean finished scans (completed/failed/cancelled) from active list
    finished = [jid for jid, j in _active_scans.items()
                if j["status"] in ("completed", "failed", "cancelled")]
    for jid in finished:
        del _active_scans[jid]
        dirty = True
    if dirty:
        _persist_scan_state()
    return list(_active_scans.values())


def _normalize_ports(ports) -> list:
    if not ports or not isinstance(ports, list):
        return []
    return [p for p in ports if isinstance(p, dict) and "port" in p and isinstance(p.get("port"), int)]


_TECH_NOISE = {
    "hsts", "application error", "not found", "page not found", "error",
    "via-proxy", "unix", "redirect", "unknown", "text/html", "text/plain",
    "utf-8", "gzip", "deflate", "chunked", "close", "keep-alive",
}

def _normalize_technologies(techs: dict) -> dict:
    if not techs or not isinstance(techs, dict):
        return {}
    merged = {}
    flat_techs = []
    for key, val in techs.items():
        if isinstance(val, list):
            host = key.replace("https://", "").replace("http://", "").rstrip("/").lower()
            existing = merged.get(host, [])
            existing.extend(val)
            merged[host] = existing
        elif val is True or isinstance(val, bool):
            name = key.strip()
            if name.lower() in _TECH_NOISE:
                continue
            if len(name) > 60:
                continue
            if any(sep in name for sep in (" — ", " - ", " :: ", " » ", " \xb7 ")):
                continue
            if name.startswith("text/") or name.startswith("application/"):
                continue
            flat_techs.append(name)
        elif isinstance(val, str):
            host = key.replace("https://", "").replace("http://", "").rstrip("/").lower()
            merged.setdefault(host, []).append(val)
    if flat_techs:
        merged.setdefault("target", []).extend(flat_techs)
    # Deduplicate each host's tech list
    for host in merged:
        merged[host] = sorted(set(merged[host]))
    return merged


def _enrich_subdomains(subs: list, status_map: dict) -> list:
    if not subs:
        return []
    status_map = status_map or {}
    out = []
    seen = set()
    for s in subs:
        if isinstance(s, dict):
            name = s.get("name") or s.get("host") or ""
            inline_live = s.get("live")
            inline_status = s.get("status")
            inline_code = s.get("status_code", 0)
            inline_note = s.get("note", "")
        else:
            name = str(s)
            inline_live = None
            inline_status = None
            inline_code = 0
            inline_note = ""
        host = str(name).replace("https://", "").replace("http://", "").rstrip("/").lower()
        if not host or host in seen:
            continue
        seen.add(host)
        st = status_map.get(host, {})
        # Prefer inline fields (from _classify_subdomains) over status_map fallback.
        is_live = inline_live if inline_live is not None else bool(st.get("live"))
        status = inline_status or ("live" if is_live else ("dead" if st else "unknown"))
        code = inline_code or st.get("status_code", 0)
        out.append({
            "name": host,
            "live": bool(is_live),
            "status": status,
            "status_code": code,
            "note": inline_note,
        })
    return out


def _split_captured_requests(raw: list, scan_id: str) -> dict:
    http_requests = []
    tool_executions = []

    # 1. Try DB first
    try:
        from core.database.pg_store import CapturedRequestRepo, ToolExecutionRepo, ToolOutputRepo
        db_http = CapturedRequestRepo.list_by_scan(scan_id)
        db_tools = ToolExecutionRepo.list_by_scan(scan_id)
        if db_http:
            http_requests = db_http
        if db_tools:
            tool_executions = db_tools
        # Enrich tool_executions with actual stdout size from tool_outputs
        if tool_executions:
            try:
                tool_outputs = ToolOutputRepo.list_by_scan(scan_id)
                output_by_cmd = {}
                for to in tool_outputs:
                    key = (to.get("tool_name", ""), (to.get("command", "") or "")[:200])
                    output_by_cmd[key] = {
                        "stdout_bytes": len(to.get("stdout", "") or ""),
                        "exit_code": to.get("exit_code", -1),
                        "duration_s": to.get("duration_s", 0),
                    }
                for te in tool_executions:
                    key = (te.get("tool", ""), (te.get("command", "") or "")[:200])
                    match = output_by_cmd.get(key)
                    if match:
                        te["stdout_bytes"] = match["stdout_bytes"]
                        te["exit_code"] = match["exit_code"]
                        if match["duration_s"]:
                            te["duration_s"] = match["duration_s"]
            except Exception:
                pass
    except Exception:
        pass

    # DB is the sole data source — no file-based fallbacks

    return {"http_requests": http_requests, "tool_executions": tool_executions}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = ScanRepo.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    vulns = VulnRepo.get_by_scan(scan_id)
    # Fallback: if no vulns in DB, check live_results (singleton) for this scan
    if not vulns:
        try:
            from core.database.pg_store import DatabaseManager as DM
            live_scan = None
            with DM.get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT scan_id FROM live_results WHERE id = 1")
                row = cur.fetchone()
                if row:
                    live_scan = row[0]
            if live_scan == scan_id:
                live = LiveDataRepo.get_results()
                if live.get("vulnerabilities"):
                    vulns = live["vulnerabilities"]
        except Exception:
            pass
    report = scan.get("report_data") or {}
    meta = report.get("metadata", {"target": scan.get("target", ""), "timestamp": str(scan.get("started_at", ""))})
    # Enrich metadata with scan-table fields the frontend needs
    dur = scan.get("duration_seconds") or 0
    if not dur and scan.get("started_at") and scan.get("finished_at"):
        try:
            dur = (scan["finished_at"] - scan["started_at"]).total_seconds()
        except Exception:
            dur = 0
    meta["duration_seconds"] = dur
    meta["agents_used"] = scan.get("agents_used") or 0
    meta["status"] = scan.get("status", "unknown")
    meta["started_at"] = str(scan.get("started_at", ""))
    meta["finished_at"] = str(scan.get("finished_at", ""))
    scope = report.get("scope", {})
    # Recon intelligence: prefer the dedicated recon_data table (written live during
    # recon), fall back to the report's embedded context.
    context = report.get("context", {})
    try:
        from core.database.pg_store import ReconRepo
        recon = ReconRepo.get(scan_id)
        if recon:
            context = recon
    except Exception:
        pass
    # Enrich DB vulns with rich report data (critic, compliance, evidence, screenshots)
    # Collect rich vulns from all sources — report_data, context, live_results, context file
    report_vulns = list(report.get("vulnerabilities", []))
    # Merge from context's vulnerabilities
    ctx_vulns = context.get("vulnerabilities", [])
    for cv in ctx_vulns:
        t = (cv.get("title") or "").strip().lower()
        if t and t not in {(rv.get("title") or "").strip().lower() for rv in report_vulns}:
            report_vulns.append(cv)
    # All vulnerability data comes from DB only — no .json/.log file reads
    # Build index by title for matching
    rich_by_title = {}
    for rv in report_vulns:
        t = (rv.get("title") or "").strip().lower()
        if t:
            rich_by_title[t] = rv
    RICH_FIELDS = ["critic", "critic_flag", "_compliance", "evidence", "llm_validation",
                   "screenshot_path", "curl_command", "original_severity", "severity_adjusted_by",
                   "source", "reproducibility_status", "retest_attempts", "retest_successes",
                   "_confidence", "_dedup"]
    for v in vulns:
        title_key = (v.get("title") or "").strip().lower()
        rich = rich_by_title.get(title_key)
        if rich:
            for field in RICH_FIELDS:
                if field in rich and field not in v:
                    v[field] = rich[field]
    # If DB has fewer vulns than report, add the extras from report
    db_titles = {(v.get("title") or "").strip().lower() for v in vulns}
    for rv in report_vulns:
        t = (rv.get("title") or "").strip().lower()
        if t and t not in db_titles:
            vulns.append(rv)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in vulns:
        sev = (v.get("severity") or "INFO").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    passed = sum(1 for v in vulns if v.get("status") == "CONFIRMED")
    failed = sum(1 for v in vulns if v.get("status") == "REJECTED")
    unconfirmed = len(vulns) - passed - failed
    return {
        "scan_id": scan_id, "metadata": meta, "scope": scope,
        "executive_summary": report.get("executive_summary", ""),
        "vulnerabilities": vulns, "severity_counts": severity_counts,
        "test_results": {"passed": passed, "failed": failed, "unconfirmed": unconfirmed},
        "context": {
            "subdomains": _enrich_subdomains(context.get("subdomains", []),
                                             context.get("subdomain_status", {})),
            "technologies": _normalize_technologies(context.get("technologies", {})),
            "endpoints": context.get("endpoints", []),
            "captured_requests": _split_captured_requests(context.get("captured_requests", []), scan_id),
            "subdomain_summary": context.get("subdomain_summary", {}),
            "osint": context.get("osint", {}),
            "ports": _normalize_ports(context.get("ports", [])),
            "ips": context.get("ips", []),
            "ssl_info": context.get("ssl_info", {}),
            "headers": context.get("headers", {}),
            "directories": context.get("directories", []),
            "secrets": context.get("secrets", []),
            "dns_records": context.get("dns_records", []),
            "tool_results": context.get("tool_results", {}),
            "tool_executions": context.get("tool_executions", []),
        },
        "exploits": _get_exploits(scan_id, report),
        "checkpoints": [],
    }


def _get_exploits(scan_id: str, report: dict) -> list:
    try:
        db_exploits = ExploitResultRepo.get_by_scan(scan_id)
        if db_exploits:
            return db_exploits
    except Exception:
        pass
    return report.get("exploit_results", [])


@app.get("/api/scans/{scan_id}/recon")
def get_recon(scan_id: str):
    try:
        from core.database.pg_store import ReconRepo
        recon = ReconRepo.get(scan_id) or {}
        if not recon:
            return {}
        # Shape identically to /api/scans/{scan_id}.context so callers can rely on
        # a single format regardless of which endpoint they hit.
        recon["subdomains"] = _enrich_subdomains(recon.get("subdomains", []),
                                                  recon.get("subdomain_status", {}))
        recon["technologies"] = _normalize_technologies(recon.get("technologies", {}))
        recon["ports"] = _normalize_ports(recon.get("ports", []))
        return recon
    except Exception as e:
        raise HTTPException(500, f"recon data unavailable: {e}")


# ── LLM COST (Phase 6.1) ──────────────────────────────────────────────────
@app.get("/api/scans/{scan_id}/cost")
def get_scan_cost(scan_id: str):
    """Per-scan LLM spend breakdown. Reads the in-process cost log, falling back
    to the llm_cost_log table when the scan ran in another process."""
    try:
        from core.economics.cost_log import get_cost_log
        breakdown = get_cost_log().get_cost_breakdown(scan_id)
        if breakdown.get("requests"):
            return breakdown
        # Fallback: aggregate from the DB table if the log is empty here.
        try:
            from core.memory.database import DatabaseManager
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT provider, model, SUM(input_tokens), SUM(output_tokens), "
                        "SUM(cost_usd), COUNT(*) FROM llm_cost_log WHERE scan_id=%s "
                        "GROUP BY provider, model", (scan_id,))
                    rows = cur.fetchall()
            by_model, total = {}, 0.0
            for prov, model, itok, otok, cost, cnt in rows:
                by_model[f"{prov}/{model}"] = {"requests": cnt, "input_tokens": itok,
                                               "output_tokens": otok, "cost_usd": float(cost or 0)}
                total += float(cost or 0)
            return {"scan_id": scan_id, "total_cost_usd": round(total, 6),
                    "requests": sum(v["requests"] for v in by_model.values()),
                    "by_model": by_model}
        except Exception:
            return breakdown  # empty but well-formed
    except Exception as e:
        raise HTTPException(500, f"cost data unavailable: {e}")


# ── LIVE CHAIN-OF-THOUGHT — per-agent reasoning stream ────────────────────
@app.get("/api/scans/{scan_id}/agents/reasoning")
def list_agent_reasoning(scan_id: str, agent_id: str = "", limit: int = 100):
    try:
        from core.database.pg_store import DatabaseManager
        import psycopg2.extras
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if agent_id:
                    cur.execute("""
                        SELECT * FROM agent_reasoning WHERE scan_id=%s AND agent_id=%s
                        ORDER BY created_at DESC LIMIT %s
                    """, (scan_id, agent_id, limit))
                else:
                    cur.execute("""
                        SELECT * FROM agent_reasoning WHERE scan_id=%s
                        ORDER BY created_at DESC LIMIT %s
                    """, (scan_id, limit))
                rows = [dict(r) for r in cur.fetchall()]
                for r in rows:
                    if r.get("created_at") and not isinstance(r["created_at"], str):
                        r["created_at"] = r["created_at"].isoformat()
        return {"scan_id": scan_id, "count": len(rows), "reasoning": rows}
    except Exception as e:
        raise HTTPException(500, f"reasoning unavailable: {e}")


# ── ATTACK CHAINS — LLM-synthesised exploitation paths ────────────────────
@app.get("/api/scans/{scan_id}/attack-chains")
def get_attack_chains(scan_id: str):
    try:
        from core.database.pg_store import AttackChainRepo
        chains = AttackChainRepo.get_by_scan(scan_id) if hasattr(AttackChainRepo, "get_by_scan") else []
        return {"scan_id": scan_id, "count": len(chains), "chains": chains}
    except Exception as e:
        raise HTTPException(500, f"attack chains unavailable: {e}")


@app.post("/api/scans/{scan_id}/attack-chains/regenerate")
async def regenerate_attack_chains(scan_id: str):
    from core.reporting.chain_intelligence import synthesize_chains
    try:
        chains = await synthesize_chains(scan_id)
        return {"scan_id": scan_id, "count": len(chains), "chains": chains}
    except Exception as e:
        raise HTTPException(500, f"regenerate failed: {e}")


# ── SCAN DIFF — new / resolved / regressed vs a baseline scan ─────────────
@app.get("/api/scans/{scan_id}/diff/{baseline_scan_id}")
def diff_scans(scan_id: str, baseline_scan_id: str):
    from core.reporting.scan_diff import compare_scans
    try:
        return compare_scans(baseline_scan_id, scan_id)
    except Exception as e:
        raise HTTPException(500, f"diff failed: {e}")


# ── REPRO BUNDLES — regenerate on demand ──────────────────────────────────
@app.post("/api/scans/{scan_id}/repro-bundles/regenerate")
def regenerate_repro_bundles(scan_id: str, min_severity: str = "HIGH"):
    from core.reporting.repro_bundle import generate_bundles_for_scan
    try:
        return generate_bundles_for_scan(scan_id, min_severity=min_severity)
    except Exception as e:
        raise HTTPException(500, f"bundle generation failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# NEW ANALYSIS SURFACES (Phases 2/3/5/6 backend → UI)
# ═══════════════════════════════════════════════════════════════════════════

def _scan_vulns(scan_id: str) -> list:
    """Best-effort fetch of a scan's findings; [] if the DB is unavailable."""
    try:
        return VulnRepo.get_by_scan(scan_id) or []
    except Exception as e:
        logger.debug("scan vulns unavailable for %s: %s", scan_id, e)
        return []


def _scan_meta(scan_id: str) -> dict:
    try:
        return (ScanRepo.get(scan_id) or {}) if hasattr(ScanRepo, "get") else {}
    except Exception:
        return {}


# ── Executive risk in dollars (Phase 5.3) ──────────────────────────────────
@app.get("/api/scans/{scan_id}/risk")
def get_scan_risk(scan_id: str):
    try:
        from core.reporting.risk_calculator import RiskCalculator, RiskContext
        vulns = _scan_vulns(scan_id)
        meta = _scan_meta(scan_id)
        ctx = RiskContext(
            industry=str(meta.get("industry", "generic") or "generic"),
            regulations=list(meta.get("regulations", []) or []),
        )
        history = meta.get("risk_history", []) or []
        return RiskCalculator().to_dashboard_dict(vulns, ctx, historical_totals=history)
    except Exception as e:
        raise HTTPException(500, f"risk unavailable: {e}")


# ── Chain analysis: re-scoring + narratives + end-to-end CVSS (Phase 2.1) ───
@app.get("/api/scans/{scan_id}/chain-analysis")
def get_chain_analysis(scan_id: str):
    try:
        from core.exploitation.chain_builder import ChainBuilder
        return ChainBuilder().synthesize(_scan_vulns(scan_id))
    except Exception as e:
        raise HTTPException(500, f"chain analysis unavailable: {e}")


# ── Regression tracking (Phase 3.3) ────────────────────────────────────────
@app.get("/api/scans/{scan_id}/regression")
def get_scan_regression(scan_id: str):
    try:
        from core.monitoring.regression_detector import RegressionDetector
        det = RegressionDetector(store_path=f"data/regression/{scan_id}.json")
        det.load()
        return det.summary()
    except Exception as e:
        raise HTTPException(500, f"regression data unavailable: {e}")


# ── AI-generated fix code per finding (Phase 5.2) ───────────────────────────
@app.get("/api/scans/{scan_id}/fix-suggestions")
def get_fix_suggestions(scan_id: str):
    try:
        from core.reporting.fix_generator import FixGenerator, detect_stack
        vulns = _scan_vulns(scan_id)
        meta = _scan_meta(scan_id)
        stack = detect_stack(headers=meta.get("response_headers", {}) or {},
                             body=str(meta.get("error_sample", "") or ""))
        gen = FixGenerator()
        out = []
        for v in vulns:
            fix = gen.generate_fix(v, stack)
            if fix.get("fix_code"):
                out.append({"finding": v.get("title") or v.get("type"),
                            "severity": v.get("severity"), **fix})
        return {"scan_id": scan_id, "stack": {"language": stack.language, "framework": stack.framework},
                "count": len(out), "fixes": out}
    except Exception as e:
        raise HTTPException(500, f"fix suggestions unavailable: {e}")


# ── Attack recordings / narratives (Phase 5.1) ──────────────────────────────
@app.get("/api/scans/{scan_id}/attack-recordings")
def get_attack_recordings(scan_id: str):
    """Recorded exploit narratives + evidence. Sources persisted recordings when
    present; otherwise builds narratives from confirmed high/critical findings."""
    try:
        from core.reporting.attack_recorder import AttackRecorder
        vulns = [v for v in _scan_vulns(scan_id)
                 if str(v.get("severity", "")).lower() in ("critical", "high")
                 and str(v.get("status", "")).upper() == "CONFIRMED"]
        recordings = []
        for v in vulns[:25]:
            rec = AttackRecorder(v.get("id") or v.get("title", "finding"),
                                 v.get("title") or v.get("type", "finding"),
                                 severity=str(v.get("severity", "high")).lower())
            if v.get("location") or v.get("target"):
                rec.add_step("Navigate to", v.get("location") or v.get("target", ""))
            if v.get("proof"):
                rec.add_step("Exploit", v.get("location") or v.get("target", ""),
                             note=str(v.get("proof"))[:160])
            recordings.append(rec.build().to_dict())
        return {"scan_id": scan_id, "count": len(recordings), "recordings": recordings}
    except Exception as e:
        raise HTTPException(500, f"attack recordings unavailable: {e}")


# ── Attack-surface diff vs a baseline (Phases 3.1 / 6.2) ────────────────────
@app.get("/api/scans/{scan_id}/surface-diff")
def get_surface_diff(scan_id: str, target: str = ""):
    try:
        from core.monitoring.surface_baseline import SurfaceBaseline
        meta = _scan_meta(scan_id)
        tgt = target or str(meta.get("target", "") or "")
        bl = SurfaceBaseline()
        baseline = bl.load_latest(tgt) if tgt else None
        if baseline is None:
            return {"scan_id": scan_id, "target": tgt, "has_baseline": False,
                    "diff": None, "message": "No stored baseline for this target yet."}
        current = bl.snapshot(meta, target=tgt)
        return {"scan_id": scan_id, "target": tgt, "has_baseline": True,
                "diff": bl.diff(baseline, current)}
    except Exception as e:
        raise HTTPException(500, f"surface diff unavailable: {e}")


# ── Benchmark catalog / scores (Phase 11) ───────────────────────────────────
@app.get("/api/benchmarks")
def get_benchmarks():
    try:
        from tests.benchmarks.juice_shop_benchmark import JUICE_SHOP_CHALLENGES, categories
        from tests.benchmarks.dvwa_benchmark import DVWA_CASES, SECURITY_LEVELS
        from tests.benchmarks.token_benchmark import TOKEN_BUDGET_LIMIT
        return {
            "juice_shop": {
                "total": len(JUICE_SHOP_CHALLENGES),
                "categories": sorted(categories()),
                "challenges": [{"id": c.id, "name": c.name, "category": c.category,
                                "difficulty": c.difficulty, "executor": c.executor}
                               for c in JUICE_SHOP_CHALLENGES],
            },
            "dvwa": {"cases": len(DVWA_CASES), "levels": list(SECURITY_LEVELS)},
            "token_budget_limit": TOKEN_BUDGET_LIMIT,
        }
    except Exception as e:
        raise HTTPException(500, f"benchmarks unavailable: {e}")


# ── Grey-box SAST↔DAST correlation (Phase 4.5) ──────────────────────────────
@app.get("/api/scans/{scan_id}/sast-correlation")
def get_sast_correlation(scan_id: str):
    try:
        from core.analysis.sast_bridge import load_correlation
        data = load_correlation(scan_id)
        if data is None:
            return {"scan_id": scan_id, "available": False,
                    "counts": {"confirmed": 0, "sast_only": 0, "dast_only": 0},
                    "confirmed": [], "sast_only": [], "dast_only": [],
                    "message": "No SAST run for this scan (use --source-repo / --source-path)."}
        return {"available": True, **data}
    except Exception as e:
        raise HTTPException(500, f"sast correlation unavailable: {e}")


# ── Standalone (individual) analysis — APK/IPA or source, no scan/target ─────
class AnalyzeMobileRequest(BaseModel):
    path: str = Field(..., max_length=1024)


class AnalyzeSourceRequest(BaseModel):
    source_repo: str = Field(default="", max_length=2048)
    source_path: str = Field(default="", max_length=1024)


@app.post("/api/analyze/mobile")
async def analyze_mobile_endpoint(body: AnalyzeMobileRequest):
    """Analyze a previously-uploaded APK/IPA on its own (no scan). `path` must be
    a file produced by /api/uploads/scan-input (restricted to data/uploads)."""
    from core.analysis.standalone_analysis import analyze_mobile
    uploads = (BASE / "data" / "uploads").resolve()
    p = Path(body.path).resolve()
    if p.parent != uploads:
        raise HTTPException(400, "path must be an uploaded file under data/uploads")
    if not p.exists():
        raise HTTPException(404, "uploaded file not found")
    try:
        return await asyncio.to_thread(analyze_mobile, str(p))
    except Exception as e:
        raise HTTPException(500, f"mobile analysis failed: {e}")


@app.post("/api/analyze/source")
async def analyze_source_endpoint(body: AnalyzeSourceRequest):
    """Run grey-box SAST on a repo URL / server path on its own (no scan)."""
    from core.analysis.standalone_analysis import analyze_source
    if not (body.source_repo or body.source_path):
        raise HTTPException(400, "provide source_repo or source_path")
    try:
        return await asyncio.to_thread(analyze_source, body.source_repo, body.source_path)
    except Exception as e:
        raise HTTPException(500, f"source analysis failed: {e}")


# ── SCAN CHATBOT — LLM Q&A over this scan's collected data ─────────────────
class ScanChatMessage(BaseModel):
    message: str
    history: list = []


@app.post("/api/scans/{scan_id}/chat")
async def scan_chat(scan_id: str, body: ScanChatMessage):
    from core.reporting.scan_chatbot import answer_question
    try:
        result = await answer_question(scan_id, body.message, history=body.history)
        return result
    except Exception as e:
        raise HTTPException(500, f"chat failed: {e}")


# ── BACKFILL — reflush live_results + report_data into vulnerabilities table ─
@app.post("/api/scans/{scan_id}/backfill")
def backfill_scan_findings(scan_id: str):
    try:
        from core.database.pg_store import (LiveDataRepo, VulnRepo, ReconRepo,
            DatabaseManager, AuthBypassRepo)
        import psycopg2.extras
        # Collect vulns from every source
        vulns_all: list = []
        seen_titles = set()
        def _add(vs):
            n = 0
            for v in (vs or []):
                if not isinstance(v, dict):
                    continue
                key = ((v.get("title") or "").strip().lower(),
                        (v.get("location") or v.get("target") or "").strip().lower())
                if key in seen_titles:
                    continue
                seen_titles.add(key)
                vulns_all.append(v)
                n += 1
            return n
        # Live results (holds the current run's raw finding stream if this
        # scan is the active singleton)
        live_added = 0
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("SELECT scan_id, data FROM live_results WHERE id = 1")
                    r = cur.fetchone()
                    if r and r.get("scan_id") == scan_id and isinstance(r.get("data"), dict):
                        live_added = _add(r["data"].get("vulnerabilities", []))
        except Exception:
            pass
        # report_data.vulnerabilities (finalised scans)
        report_added = 0
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("SELECT report_data FROM scans WHERE scan_id = %s", (scan_id,))
                    r = cur.fetchone()
                    if r and isinstance(r.get("report_data"), dict):
                        report_added = _add(r["report_data"].get("vulnerabilities", []))
        except Exception:
            pass
        # recon_data.vulnerabilities (sometimes populated by mixins)
        recon_added = 0
        try:
            recon = ReconRepo.get(scan_id) or {}
            recon_added = _add(recon.get("vulnerabilities", []))
        except Exception:
            pass
        # Persist under the new relaxed finding_uid
        before = len(VulnRepo.get_by_scan(scan_id) or [])
        VulnRepo.bulk_insert(scan_id, vulns_all)
        after = len(VulnRepo.get_by_scan(scan_id) or [])
        # Extract structured credentials from every finding's evidence
        from core.exploitation.dump_extractor import extract_from_all_findings
        creds_added = extract_from_all_findings(scan_id, vulns_all, ctx=None)
        auth_count = AuthBypassRepo.count_by_scan(scan_id)
        return {
            "scan_id": scan_id,
            "sources": {"live_results": live_added, "report_data": report_added,
                        "recon_data": recon_added},
            "vulns_considered": len(vulns_all),
            "vulns_before": before, "vulns_after": after,
            "vulns_added": after - before,
            "credentials_extracted": creds_added,
            "auth_bypass_rows": auth_count,
        }
    except Exception as e:
        raise HTTPException(500, f"backfill failed: {e}")


# ── LIVE AGENTS — per-agent card view of parallel work in progress ─────────
@app.get("/api/scans/{scan_id}/agents/live")
def list_live_agents(scan_id: str):
    try:
        rows = LiveAgentRepo.list_by_scan(scan_id) or []
        counts = LiveAgentRepo.counts_by_scan(scan_id) or {}
        # Convert timestamps to ISO strings for JSON safety
        for r in rows:
            for k in ("started_at", "finished_at", "updated_at"):
                v = r.get(k)
                if v is not None and not isinstance(v, str):
                    r[k] = v.isoformat()
        return {"scan_id": scan_id, "count": len(rows),
                "counts_by_status": counts, "agents": rows}
    except Exception as e:
        raise HTTPException(500, f"live agents unavailable: {e}")


# ── AUTH BYPASSES / "Access Gained" (SQLi bypass, mass-assign, cred replay) ──
@app.get("/api/scans/{scan_id}/auth-bypasses")
def list_auth_bypasses(scan_id: str):
    try:
        rows = AuthBypassRepo.get_by_scan(scan_id) or []
        # Never return the raw token in full to the browser — only preview.
        for r in rows:
            tok = r.get("token") or ""
            if tok:
                r["token_preview"] = tok[:24] + ("…" if len(tok) > 24 else "")
                r["token_len"] = len(tok)
                r["token"] = tok[:120] + ("…[truncated]" if len(tok) > 120 else "")
        return {"scan_id": scan_id, "count": len(rows), "bypasses": rows}
    except Exception as e:
        raise HTTPException(500, f"auth-bypasses unavailable: {e}")


# ── SCAN ARTIFACTS (PoC, screenshots, SARIF, nuclei templates, canonical) ──
@app.get("/api/scans/{scan_id}/artifacts")
def list_scan_artifacts(scan_id: str, kind: str = ""):
    try:
        rows = ScanArtifactRepo.list_by_scan(scan_id, kind=kind or None)
        # Strip binary; the content endpoint serves it
        return {"scan_id": scan_id, "count": len(rows),
                "counts_by_kind": ScanArtifactRepo.counts_by_kind(scan_id),
                "artifacts": rows}
    except Exception as e:
        raise HTTPException(500, f"artifacts unavailable: {e}")


@app.get("/api/scans/{scan_id}/artifacts/{artifact_id}")
def get_scan_artifact(scan_id: str, artifact_id: int, download: bool = False):
    from fastapi.responses import Response
    try:
        row = ScanArtifactRepo.get(artifact_id)
        if not row or row.get("scan_id") != scan_id:
            raise HTTPException(404, "artifact not found")
        mime = row.get("mime_type") or "application/octet-stream"
        content = row.get("content") or b""
        headers = {}
        if download:
            headers["Content-Disposition"] = f'attachment; filename="{row.get("name", "artifact.bin")}"'
        return Response(content=content, media_type=mime, headers=headers)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"artifact unavailable: {e}")


@app.get("/api/scans/{scan_id}/pocs")
def get_scan_pocs(scan_id: str):
    try:
        rows = ScanArtifactRepo.list_by_scan(scan_id)
        pocs = {}
        for r in rows:
            if not str(r.get("kind", "")).startswith("poc_"):
                continue
            full = ScanArtifactRepo.get(r["id"])
            if not full:
                continue
            try:
                text = (full.get("content") or b"").decode("utf-8", errors="replace")
            except Exception:
                text = ""
            pocs[r["kind"]] = {
                "id": r["id"], "name": r.get("name", ""),
                "mime_type": r.get("mime_type", "text/plain"),
                "size_bytes": r.get("size_bytes", 0),
                "content": text,
            }
        return {"scan_id": scan_id, "pocs": pocs}
    except Exception as e:
        raise HTTPException(500, f"pocs unavailable: {e}")


@app.get("/api/scans/{scan_id}/screenshots")
def list_scan_screenshots(scan_id: str):
    try:
        rows = ScanArtifactRepo.list_by_scan(scan_id, kind="screenshot")
        return {"scan_id": scan_id, "count": len(rows), "screenshots": rows}
    except Exception as e:
        raise HTTPException(500, f"screenshots unavailable: {e}")


@app.get("/api/scans/{scan_id}/tool-outputs")
def get_tool_outputs(scan_id: str, grouped: bool = False):
    try:
        from core.database.pg_store import ToolOutputRepo
        rows = ToolOutputRepo.list_by_scan(scan_id)
        for r in rows:
            if "created_at" in r:
                r["created_at"] = str(r["created_at"])
        if not grouped:
            return rows
        by_tool = {}
        for r in rows:
            tool = r.get("tool_name", "unknown")
            raw_target = r.get("target", "")
            target = raw_target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].rstrip("/").lower()
            if not target:
                target = raw_target
            if tool not in by_tool:
                by_tool[tool] = {"tool": tool, "targets": {}}
            if target not in by_tool[tool]["targets"]:
                by_tool[tool]["targets"][target] = []
            by_tool[tool]["targets"][target].append({
                "command": r.get("command", ""),
                "stdout": r.get("stdout", ""),
                "exit_code": r.get("exit_code", -1),
                "operation": r.get("operation", ""),
                "created_at": r.get("created_at", ""),
            })
        return list(by_tool.values())
    except Exception as e:
        raise HTTPException(500, f"tool outputs unavailable: {e}")


@app.get("/api/scans/{scan_id}/vulnerabilities")
def get_vulnerabilities(scan_id: str):
    return VulnRepo.get_by_scan(scan_id)


@app.get("/api/scans/{scan_id}/activity")
def get_activity_log(scan_id: str, limit: int = 500):
    try:
        from core.reporting.agent_activity import get_activity_log
        return get_activity_log().get(scan_id, limit)
    except Exception as e:
        raise HTTPException(500, f"activity log unavailable: {e}")


# ── Human review queue: agent successes to showcase + failures to pentest manually ──

def _review_queue():
    from core.reporting.review_queue import get_review_queue
    return get_review_queue()


@app.get("/api/review-queue")
def review_queue_all(limit: int = 200):
    q = _review_queue()
    return {"summary": q.summary(), "items": q.all(limit)}


@app.get("/api/review-queue/successes")
def review_queue_successes(limit: int = 200):
    return {"items": _review_queue().successes(limit)}


@app.get("/api/review-queue/manual")
def review_queue_manual(limit: int = 200):
    return {"items": _review_queue().manual_followups(limit)}


class ReviewResolve(BaseModel):
    note: str = ""


@app.post("/api/review-queue/{record_id}/resolve")
def review_queue_resolve(record_id: str, body: ReviewResolve):
    ok = _review_queue().resolve(record_id, note=body.note)
    if not ok:
        raise HTTPException(status_code=404, detail="review record not found")
    return {"status": "resolved", "id": record_id}


@app.get("/api/audit-trail")
def get_audit_trail():
    try:
        return AuditRepo.get_recent(limit=500)
    except Exception:
        return []


@app.get("/api/execution-log")
def get_execution_log():
    try:
        return AuditRepo.get_execution_log(limit=500)
    except Exception:
        return []


@app.get("/api/poc")
def get_poc():
    results = {}
    for ext in ["py", "sh"]:
        path = REPORTS_DIR / f"poc_reproduce.{ext}"
        if path.exists():
            results[ext] = path.read_text(encoding="utf-8", errors="replace")
    summary = REPORTS_DIR / "poc_summary.md"
    if summary.exists():
        results["summary"] = summary.read_text(encoding="utf-8", errors="replace")
    return results


@app.get("/api/stats")
def get_stats():
    scans = _get_scans()
    total_vulns = sum(s["total_vulns"] for s in scans)
    total_critical = sum(s["severity_counts"].get("CRITICAL", 0) for s in scans)
    total_high = sum(s["severity_counts"].get("HIGH", 0) for s in scans)
    total_medium = sum(s["severity_counts"].get("MEDIUM", 0) for s in scans)
    total_low = sum(s["severity_counts"].get("LOW", 0) for s in scans)
    total_info = sum(s["severity_counts"].get("INFO", 0) for s in scans)
    targets = set(s["target"] for s in scans)
    confirmed = sum(s.get("status_counts", {}).get("CONFIRMED", 0) for s in scans)
    rejected = sum(s.get("status_counts", {}).get("REJECTED", 0) for s in scans)
    durations = [s.get("duration_seconds", 0) for s in scans if s.get("duration_seconds")]
    avg_duration = sum(durations) / len(durations) if durations else 0
    last_scan = max((s.get("timestamp", "") for s in scans), default="") if scans else ""
    return {
        "total_scans": len(scans),
        "total_vulns": total_vulns,
        "total_vulnerabilities": total_vulns,
        "critical_count": total_critical,
        "total_critical": total_critical,
        "high_count": total_high,
        "total_high": total_high,
        "medium_count": total_medium,
        "total_medium": total_medium,
        "low_count": total_low,
        "total_low": total_low,
        "info_count": total_info,
        "total_info": total_info,
        "confirmed_count": confirmed,
        "rejected_count": rejected,
        "unique_targets": len(targets),
        "targets": list(targets),
        "avg_duration": round(avg_duration, 1),
        "last_scan": last_scan,
    }


@app.get("/api/scans/{scan_id}/report")
def download_report(scan_id: str):
    scan = ScanRepo.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    report = scan.get("report_data") or {}
    if not report:
        vulns = VulnRepo.get_by_scan(scan_id)
        report = {
            "metadata": {"target": scan.get("target", ""), "timestamp": str(scan.get("started_at", ""))},
            "vulnerabilities": vulns,
        }
    return report


@app.post("/api/scans/run")
def run_scan(body: ScanRequest):
    # Check not already scanning this target
    for job in _active_scans.values():
        if job["target"] == body.target and job["status"] == "running":
            raise HTTPException(409, f"Scan already running for {body.target}")

    job_id = make_run_id(body.target)
    _active_scans[job_id] = {
        "job_id": job_id,
        "target": body.target,
        "tier": body.tier,
        "status": "starting",
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
        "pid": None,
        "exit_code": None,
        "error": None,
        "log_file": str(_scan_log_path(job_id)),
    }

    _active_scans[job_id]["phases"] = body.phases or ["RECON", "ACTIVE_SCANNING", "EXPLOITATION", "REPORTING"]
    try:
        ScanRepo.create(job_id, body.target, body.tier,
                        log_file=str(_scan_log_path(job_id)))
    except Exception:
        pass
    _persist_scan_state()

    t = threading.Thread(
        target=_run_scan_process,
        args=(job_id, body.target, body.tier,
              body.auto_approve, body.skip_osint, body.reset_dedup),
        kwargs={"phases": body.phases if body.phases else None,
                "credentials": body.credentials if body.credentials else None,
                "allow_shell_operators": body.allow_shell_operators,
                "allow_ambient_auth": body.allow_ambient_auth,
                "mobile_app": body.mobile_app, "ipa_app": body.ipa_app,
                "source_repo": body.source_repo, "source_path": body.source_path},
        daemon=True,
    )
    t.start()
    return {"job_id": job_id, "status": "started"}


@app.get("/api/scans/job/{job_id}")
def get_scan_job(job_id: str):
    if job_id in _active_scans:
        return _active_scans[job_id]
    raise HTTPException(404, "Job not found")


def _resolve_log_file(job_id: str) -> Path:
    if job_id in _active_scans:
        raw = _active_scans[job_id].get("log_file", "")
        if raw:
            return Path(raw)
    default = _scan_log_path(job_id)
    if default.is_file():
        return default
    try:
        row = ScanRepo.get(job_id)
        if row and row.get("log_file"):
            p = Path(row["log_file"])
            if p.is_file():
                return p
    except Exception:
        pass
    return default


@app.get("/api/scans/job/{job_id}/logs")
def get_scan_logs(job_id: str, tail: int = 100):
    try:
        raw = _read_scan_log(job_id)
        if not raw:
            return {"lines": [], "total": 0}
        text = raw.decode("utf-8", errors="replace")
        all_lines = text.splitlines()
        return {"lines": all_lines[-tail:], "total": len(all_lines)}
    except Exception as e:
        import traceback
        logger.error(f"get_scan_logs error: {traceback.format_exc()}")
        return {"lines": [f"Error reading logs: {e}"], "total": 0}


@app.post("/api/scans/job/{job_id}/stop")
def stop_scan(job_id: str):
    target = None

    if job_id in _active_scans:
        job = _active_scans[job_id]
        if job["status"] != "running":
            raise HTTPException(400, f"Scan is not running (status={job['status']})")
        target = job["target"]
        job["status"] = "stopping"
        _persist_scan_state()
    else:
        raise HTTPException(404, "Job not found")

    slug = target.replace("://", "_").replace("/", "_").replace(":", "_")
    stop_file = BASE / ".antigravity" / f"stop_{slug}.signal"
    stop_file.parent.mkdir(parents=True, exist_ok=True)
    stop_file.touch()
    return {"status": "stop_requested", "job_id": job_id}


@app.post("/api/scans/job/{job_id}/cancel")
def cancel_scan(job_id: str):
    if job_id in _active_scans:
        job = _active_scans[job_id]
        target = job.get("target", "")
        pid = job.get("pid")
        # Kill the subprocess if still alive so it stops writing to the log tempfile
        if pid and _is_pid_alive(pid):
            try:
                import signal
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
            # Give it a moment to exit cleanly
            import time as _t
            for _ in range(20):
                if not _is_pid_alive(pid):
                    break
                _t.sleep(0.1)
            if _is_pid_alive(pid):
                try:
                    os.kill(pid, signal.SIGKILL if hasattr(signal, "SIGKILL") else signal.SIGTERM)
                except Exception:
                    pass
        try:
            ScanRepo.update_status(job_id, "cancelled")
        except Exception:
            pass
        del _active_scans[job_id]
        _persist_scan_state()
    else:
        raise HTTPException(404, "Job not found")

    # Clean up stop signal if present
    if target:
        slug = target.replace("://", "_").replace("/", "_").replace(":", "_")
        stop_file = BASE / ".antigravity" / f"stop_{slug}.signal"
        if stop_file.exists():
            stop_file.unlink()

    # Flush partial log to DB AFTER process is dead so tempfile is complete
    try:
        _flush_scan_log_to_db(job_id)
    except Exception:
        pass
    # Sweep per-scan temp files (kali container + host scratch)
    try:
        from core.common.scan_cleanup import cleanup_after_scan
        cleanup_after_scan(scan_id=job_id)
    except Exception:
        pass

    return {"status": "cancelled", "job_id": job_id}


@app.post("/api/scans/kill-all")
def kill_all_scans():
    killed = []
    for job_id, job in list(_active_scans.items()):
        pid = job.get("pid")
        target = job.get("target", "")
        if pid and _is_pid_alive(pid):
            try:
                import signal
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
        if target:
            slug = target.replace("://", "_").replace("/", "_").replace(":", "_")
            stop_file = BASE / ".antigravity" / f"stop_{slug}.signal"
            stop_file.parent.mkdir(parents=True, exist_ok=True)
            stop_file.touch()
        job["status"] = "cancelled"
        ScanRepo.update_status(job_id, "cancelled")
        killed.append(job_id)
        # Flush partial log to DB, then sweep this scan's temp files
        try:
            _flush_scan_log_to_db(job_id)
        except Exception:
            pass
        try:
            from core.common.scan_cleanup import cleanup_after_scan
            cleanup_after_scan(scan_id=job_id)
        except Exception:
            pass
    _active_scans.clear()
    _persist_scan_state()
    return {"status": "all_killed", "killed": killed, "count": len(killed)}


class ResumeRequest(BaseModel):
    target: str
    tier: str = "POC"
    auto_approve: bool = False
    skip_osint: bool = False


@app.post("/api/scans/resume")
def resume_scan(body: ResumeRequest):
    from core.orchestration.checkpointer import Checkpointer
    cp = Checkpointer()
    cp_path = cp.get_latest_checkpoint(body.target)
    if not cp_path:
        raise HTTPException(404, f"No checkpoint found for {body.target}")

    for job in _active_scans.values():
        if job["target"] == body.target and job["status"] == "running":
            raise HTTPException(409, f"Scan already running for {body.target}")

    job_id = make_run_id(body.target)
    _active_scans[job_id] = {
        "job_id": job_id,
        "target": body.target,
        "tier": body.tier,
        "status": "starting",
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
        "pid": None,
        "exit_code": None,
        "error": None,
        "log_file": str(_scan_log_path(job_id)),
        "resumed_from": cp_path,
    }
    _persist_scan_state()

    t = threading.Thread(
        target=_run_scan_process,
        args=(job_id, body.target, body.tier, body.auto_approve, body.skip_osint, False),
        kwargs={"resume": True},
        daemon=True,
    )
    t.start()
    return {"job_id": job_id, "status": "resumed", "checkpoint": cp_path}


@app.get("/api/scans/job/{job_id}/logs-full")
def get_scan_logs_full(job_id: str):
    raw = _read_scan_log(job_id)
    if not raw:
        return {"lines": [], "total": 0}
    text = raw.decode("utf-8", errors="replace")
    all_lines = text.splitlines(keepends=True)
    return {"lines": all_lines, "total": len(all_lines)}


@app.get("/api/scans/job/{job_id}/logs-download")
def download_scan_logs(job_id: str):
    from fastapi.responses import Response
    raw = _read_scan_log(job_id)
    if not raw:
        raise HTTPException(404, "Log not found (scan may still be initialising)")
    return Response(
        content=raw, media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="scan_{job_id}_logs.txt"'},
    )


# ── WebSocket Live Feed ────────────────────────────────────────────────────

class ConnectionManager:

    def __init__(self):
        self.active: dict = {}  # job_id -> set of WebSocket connections
        self._broadcast_lock = threading.Lock()

    async def connect(self, websocket: WebSocket, job_id: str, subprotocol: str = None):
        if subprotocol:
            await websocket.accept(subprotocol=subprotocol)
        else:
            await websocket.accept()
        if job_id not in self.active:
            self.active[job_id] = set()
        self.active[job_id].add(websocket)

    def disconnect(self, websocket: WebSocket, job_id: str):
        if job_id in self.active:
            self.active[job_id].discard(websocket)
            if not self.active[job_id]:
                del self.active[job_id]

    async def broadcast(self, job_id: str, message: dict):
        if job_id not in self.active:
            return
        dead = set()
        msg_text = json.dumps(message)
        for ws in self.active[job_id]:
            try:
                await ws.send_text(msg_text)
            except Exception:
                dead.add(ws)
        self.active[job_id] -= dead

    def has_subscribers(self, job_id: str) -> bool:
        return bool(self.active.get(job_id))


ws_manager = ConnectionManager()

# Background task that pushes live data to WebSocket subscribers
_ws_push_tasks: dict = {}


async def _ws_push_loop(job_id: str):
    import asyncio as _aio
    prev_hash = ""
    while ws_manager.has_subscribers(job_id):
        try:
            progress = {}
            try:
                progress = LiveDataRepo.get_progress() or {}
            except Exception:
                pass

            results = {}
            try:
                results = LiveDataRepo.get_results() or {}
            except Exception:
                pass

            job = _active_scans.get(job_id, {})
            log_lines = []
            log_file = Path(job.get("log_file", "")) if job.get("log_file") else None
            if log_file and log_file.exists():
                try:
                    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                        all_lines = f.readlines()
                        log_lines = all_lines[-50:]
                except Exception:
                    pass

            payload = {
                "type": "live_update",
                "job_id": job_id,
                "status": job.get("status", "unknown"),
                "progress": progress,
                "results": results,
                # Scrub bearer tokens, API keys, passwords, and long hex/base64
                # secrets before they hit the wire. Log lines commonly contain
                # captured Authorization headers from target responses.
                "log_tail": [_scrub_secrets(l.rstrip()) for l in log_lines],
                "timestamp": datetime.utcnow().isoformat(),
            }

            cur_hash = str(hash(json.dumps(payload, sort_keys=True, default=str)))
            if cur_hash != prev_hash:
                await ws_manager.broadcast(job_id, payload)
                prev_hash = cur_hash

        except Exception:
            pass

        await _aio.sleep(2)

    _ws_push_tasks.pop(job_id, None)


@app.websocket("/ws/scan/{job_id}")
async def ws_scan_feed(websocket: WebSocket, job_id: str):
    import asyncio as _aio

    # Extract client-provided key
    provided = websocket.headers.get("x-api-key") or ""
    subprotocol_to_accept = None
    if not provided:
        # Subprotocol form: client sends ["api-key", "<the-key>"]
        subs = websocket.headers.get("sec-websocket-protocol", "")
        parts = [p.strip() for p in subs.split(",") if p.strip()]
        if len(parts) >= 2 and parts[0] == "api-key":
            provided = parts[1]
            subprotocol_to_accept = "api-key"

    if not _constant_time_eq(provided, _API_KEY):
        await websocket.close(code=4401)  # 4xxx = application-defined
        return

    await ws_manager.connect(websocket, job_id, subprotocol=subprotocol_to_accept)

    # Start push loop if not already running
    if job_id not in _ws_push_tasks:
        _ws_push_tasks[job_id] = _aio.create_task(_ws_push_loop(job_id))

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        ws_manager.disconnect(websocket, job_id)


# ── Canonical V2 State APIs ────────────────────────────────────────────────

@app.get("/api/canonical/summary")
def get_canonical_summary(scan_id: Optional[str] = None):
    summary_path = REPORTS_DIR / "canonical_summary.json"
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"status": "no_canonical_report", "message": "Run a scan to generate canonical report"}


@app.get("/api/canonical/coverage")
def get_canonical_coverage():
    summary_path = REPORTS_DIR / "canonical_summary.json"
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("coverage", {})
    return {"status": "no_coverage_data"}


@app.get("/api/canonical/convergence")
def get_canonical_convergence():
    summary_path = REPORTS_DIR / "canonical_summary.json"
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("convergence", {})
    return {"status": "no_convergence_data"}


@app.get("/api/canonical/attack-surface")
def get_canonical_attack_surface():
    summary_path = REPORTS_DIR / "canonical_summary.json"
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("discovery", {})
    return {"status": "no_attack_surface"}


@app.get("/api/canonical/learning")
def get_canonical_learning():
    summary_path = REPORTS_DIR / "canonical_summary.json"
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("learning", {})
    return {"status": "no_learning_data"}


@app.get("/api/canonical/health")
def get_canonical_health():
    summary_path = REPORTS_DIR / "canonical_summary.json"
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("health", {})
    return {"status": "no_health_data"}


@app.get("/api/coverage/tracker")
def get_coverage_tracker():
    tracker_path = REPORTS_DIR / "coverage_tracker.json"
    if tracker_path.exists():
        with open(tracker_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"status": "no_coverage_data"}


@app.get("/api/coverage/honest")
def get_honest_coverage():
    tracker_path = REPORTS_DIR / "coverage_tracker.json"
    if tracker_path.exists():
        with open(tracker_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("report", {}).get("coverage", {"status": "no_coverage_data"})
    return {"status": "no_coverage_data"}


@app.get("/api/skills")
def list_skills():
    try:
        from core.skills import SkillLoader
        loader = SkillLoader()
        skills = loader.load_all()
        return {"skills": [s.to_dict() for s in skills], "count": len(skills)}
    except Exception as e:
        return {"error": str(e), "skills": []}


# ── SARIF Export ────────────────────────────────────────────────────────────

@app.get("/api/scans/{scan_id}/sarif")
def export_sarif(scan_id: str):
    scan = ScanRepo.get(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")
    vulns = VulnRepo.get_by_scan(scan_id)
    from core.reporting.sarif_export import SARIFExporter
    exporter = SARIFExporter()
    target = scan.get("target", "")
    return exporter.export(vulns, target=target, scan_id=scan_id)


@app.get("/api/scans/{scan_id}/gitlab-dast")
def export_gitlab_dast(scan_id: str):
    scan = ScanRepo.get(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")
    vulns = VulnRepo.get_by_scan(scan_id)
    from core.reporting.sarif_export import SARIFExporter
    exporter = SARIFExporter()
    target = scan.get("target", "")
    return exporter.export_gitlab_dast(vulns, target=target, scan_id=scan_id)


# ── Scheduled Scans ────────────────────────────────────────────────────────

class ScheduleRequest(BaseModel):
    target: str = Field(..., max_length=2048)
    # 1 hour minimum stops a scheduler spin-loop; 24 * 30 days upper bound is
    # generous for monthly cadence but still finite.
    interval_hours: int = Field(24, ge=1, le=24 * 30)
    tier: str = "POC"
    phases: Optional[List[str]] = None

    @field_validator("target")
    @classmethod
    def _v_target(cls, v: str) -> str:
        return _validate_target_url(v)

    @field_validator("tier")
    @classmethod
    def _v_tier(cls, v: str) -> str:
        v = str(v or "").strip().upper()
        if v not in _ALLOWED_TIERS:
            raise ValueError(f"tier must be one of {sorted(_ALLOWED_TIERS)}")
        return v

    @field_validator("phases")
    @classmethod
    def _v_phases(cls, v):
        if v is None:
            return None
        out = []
        for p in v:
            p_norm = str(p or "").strip().upper()
            if p_norm and p_norm not in _ALLOWED_PHASES:
                raise ValueError(f"phase '{p}' not one of {sorted(_ALLOWED_PHASES)}")
            if p_norm:
                out.append(p_norm)
        return out


@app.get("/api/schedules")
def list_schedules():
    from core.orchestration.scheduler import get_scheduler
    return get_scheduler().list_schedules()


@app.post("/api/schedules")
def add_schedule(req: ScheduleRequest):
    from core.orchestration.scheduler import get_scheduler
    scheduler = get_scheduler()
    schedule = scheduler.add_schedule(req.target, req.interval_hours, req.tier, req.phases)
    return {"status": "created", "schedule": schedule.__dict__}


@app.delete("/api/schedules/{schedule_id}")
def delete_schedule(schedule_id: str):
    from core.orchestration.scheduler import get_scheduler
    if get_scheduler().remove_schedule(schedule_id):
        return {"status": "deleted"}
    raise HTTPException(404, "Schedule not found")


@app.post("/api/schedules/{schedule_id}/toggle")
def toggle_schedule(schedule_id: str):
    from core.orchestration.scheduler import get_scheduler
    scheduler = get_scheduler()
    s = scheduler.schedules.get(schedule_id)
    if not s:
        raise HTTPException(404, "Schedule not found")
    scheduler.update_schedule(schedule_id, enabled=not s.enabled)
    return {"status": "toggled", "enabled": not s.enabled}


@app.post("/api/scheduler/start")
def start_scheduler():
    from core.orchestration.scheduler import get_scheduler
    get_scheduler().start()
    return {"status": "started"}


# ── Campaign Mode ──────────────────────────────────────────────────────────

class CampaignRequest(BaseModel):
    targets: List[str] = Field(..., min_length=1, max_length=1000)
    tier: str = "POC"
    # 1 to 32 parallel scans. Above 32 the Kali container + subprocess storm
    # exhausts host resources; below 1 the campaign wouldn't progress.
    max_parallel: int = Field(3, ge=1, le=32)

    @field_validator("targets")
    @classmethod
    def _v_targets(cls, v: List[str]) -> List[str]:
        return [_validate_target_url(t) for t in v]

    @field_validator("tier")
    @classmethod
    def _v_tier(cls, v: str) -> str:
        v = str(v or "").strip().upper()
        if v not in _ALLOWED_TIERS:
            raise ValueError(f"tier must be one of {sorted(_ALLOWED_TIERS)}")
        return v


@app.post("/api/campaigns/run")
async def run_campaign(req: CampaignRequest):
    from core.orchestration.campaign import CampaignManager
    campaign = CampaignManager(req.targets, tier=req.tier, max_parallel=req.max_parallel)
    job_id = f"campaign_{campaign.campaign_id}"
    import asyncio
    asyncio.create_task(campaign.run())
    return {"status": "started", "campaign_id": campaign.campaign_id, "job_id": job_id,
            "targets": len(req.targets)}


@app.get("/api/campaigns/progress")
def campaign_progress():
    try:
        return CampaignRepo.get_progress()
    except Exception:
        return {}


@app.get("/api/campaigns")
def list_campaigns():
    try:
        return CampaignRepo.list_all()
    except Exception:
        return []


# ── Decision Log ───────────────────────────────────────────────────────────
def _query_table(sql: str, limit: int, serialize_dates: bool = True):
    from core.database.pg_store import DatabaseManager
    import psycopg2.extras
    with DatabaseManager.get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (limit,))
            rows = [dict(r) for r in cur.fetchall()]
    if serialize_dates:
        for r in rows:
            for k, v in r.items():
                if hasattr(v, 'isoformat'):
                    r[k] = v.isoformat()
                elif isinstance(v, float):
                    r[k] = round(v, 4)
    return rows


@app.get("/api/decision-log")
def get_decision_log(limit: int = 200):
    try:
        return _query_table(
            "SELECT id, timestamp, phase, decision_type, context, result, confidence, model_used "
            "FROM decision_log ORDER BY id DESC LIMIT %s", limit)
    except Exception as e:
        logger.debug(f"decision-log: {e}")
        return []


# ── Experiences & Strategies ───────────────────────────────────────────────
@app.get("/api/experiences")
def get_experiences(limit: int = 200):
    try:
        return _query_table(
            "SELECT experience_id, test_type, target_fingerprint, strategy_used, "
            "outcome, evidence_quality, duration_ms, error_type, created_at "
            "FROM experiences ORDER BY created_at DESC LIMIT %s", limit)
    except Exception as e:
        logger.debug(f"experiences: {e}")
        return []


@app.get("/api/strategies")
def get_strategies(limit: int = 100):
    try:
        return _query_table(
            "SELECT strategy_id, test_type, description, success_rate, avg_duration_ms, "
            "total_attempts, total_successes, total_failures, last_used "
            "FROM strategies ORDER BY last_used DESC LIMIT %s", limit)
    except Exception as e:
        logger.debug(f"strategies: {e}")
        return []


# ── LLM Failures ───────────────────────────────────────────────────────────
@app.get("/api/llm-failures")
def get_llm_failures(limit: int = 200):
    try:
        return _query_table(
            "SELECT failure_id, provider, model, task_type, failure_type, failure_reason, "
            "input_tokens, output_tokens, duration_ms, created_at "
            "FROM llm_failures ORDER BY created_at DESC LIMIT %s", limit)
    except Exception as e:
        logger.debug(f"llm-failures: {e}")
        return []


# ── Error Classification Stats ─────────────────────────────────────────────
@app.get("/api/error-stats")
def get_error_stats():
    try:
        from core.error.error_classifier import ErrorClassifier, RetryExecutor
        retry_path = REPORTS_DIR / "retry_stats.json"
        if retry_path.exists():
            with open(retry_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"total_attempts": 0, "retries": 0, "recovered": 0, "permanent_failures": 0}
    except Exception:
        return {"total_attempts": 0, "retries": 0, "recovered": 0, "permanent_failures": 0}


# ── Confidence Scoring Aggregate ───────────────────────────────────────────
@app.get("/api/confidence/summary")
def get_confidence_summary():
    try:
        all_vulns = VulnRepo.get_all()
        reportable = 0
        needs_review = 0
        rejected = 0
        scored = 0
        total = len(all_vulns)
        scores = []
        for v in all_vulns:
            cs = v.get("confidence_score")
            if cs is not None:
                scored += 1
                score_pct = cs * 100 if cs <= 1 else cs
                scores.append(score_pct)
                if v.get("auto_reportable"):
                    reportable += 1
                elif v.get("needs_review"):
                    needs_review += 1
                else:
                    rejected += 1
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0
        return {
            "total_findings": total,
            "scored": scored,
            "unscored": total - scored,
            "reportable": reportable,
            "needs_review": needs_review,
            "rejected": rejected,
            "avg_confidence": avg_score,
        }
    except Exception:
        return {"total_findings": 0, "scored": 0, "unscored": 0, "reportable": 0,
                "needs_review": 0, "rejected": 0, "avg_confidence": 0}


# ── Findings V2 ────────────────────────────────────────────────────────────
@app.get("/api/findings-v2")
def get_findings_v2():
    try:
        return FindingV2Repo.list_all()
    except Exception:
        return []


@app.get("/api/findings-v2/confirmed")
def get_findings_v2_confirmed():
    try:
        return FindingV2Repo.list_confirmed()
    except Exception:
        return []


# ── Exploit Results (from DB table) ────────────────────────────────────────
@app.get("/api/scans/{scan_id}/exploit-results")
def get_exploit_results(scan_id: str):
    try:
        return ExploitResultRepo.get_by_scan(scan_id)
    except Exception:
        return []


# ── Dedup Stats ───────────────────────────────────────────────────────────
@app.get("/api/dedup-stats")
def get_dedup_stats():
    try:
        rows = DedupRepo.list_all(500)
        return {
            "total_signatures": len(rows),
            "total_duplicates_caught": sum(r.get("count", 1) - 1 for r in rows),
            "entries": rows,
        }
    except Exception:
        return {"total_signatures": 0, "total_duplicates_caught": 0, "entries": []}


# ── Data Transparency ────────────────────────────────────────────────────
@app.get("/api/scans/{scan_id}/collected-data")
def get_collected_data(scan_id: str):
    out = {"scan_id": scan_id, "tables": {}}
    try:
        scan = ScanRepo.get(scan_id)
        out["tables"]["scans"] = {"count": 1 if scan else 0, "description": "Scan metadata, status, timing"}
    except Exception:
        out["tables"]["scans"] = {"count": 0, "description": "Scan metadata"}
    try:
        vulns = VulnRepo.get_by_scan(scan_id)
        out["tables"]["vulnerabilities"] = {"count": len(vulns), "description": "Discovered vulnerabilities", "data": vulns}
    except Exception:
        out["tables"]["vulnerabilities"] = {"count": 0, "description": "Discovered vulnerabilities", "data": []}
    try:
        exploits = ExploitResultRepo.get_by_scan(scan_id)
        out["tables"]["exploit_results"] = {"count": len(exploits), "description": "Exploitation attempts and results", "data": exploits}
    except Exception:
        out["tables"]["exploit_results"] = {"count": 0, "description": "Exploitation attempts", "data": []}
    try:
        from core.database.pg_store import ReconRepo
        recon = ReconRepo.get(scan_id)
        recon_keys = list(recon.keys()) if recon else []
        out["tables"]["recon_data"] = {"count": 1 if recon else 0, "description": "Reconnaissance intelligence", "keys": recon_keys}
    except Exception:
        out["tables"]["recon_data"] = {"count": 0, "description": "Reconnaissance intelligence", "keys": []}
    try:
        from core.database.pg_store import DatabaseManager
        import psycopg2.extras
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM tool_outputs WHERE scan_id = %s", (scan_id,))
                tool_count = cur.fetchone()["cnt"]
                cur.execute("SELECT id, scan_id, tool_name, operation, exit_code, duration_s, length(stdout) as stdout_len, created_at FROM tool_outputs WHERE scan_id = %s ORDER BY created_at DESC LIMIT 50", (scan_id,))
                tool_rows = [dict(r) for r in cur.fetchall()]

                cur.execute("SELECT COUNT(*) as cnt FROM agent_activity WHERE scan_id = %s", (scan_id,))
                activity_count = cur.fetchone()["cnt"]
                cur.execute("SELECT id, scan_id, action, title, tool, target, phase, status, duration_s, created_at FROM agent_activity WHERE scan_id = %s ORDER BY created_at DESC LIMIT 50", (scan_id,))
                activity_rows = [dict(r) for r in cur.fetchall()]

                cur.execute("SELECT COUNT(*) as cnt FROM captured_requests WHERE scan_id = %s", (scan_id,))
                requests_count = cur.fetchone()["cnt"]
                cur.execute("SELECT id, scan_id, method, url, resource_type, status, source, created_at FROM captured_requests WHERE scan_id = %s ORDER BY created_at DESC LIMIT 50", (scan_id,))
                request_rows = [dict(r) for r in cur.fetchall()]

                cur.execute("SELECT COUNT(*) as cnt FROM tool_executions WHERE scan_id = %s", (scan_id,))
                texec_count = cur.fetchone()["cnt"]
                cur.execute("SELECT id, scan_id, tool, capability, success, stdout_bytes, duration_s, created_at FROM tool_executions WHERE scan_id = %s ORDER BY created_at DESC LIMIT 50", (scan_id,))
                texec_rows = [dict(r) for r in cur.fetchall()]

        out["tables"]["tool_outputs"] = {"count": tool_count, "description": "Raw tool stdout/stderr per execution", "data": tool_rows}
        out["tables"]["agent_activity"] = {"count": activity_count, "description": "Agent actions, decisions, tool calls", "data": activity_rows}
        out["tables"]["captured_requests"] = {"count": requests_count, "description": "HTTP requests captured during browsing", "data": request_rows}
        out["tables"]["tool_executions"] = {"count": texec_count, "description": "Tool execution records with timing", "data": texec_rows}
    except Exception:
        pass
    try:
        f2 = FindingV2Repo.list_all()
        out["tables"]["findings_v2"] = {"count": len(f2), "description": "Canonical validated findings", "data": f2}
    except Exception:
        out["tables"]["findings_v2"] = {"count": 0, "description": "Canonical validated findings", "data": []}
    try:
        dedup = DedupRepo.list_all(200)
        out["tables"]["findings_dedup"] = {"count": len(dedup), "description": "Deduplication signatures to prevent double-counting", "data": dedup}
    except Exception:
        out["tables"]["findings_dedup"] = {"count": 0, "description": "Deduplication signatures", "data": []}
    return out


# ── Exploit Reports (markdown files from reports/exploits/) ──────────────

@app.get("/api/scans/{scan_id}/exploit-reports")
def get_exploit_reports(scan_id: str):
    exploit_dir = REPORTS_DIR / "exploits"
    if not exploit_dir.exists():
        return []
    reports = []
    for md_file in sorted(exploit_dir.glob("*.md")):
        content = md_file.read_text(encoding="utf-8", errors="replace")
        parsed = _parse_exploit_md(content, md_file.name)
        reports.append(parsed)
    return reports


def _parse_exploit_md(content: str, filename: str) -> dict:
    result = {"filename": filename, "raw": content}
    lines = content.split("\n")
    for line in lines:
        line_s = line.strip()
        if line_s.startswith("- **Agent:**"):
            result["agent"] = line_s.split("**Agent:**")[1].strip()
        elif line_s.startswith("- **Target:**"):
            result["target"] = line_s.split("**Target:**")[1].strip()
        elif line_s.startswith("- **Objective:**"):
            result["objective"] = line_s.split("**Objective:**")[1].strip()
        elif line_s.startswith("- **Outcome:**"):
            result["outcome"] = line_s.split("**Outcome:**")[1].strip()
        elif line_s.startswith("- **Payloads tested:**"):
            result["payloads_tested"] = line_s.split("**Payloads tested:**")[1].strip()
        elif line_s.startswith("- **Tier:**"):
            result["tier"] = line_s.split("**Tier:**")[1].strip()
        elif line_s.startswith("- **Generated:**"):
            result["generated"] = line_s.split("**Generated:**")[1].strip()
        elif line_s.startswith("- **Operator consent:**"):
            result["consent"] = line_s.split("**Operator consent:**")[1].strip()
    # Extract sections
    sections = {}
    current_section = None
    current_lines = []
    for line in lines:
        if line.startswith("## "):
            if current_section:
                sections[current_section] = "\n".join(current_lines).strip()
            current_section = line[3:].strip()
            current_lines = []
        elif current_section:
            current_lines.append(line)
    if current_section:
        sections[current_section] = "\n".join(current_lines).strip()
    result["sections"] = sections
    # Extract activity table
    if "Activity log" in sections:
        rows = []
        for line in sections["Activity log"].split("\n"):
            if line.strip().startswith("|") and not line.strip().startswith("|---") and "Step" not in line:
                parts = [p.strip() for p in line.split("|")[1:-1]]
                if len(parts) >= 4:
                    rows.append({"step": parts[0], "action": parts[1], "payload": parts[2], "status": parts[3], "analysis": parts[4] if len(parts) > 4 else ""})
        result["activity_log"] = rows
    return result


@app.get("/api/evidence/{filename}")
def get_evidence_file(filename: str):
    import re
    if not filename or "\x00" in filename:
        raise HTTPException(400, "Invalid filename")
    # No separators, no traversal segments.
    if "/" in filename or "\\" in filename or filename in ("", ".", ".."):
        raise HTTPException(400, "Invalid filename")
    # Conservative allowlist for evidence filenames.
    if not re.match(r'^[A-Za-z0-9._-]+$', filename):
        raise HTTPException(400, "Invalid filename")

    evidence_dir = (REPORTS_DIR / "evidence").resolve()
    try:
        file_path = (evidence_dir / filename).resolve()
    except Exception:
        raise HTTPException(400, "Invalid filename")
    # Enforce boundary — refuse anything that resolved outside evidence_dir.
    try:
        file_path.relative_to(evidence_dir)
    except ValueError:
        raise HTTPException(400, "Invalid filename")
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(404, "Evidence file not found")
    from fastapi.responses import FileResponse
    media_type = "image/png" if filename.endswith(".png") else "application/octet-stream"
    return FileResponse(str(file_path), media_type=media_type)


@app.get("/api/evidence")
def list_evidence():
    evidence_dir = REPORTS_DIR / "evidence"
    if not evidence_dir.exists():
        return []
    return [{"name": f.name, "size": f.stat().st_size, "type": f.suffix}
            for f in evidence_dir.iterdir() if f.is_file()]


@app.get("/api/scans/{scan_id}/executive-summary")
def get_executive_summary(scan_id: str):
    scan = ScanRepo.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    report = scan.get("report_data") or {}
    return {
        "executive_summary": report.get("executive_summary", ""),
        "metadata": report.get("metadata", {}),
        "scope": report.get("scope", {}),
    }


# NOTE: the earlier `@app.get("/api/scans/{scan_id}/attack-chains")` at ~1110
# is the canonical handler. FastAPI keeps the last-registered handler for a
# path, so a second registration here was silently masking the earlier one
# and returning a different shape than the frontend expects. Removed.


@app.get("/api/scans/{scan_id}/post-exploit")
async def get_post_exploit(scan_id: str, data_type: str = None):
    try:
        from core.database.pg_store import PostExploitRepo
        return PostExploitRepo.get_by_scan(scan_id, data_type)
    except Exception as e:
        return {"error": str(e), "data": []}


@app.get("/api/scans/{scan_id}/metadata")
async def get_scan_metadata(scan_id: str, key: str = None):
    try:
        from core.database.pg_store import ScanMetadataRepo
        if key:
            return {"key": key, "value": ScanMetadataRepo.get(scan_id, key)}
        return ScanMetadataRepo.get_all(scan_id)
    except Exception as e:
        return {"error": str(e)}


# ── RAG Knowledge Base Endpoints ───────────────────────────────────────────

class RAGTextIngest(BaseModel):
    text: str
    title: str = "manual_note"
    metadata: dict = {}

class RAGURLIngest(BaseModel):
    url: str = Field(..., max_length=4096)
    metadata: dict = {}

    @field_validator("url")
    @classmethod
    def _v_url(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("url required")
        parsed = _urlparse(v)
        if parsed.scheme not in _ALLOWED_SCHEMES:
            raise ValueError(f"url scheme must be one of {sorted(_ALLOWED_SCHEMES)}")
        if not parsed.hostname:
            raise ValueError("url must include a hostname")
        # Reject IP literals in blocked ranges. Hostnames are DNS-resolved by
        # the ingest client; if the operator's environment permits SSRF, run
        # the API in a network namespace with egress restricted.
        try:
            ip = _ipaddress.ip_address(parsed.hostname)
            if (ip.is_loopback or ip.is_private or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved):
                raise ValueError("url points to a non-routable / private address")
            if str(ip) == "169.254.169.254":
                raise ValueError("cloud metadata address is not permitted")
        except ValueError as e:
            # Re-raise our own; ignore _ipaddress ValueError from hostname strings.
            if "url" in str(e) or "cloud metadata" in str(e):
                raise
        return v

class RAGSearchIngest(BaseModel):
    query: str
    max_results: int = 3

class RAGQuery(BaseModel):
    query: str
    top_k: int = 5
    category: str = ""

class RAGDelete(BaseModel):
    source_type: str
    source_ref: str = ""


def _get_rag():
    from core.rag.pipeline import get_rag
    rag = get_rag()
    if not rag:
        raise HTTPException(status_code=503, detail="RAG pipeline not initialized. Run a scan first or call /api/rag/init.")
    return rag


async def _ensure_rag():
    from core.rag.pipeline import get_rag, SecurityRAGPipeline
    rag = get_rag()
    if rag:
        return rag
    from core.common.config import get_config
    config = get_config()
    rag = SecurityRAGPipeline(api_key=config.get("DEEPSEEK_API_KEY"))
    await rag.initialize()
    return rag


# ── RAG ingest progress registry ──────────────────────────────────────────
# In-memory per-job progress so the UI can show a real percentage while a
# large PDF/URL is being embedded. Bounded to the most recent jobs.
_RAG_PROGRESS: OrderedDict[str, dict] = OrderedDict()
_RAG_PROGRESS_MAX = 200


def _rag_progress_set(job_id: str, **fields) -> None:
    if not job_id:
        return
    cur = _RAG_PROGRESS.get(job_id) or {"done": 0, "total": 0, "status": "running"}
    cur.update(fields)
    _RAG_PROGRESS[job_id] = cur
    _RAG_PROGRESS.move_to_end(job_id)
    while len(_RAG_PROGRESS) > _RAG_PROGRESS_MAX:
        _RAG_PROGRESS.popitem(last=False)


def _rag_progress_cb(job_id: str):
    def _cb(done: int, total: int):
        pct = int(done * 100 / total) if total else 0
        _rag_progress_set(job_id, done=done, total=total, percent=pct,
                          status="running" if done < total else "finalizing")
    return _cb


@app.get("/api/rag/ingest/progress/{job_id}")
def rag_ingest_progress(job_id: str):
    p = _RAG_PROGRESS.get(job_id)
    if not p:
        return {"job_id": job_id, "status": "unknown", "percent": 0, "done": 0, "total": 0}
    return {"job_id": job_id, **p}


@app.post("/api/rag/init")
async def rag_init():
    try:
        from core.rag.pipeline import SecurityRAGPipeline, get_rag
        rag = get_rag()
        if rag:
            return {"status": "already_initialized", **rag.stats()}
        from core.common.config import get_config
        config = get_config()
        rag = SecurityRAGPipeline(api_key=config.get("DEEPSEEK_API_KEY"))
        await rag.initialize()
        return {"status": "initialized", **rag.stats()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/rag/stats")
async def rag_stats():
    return (await _ensure_rag()).stats()


@app.post("/api/rag/ingest/file")
async def rag_ingest_file(file_path: str = "", metadata: str = "{}"):
    if not file_path:
        raise HTTPException(status_code=400, detail="file_path required")

    # Resolve the requested file and enforce it lives under an approved root.
    try:
        candidate = Path(file_path).expanduser().resolve()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid file_path")
    if not candidate.exists() or not candidate.is_file():
        raise HTTPException(status_code=404, detail="file not found")

    _default_root = (BASE / "data" / "rag_ingest").resolve()
    _default_root.mkdir(parents=True, exist_ok=True)
    _roots_env = os.getenv("RAG_INGEST_ROOTS", "").strip()
    if _roots_env:
        # Split on ; and : (but leave Windows drive letters alone by only
        # treating single-char colons as separators when they're not the 2nd char).
        import re as _re
        raw_roots = [p for p in _re.split(r"[;\n]+", _roots_env) if p.strip()]
        roots = []
        for r in raw_roots:
            try:
                roots.append(Path(r).expanduser().resolve())
            except Exception:
                pass
    else:
        roots = [_default_root]

    if not any(_is_within(candidate, r) for r in roots):
        raise HTTPException(
            status_code=403,
            detail=f"file_path must be within an approved RAG_INGEST_ROOTS directory. "
                   f"Approved: {[str(r) for r in roots]}")

    rag = await _ensure_rag()
    try:
        meta = json.loads(metadata) if metadata else {}
    except Exception:
        meta = {}
    result = await rag.ingest_file(str(candidate), metadata=meta)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


from fastapi import UploadFile, File, Form

@app.post("/api/rag/ingest/uploaded")
async def rag_ingest_uploaded(file: UploadFile = File(...), metadata: str = Form("{}"),
                              job_id: str = ""):
    import tempfile
    rag = await _ensure_rag()
    suffix = Path(file.filename).suffix if file.filename else ".txt"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False, dir=str(REPORTS_DIR)) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name
    try:
        meta = json.loads(metadata) if metadata else {}
    except Exception:
        meta = {}
    meta["original_filename"] = file.filename

    if job_id:
        _rag_progress_set(job_id, status="running", done=0, total=0, percent=0,
                          label=file.filename)

        async def _job():
            try:
                res = await rag.ingest_file(tmp_path, metadata=meta,
                                            progress_cb=_rag_progress_cb(job_id))
                _rag_progress_set(job_id, result=res, error=res.get("error"),
                                  status="error" if "error" in res else "done",
                                  percent=100 if "error" not in res else _RAG_PROGRESS.get(job_id, {}).get("percent", 0))
            except Exception as e:
                _rag_progress_set(job_id, status="error", error=str(e))
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
        asyncio.create_task(_job())
        return {"job_id": job_id, "status": "started"}

    result = await rag.ingest_file(tmp_path, metadata=meta)
    try:
        os.unlink(tmp_path)
    except Exception:
        pass
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


# ── Scan input upload — APK / IPA for mobile backend analysis (Phase 4.4) ───
_ALLOWED_SCAN_UPLOAD_SUFFIXES = {".apk", ".ipa"}
_MAX_SCAN_UPLOAD_BYTES = 300 * 1024 * 1024  # 300 MB

@app.post("/api/uploads/scan-input")
async def upload_scan_input(file: UploadFile = File(...)):
    """Receive an APK/IPA to analyze, store it server-side under data/uploads/,
    and return a path the scan can be launched with (`mobile_app` / `ipa_app`)."""
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in _ALLOWED_SCAN_UPLOAD_SUFFIXES:
        raise HTTPException(400, f"unsupported file type '{suffix}' (allow: .apk, .ipa)")
    uploads = BASE / "data" / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    dest = uploads / f"{uuid.uuid4().hex}{suffix}"
    size = 0
    with open(dest, "wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_SCAN_UPLOAD_BYTES:
                out.close()
                try:
                    dest.unlink(missing_ok=True)
                except Exception:
                    pass
                raise HTTPException(413, "file too large (max 300MB)")
            out.write(chunk)
    kind = "ipa" if suffix == ".ipa" else "apk"
    logger.info("scan-input uploaded: %s (%d bytes) → %s", file.filename, size, dest)
    return {"path": str(dest), "kind": kind, "filename": file.filename, "size": size}


@app.post("/api/rag/ingest/text")
async def rag_ingest_text(body: RAGTextIngest, job_id: str = ""):
    rag = await _ensure_rag()
    if job_id:
        _rag_progress_set(job_id, status="running", done=0, total=0, percent=0,
                          label=body.title or "note")

        async def _job():
            try:
                res = await rag.ingest_text(body.text, title=body.title,
                                            metadata=body.metadata,
                                            progress_cb=_rag_progress_cb(job_id))
                _rag_progress_set(job_id, result=res, error=res.get("error"),
                                  status="error" if "error" in res else "done",
                                  percent=100 if "error" not in res else _RAG_PROGRESS.get(job_id, {}).get("percent", 0))
            except Exception as e:
                _rag_progress_set(job_id, status="error", error=str(e))
        asyncio.create_task(_job())
        return {"job_id": job_id, "status": "started"}

    result = await rag.ingest_text(body.text, title=body.title, metadata=body.metadata)
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/rag/ingest/url")
async def rag_ingest_url(body: RAGURLIngest, job_id: str = ""):
    rag = await _ensure_rag()
    if job_id:
        _rag_progress_set(job_id, status="running", done=0, total=0, percent=0,
                          label=body.url)

        async def _job():
            try:
                res = await rag.ingest_url(body.url, metadata=body.metadata,
                                           progress_cb=_rag_progress_cb(job_id))
                _rag_progress_set(job_id, result=res, error=res.get("error"),
                                  status="error" if "error" in res else "done",
                                  percent=100 if "error" not in res else _RAG_PROGRESS.get(job_id, {}).get("percent", 0))
            except Exception as e:
                _rag_progress_set(job_id, status="error", error=str(e))
        asyncio.create_task(_job())
        return {"job_id": job_id, "status": "started"}

    result = await rag.ingest_url(body.url, metadata=body.metadata)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/rag/ingest/search")
async def rag_ingest_search(body: RAGSearchIngest, job_id: str = ""):
    rag = await _ensure_rag()
    if job_id:
        _rag_progress_set(job_id, status="running", done=0, total=0, percent=0,
                          label=f"searching: {body.query}")

        async def _job():
            try:
                res = await rag.search_and_ingest(body.query, max_results=body.max_results,
                                                  progress_cb=_rag_progress_cb(job_id))
                _rag_progress_set(job_id, result=res, error=res.get("error"),
                                  status="error" if "error" in res else "done",
                                  percent=100 if "error" not in res else _RAG_PROGRESS.get(job_id, {}).get("percent", 0))
            except Exception as e:
                _rag_progress_set(job_id, status="error", error=str(e))
        asyncio.create_task(_job())
        return {"job_id": job_id, "status": "started"}

    result = await rag.search_and_ingest(body.query, max_results=body.max_results)
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/rag/query")
async def rag_query(body: RAGQuery):
    rag = await _ensure_rag()
    docs = await rag.retrieve(
        body.query,
        top_k=body.top_k,
        category_filter=body.category if body.category else None,
    )
    return {"query": body.query, "results": docs, "count": len(docs)}


@app.delete("/api/rag/documents")
async def rag_delete_docs(body: RAGDelete):
    rag = await _ensure_rag()
    deleted = await rag.delete_by_source(body.source_type, body.source_ref or None)
    return {"deleted": deleted}


@app.get("/api/rag/documents")
async def rag_list_documents(source_type: str = None, limit: int = 100, offset: int = 0):
    rag = await _ensure_rag()
    docs = rag.list_documents(source_type=source_type, limit=limit, offset=offset)
    return {"documents": docs, "count": len(docs)}


@app.delete("/api/rag/documents/{doc_id}")
async def rag_delete_single_doc(doc_id: str):
    rag = await _ensure_rag()
    try:
        from core.memory.database import DatabaseManager
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM rag_documents WHERE doc_id = %s", (doc_id,))
                deleted = cur.rowcount
                conn.commit()
        return {"deleted": deleted}
    except Exception as e:
        return {"error": str(e)}


# Mount static frontend AFTER all API routes so /api/* takes priority
if _FRONTEND_DIR.exists():
    from starlette.responses import FileResponse as _SFR

    app.mount("/assets", StaticFiles(directory=str(_FRONTEND_DIR / "assets")), name="static-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def _spa_fallback(full_path: str):
        try:
            _frontend_root = _FRONTEND_DIR.resolve()
            file = (_FRONTEND_DIR / full_path).resolve()
            file.relative_to(_frontend_root)
        except Exception:
            return _SFR(str(_FRONTEND_DIR / "index.html"))
        if file.exists() and file.is_file():
            return _SFR(str(file))
        return _SFR(str(_FRONTEND_DIR / "index.html"))


if __name__ == "__main__":
    import uvicorn
    _api_port = int(os.getenv("API_PORT", "8903"))
    _api_host = os.getenv("API_HOST", "0.0.0.0")
    uvicorn.run(app, host=_api_host, port=_api_port)
