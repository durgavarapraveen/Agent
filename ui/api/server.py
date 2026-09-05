"""AntiGravity Dashboard API — PostgreSQL-backed, no flat files or SQLite."""

import json
import logging
import os
import subprocess
import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("antigravity.api")

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="AntiGravity Dashboard API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

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
REPORTS_DIR = BASE / "reports"

# ── PostgreSQL initialization ──────────────────────────────────────────────
sys.path.insert(0, str(BASE))
from core.database.pg_store import (
    _init_schema, TargetRepo, ScanRepo, VulnRepo, LiveDataRepo,
    FindingV2Repo, DedupRepo, AuditRepo, ScheduleRepo, CampaignRepo,
    ExploitResultRepo, make_run_id,
)
try:
    _init_schema()
except Exception as _e:
    import logging as _log
    _log.getLogger(__name__).warning(f"PG schema init failed (will retry on first query): {_e}")


# ── Models ──────────────────────────────────────────────────────────────────

class TargetCreate(BaseModel):
    url: str
    scope: str = ""
    notes: str = ""


class ScanRequest(BaseModel):
    target: str
    tier: str = "POC"
    auto_approve: bool = False
    skip_osint: bool = False
    reset_dedup: bool = False
    phases: list = []
    credentials: list = []  # [{"role": "admin", "username": "", "password": "", "login_url": ""}, ...]


# ── Scan Process Tracker ────────────────────────────────────────────────────

_active_scans: dict = {}  # in-memory cache, synced to PG


def _persist_scan_state():
    """Sync active scans to PostgreSQL."""
    for job_id, job in _active_scans.items():
        try:
            ScanRepo.update_status(job_id, job.get("status", "unknown"),
                                   pid=job.get("pid"), exit_code=job.get("exit_code"),
                                   error=job.get("error", ""), command=job.get("command", ""),
                                   log_file=job.get("log_file", ""))
        except Exception:
            pass


def _is_pid_alive(pid: int) -> bool:
    """Check if a process is still running (cross-platform)."""
    try:
        import psutil
        return psutil.pid_exists(pid)
    except ImportError:
        pass
    try:
        if os.name == "nt":
            import subprocess
            r = subprocess.run(f'tasklist /FI "PID eq {pid}" /NH', shell=True,
                               capture_output=True, encoding="utf-8", timeout=5)
            return str(pid) in r.stdout
        else:
            os.kill(pid, 0)
            return True
    except (OSError, Exception):
        return False


def _load_scan_state():
    """Reload active scans from PostgreSQL on startup."""
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
                "log_file": scan.get("log_file") or str(REPORTS_DIR / f"scan_log_{sid}.txt"),
                "command": scan.get("command", ""),
            }
    except Exception:
        _active_scans = {}


_load_scan_state()


def _run_scan_process(job_id: str, target: str, tier: str,
                      auto_approve: bool, skip_osint: bool, reset_dedup: bool,
                      resume: bool = False, phases: list = None,
                      credentials: dict = None):
    """Runs main.py as a subprocess in a background thread."""
    log_file = REPORTS_DIR / f"scan_log_{job_id}.txt"
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
    if credentials:
        import json as _json
        cmd.extend(["--credentials", _json.dumps(credentials)])
    # The run's identity is the job_id — pass it so the brain persists every row
    # (scan, vulns, review queue) under this exact id and never merges with another run.
    cmd.extend(["--scan-id", job_id])

    _active_scans[job_id]["status"] = "running"
    _active_scans[job_id]["command"] = " ".join(cmd)
    _persist_scan_state()

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

    _active_scans[job_id]["finished_at"] = datetime.utcnow().isoformat()
    _persist_scan_state()

    # Update last_scanned on the target
    try:
        TargetRepo.update_last_scanned(target)
    except Exception:
        pass


# ── Helpers ─────────────────────────────────────────────────────────────────

def _get_scans() -> list:
    """Get all scans from PostgreSQL."""
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
    """Compare two scan reports side by side (PostgreSQL-backed)."""
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
    """Return live progress from PostgreSQL, scoped to scan_id when provided."""
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
    """Return structured live results from PostgreSQL, scoped to scan_id when provided.

    When scan_id is given, the live singleton is only returned if it belongs to that
    scan; cross-scan finding merges are skipped and only that scan's persisted vulns
    are added. This prevents leakage from previous scans into the Live Scan view.
    """
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
    """Filter out garbage port entries (hostname strings from list(dict) bug)."""
    if not ports or not isinstance(ports, list):
        return []
    return [p for p in ports if isinstance(p, dict) and "port" in p and isinstance(p.get("port"), int)]


_TECH_NOISE = {
    "hsts", "application error", "not found", "page not found", "error",
    "via-proxy", "unix", "redirect", "unknown", "text/html", "text/plain",
    "utf-8", "gzip", "deflate", "chunked", "close", "keep-alive",
}

def _normalize_technologies(techs: dict) -> dict:
    """Normalize mixed-format technologies into clean {host: [tech_list]}.

    Handles: flat {name: True}, per-host {host: [techs]}, and mixed.
    Merges hosts with/without protocol prefix, filters garbage entries.
    """
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
    """Convert plain subdomain strings into structured objects with live/dead status."""
    if not subs:
        return []
    status_map = status_map or {}
    out = []
    seen = set()
    for s in subs:
        name = s if isinstance(s, str) else (s.get("name") if isinstance(s, dict) else str(s))
        host = str(name).replace("https://", "").replace("http://", "").rstrip("/").lower()
        if host in seen:
            continue
        seen.add(host)
        st = status_map.get(host, {})
        out.append({
            "name": host,
            "live": bool(st.get("live")),
            "status": "live" if st.get("live") else ("dead" if st else "unknown"),
            "status_code": st.get("status_code", 0),
        })
    return out


def _split_captured_requests(raw: list, scan_id: str) -> dict:
    """Separate real HTTP requests from tool executions. DB-first, fallback to context."""
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
    """Read exploit results from DB table first, fall back to report_data."""
    try:
        db_exploits = ExploitResultRepo.get_by_scan(scan_id)
        if db_exploits:
            return db_exploits
    except Exception:
        pass
    return report.get("exploit_results", [])


@app.get("/api/scans/{scan_id}/recon")
def get_recon(scan_id: str):
    """Full recon intelligence collected for a scan (live during recon, and after)."""
    try:
        from core.database.pg_store import ReconRepo
        return ReconRepo.get(scan_id)
    except Exception as e:
        raise HTTPException(500, f"recon data unavailable: {e}")


@app.get("/api/scans/{scan_id}/tool-outputs")
def get_tool_outputs(scan_id: str, grouped: bool = False):
    """Per-tool raw stdout/stderr for a scan — shows what each tool produced."""
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
    """Agent activity timeline — read-only log of what the agent did, how, and the output."""
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
    """Everything the agent attempted, newest first (successes + manual follow-ups)."""
    q = _review_queue()
    return {"summary": q.summary(), "items": q.all(limit)}


@app.get("/api/review-queue/successes")
def review_queue_successes(limit: int = 200):
    """Objectives the agent actually exploited — ready for a human to verify/showcase."""
    return {"items": _review_queue().successes(limit)}


@app.get("/api/review-queue/manual")
def review_queue_manual(limit: int = 200):
    """Objectives the agent could NOT exploit — for a human to pentest manually,
    with what was tried and suggested next steps."""
    return {"items": _review_queue().manual_followups(limit)}


class ReviewResolve(BaseModel):
    note: str = ""


@app.post("/api/review-queue/{record_id}/resolve")
def review_queue_resolve(record_id: str, body: ReviewResolve):
    """Mark a manual follow-up as handled by the human."""
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
    """Return the full JSON report for download from PostgreSQL."""
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
        "log_file": str(REPORTS_DIR / f"scan_log_{job_id}.txt"),
    }

    _active_scans[job_id]["phases"] = body.phases or ["RECON", "ACTIVE_SCANNING", "EXPLOITATION", "REPORTING"]
    try:
        ScanRepo.create(job_id, body.target, body.tier,
                        log_file=str(REPORTS_DIR / f"scan_log_{job_id}.txt"))
    except Exception:
        pass
    _persist_scan_state()

    t = threading.Thread(
        target=_run_scan_process,
        args=(job_id, body.target, body.tier,
              body.auto_approve, body.skip_osint, body.reset_dedup),
        kwargs={"phases": body.phases if body.phases else None,
                "credentials": body.credentials if body.credentials else None},
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
    default = REPORTS_DIR / f"scan_log_{job_id}.txt"
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
        log_file = _resolve_log_file(job_id)

        if not log_file.is_file():
            return {"lines": [], "total": 0}
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
        stripped = [line.rstrip("\r\n") for line in all_lines[-tail:]]
        return {"lines": stripped, "total": len(all_lines)}
    except Exception as e:
        import traceback
        logger.error(f"get_scan_logs error: {traceback.format_exc()}")
        return {"lines": [f"Error reading logs: {e}"], "total": 0}


@app.post("/api/scans/job/{job_id}/stop")
def stop_scan(job_id: str):
    """Write a stop signal file so the brain exits after the current phase."""
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
    """Cancel and dismiss a scan — removes it from active list and cleans up state files."""
    if job_id in _active_scans:
        job = _active_scans[job_id]
        target = job.get("target", "")
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

    return {"status": "cancelled", "job_id": job_id}


@app.post("/api/scans/kill-all")
def kill_all_scans():
    """Emergency kill switch — terminate all running scan processes and mark them cancelled."""
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
    """Resume a previously stopped scan from its last checkpoint."""
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
        "log_file": str(REPORTS_DIR / f"scan_log_{job_id}.txt"),
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
    """Return the complete scan log file."""
    log_file = _resolve_log_file(job_id)
    if not log_file.is_file():
        return {"lines": [], "total": 0}
    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()
    return {"lines": all_lines, "total": len(all_lines)}


@app.get("/api/scans/job/{job_id}/logs-download")
def download_scan_logs(job_id: str):
    """Download the complete scan log as a file."""
    from fastapi.responses import FileResponse
    log_file = _resolve_log_file(job_id)
    if not log_file.is_file():
        raise HTTPException(404, "Log file not found")
    return FileResponse(str(log_file), filename=f"scan_{job_id}_logs.txt", media_type="text/plain")


# ── WebSocket Live Feed ────────────────────────────────────────────────────

class ConnectionManager:
    """Manages WebSocket connections for live scan updates."""

    def __init__(self):
        self.active: dict = {}  # job_id -> set of WebSocket connections
        self._broadcast_lock = threading.Lock()

    async def connect(self, websocket: WebSocket, job_id: str):
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
    """Push progress/results to WS subscribers every 2 seconds."""
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
                "log_tail": [l.rstrip() for l in log_lines],
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
    """WebSocket endpoint for real-time scan updates."""
    import asyncio as _aio

    await ws_manager.connect(websocket, job_id)

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
    """Return the canonical summary report if available."""
    summary_path = REPORTS_DIR / "canonical_summary.json"
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"status": "no_canonical_report", "message": "Run a scan to generate canonical report"}


@app.get("/api/canonical/coverage")
def get_canonical_coverage():
    """Return coverage matrix state from the latest canonical report."""
    summary_path = REPORTS_DIR / "canonical_summary.json"
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("coverage", {})
    return {"status": "no_coverage_data"}


@app.get("/api/canonical/convergence")
def get_canonical_convergence():
    """Return convergence status from the latest canonical report."""
    summary_path = REPORTS_DIR / "canonical_summary.json"
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("convergence", {})
    return {"status": "no_convergence_data"}


@app.get("/api/canonical/attack-surface")
def get_canonical_attack_surface():
    """Return the canonical attack surface discovery summary."""
    summary_path = REPORTS_DIR / "canonical_summary.json"
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("discovery", {})
    return {"status": "no_attack_surface"}


@app.get("/api/canonical/learning")
def get_canonical_learning():
    """Return structured learning summary."""
    summary_path = REPORTS_DIR / "canonical_summary.json"
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("learning", {})
    return {"status": "no_learning_data"}


@app.get("/api/canonical/health")
def get_canonical_health():
    """Return target health status."""
    summary_path = REPORTS_DIR / "canonical_summary.json"
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("health", {})
    return {"status": "no_health_data"}


@app.get("/api/coverage/tracker")
def get_coverage_tracker():
    """Return honest per-test coverage tracking (Strix Pattern #2)."""
    tracker_path = REPORTS_DIR / "coverage_tracker.json"
    if tracker_path.exists():
        with open(tracker_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"status": "no_coverage_data"}


@app.get("/api/coverage/honest")
def get_honest_coverage():
    """Return honest coverage summary instead of inflated metrics."""
    tracker_path = REPORTS_DIR / "coverage_tracker.json"
    if tracker_path.exists():
        with open(tracker_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("report", {}).get("coverage", {"status": "no_coverage_data"})
    return {"status": "no_coverage_data"}


@app.get("/api/skills")
def list_skills():
    """Return loaded testing skills metadata."""
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
    """Export scan findings in SARIF 2.1.0 format."""
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
    """Export scan findings in GitLab DAST report format."""
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
    target: str
    interval_hours: int = 24
    tier: str = "POC"
    phases: list = None


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
    targets: list
    tier: str = "POC"
    max_parallel: int = 3


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
    """Returns a summary of ALL data collected and stored for a scan.
    Every DB table that holds scan-scoped data is queried here."""
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
    """Return parsed exploit markdown reports from reports/exploits/."""
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
    """Parse an exploit markdown report into structured data."""
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
    """Serve evidence screenshots/files from reports/evidence/."""
    import re
    if not re.match(r'^[\w\-\.]+$', filename):
        raise HTTPException(400, "Invalid filename")
    evidence_dir = REPORTS_DIR / "evidence"
    file_path = evidence_dir / filename
    if not file_path.exists():
        raise HTTPException(404, "Evidence file not found")
    from fastapi.responses import FileResponse
    media_type = "image/png" if filename.endswith(".png") else "application/octet-stream"
    return FileResponse(str(file_path), media_type=media_type)


@app.get("/api/evidence")
def list_evidence():
    """List all evidence files."""
    evidence_dir = REPORTS_DIR / "evidence"
    if not evidence_dir.exists():
        return []
    return [{"name": f.name, "size": f.stat().st_size, "type": f.suffix}
            for f in evidence_dir.iterdir() if f.is_file()]


@app.get("/api/scans/{scan_id}/executive-summary")
def get_executive_summary(scan_id: str):
    """Return the executive summary and full report metadata."""
    scan = ScanRepo.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    report = scan.get("report_data") or {}
    return {
        "executive_summary": report.get("executive_summary", ""),
        "metadata": report.get("metadata", {}),
        "scope": report.get("scope", {}),
    }


@app.get("/api/scans/{scan_id}/attack-chains")
async def get_attack_chains(scan_id: str):
    try:
        from core.database.pg_store import AttackChainRepo
        return AttackChainRepo.get_by_scan(scan_id)
    except Exception as e:
        return {"error": str(e), "chains": []}


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
    url: str
    metadata: dict = {}

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
    return _get_rag().stats()


@app.post("/api/rag/ingest/file")
async def rag_ingest_file(file_path: str = "", metadata: str = "{}"):
    """Ingest a local file. Pass file_path as query param."""
    if not file_path:
        raise HTTPException(status_code=400, detail="file_path required")
    rag = _get_rag()
    try:
        meta = json.loads(metadata) if metadata else {}
    except Exception:
        meta = {}
    result = await rag.ingest_file(file_path, metadata=meta)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


from fastapi import UploadFile, File, Form

@app.post("/api/rag/ingest/uploaded")
async def rag_ingest_uploaded(file: UploadFile = File(...), metadata: str = Form("{}")):
    """Ingest an uploaded file (PDF, txt, md, html, csv, json)."""
    import tempfile
    rag = _get_rag()
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
    result = await rag.ingest_file(tmp_path, metadata=meta)
    try:
        os.unlink(tmp_path)
    except Exception:
        pass
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/rag/ingest/text")
async def rag_ingest_text(body: RAGTextIngest):
    rag = _get_rag()
    return await rag.ingest_text(body.text, title=body.title, metadata=body.metadata)


@app.post("/api/rag/ingest/url")
async def rag_ingest_url(body: RAGURLIngest):
    rag = _get_rag()
    result = await rag.ingest_url(body.url, metadata=body.metadata)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/rag/ingest/search")
async def rag_ingest_search(body: RAGSearchIngest):
    """Search the web and ingest results into the knowledge base."""
    rag = _get_rag()
    return await rag.search_and_ingest(body.query, max_results=body.max_results)


@app.post("/api/rag/query")
async def rag_query(body: RAGQuery):
    """Query the knowledge base for relevant documents."""
    rag = _get_rag()
    docs = await rag.retrieve(
        body.query,
        top_k=body.top_k,
        category_filter=body.category if body.category else None,
    )
    return {"query": body.query, "results": docs, "count": len(docs)}


@app.delete("/api/rag/documents")
async def rag_delete_docs(body: RAGDelete):
    rag = _get_rag()
    deleted = await rag.delete_by_source(body.source_type, body.source_ref or None)
    return {"deleted": deleted}


@app.get("/api/rag/documents")
async def rag_list_documents(source_type: str = None, limit: int = 100, offset: int = 0):
    rag = _get_rag()
    docs = rag.list_documents(source_type=source_type, limit=limit, offset=offset)
    return {"documents": docs, "count": len(docs)}


@app.delete("/api/rag/documents/{doc_id}")
async def rag_delete_single_doc(doc_id: str):
    rag = _get_rag()
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
        """Serve index.html for all non-API routes (SPA client-side routing)."""
        file = _FRONTEND_DIR / full_path
        if file.exists() and file.is_file():
            return _SFR(str(file))
        return _SFR(str(_FRONTEND_DIR / "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8903)
