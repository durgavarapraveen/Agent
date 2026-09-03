"""AntiGravity Dashboard API — PostgreSQL-backed, no flat files or SQLite."""

import json
import os
import subprocess
import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

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
    make_run_id,
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
                                   error=job.get("error", ""), command=job.get("command", ""))
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
            if pid and not _is_pid_alive(pid):
                ScanRepo.update_status(sid, "completed")
                continue
            _active_scans[sid] = {
                "job_id": sid, "target": scan["target"], "tier": scan.get("tier", "POC"),
                "status": scan["status"], "started_at": str(scan.get("started_at", "")),
                "finished_at": str(scan.get("finished_at", "")), "pid": pid,
                "exit_code": scan.get("exit_code"), "error": scan.get("error", ""),
                "log_file": scan.get("log_file", str(REPORTS_DIR / f"scan_log_{sid}.txt")),
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
            scans.append({
                "scan_id": s["scan_id"],
                "target": s.get("target", "unknown"),
                "timestamp": str(s.get("started_at", "")),
                "duration_seconds": s.get("duration_seconds", 0),
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
    return TargetRepo.list_all()


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


@app.get("/api/scans/live-progress")
def get_live_progress():
    """Return live progress from PostgreSQL."""
    try:
        data = LiveDataRepo.get_progress()
        if data:
            return data
    except Exception:
        pass
    return {}


@app.get("/api/scans/live-results")
def get_live_results():
    """Return structured live results from PostgreSQL."""
    try:
        data = LiveDataRepo.get_results()
        if data:
            try:
                v2 = FindingV2Repo.list_confirmed()
                for f in v2:
                    if not any(v.get("title") == f.get("title") for v in data.get("vulnerabilities", [])):
                        data.setdefault("vulnerabilities", []).append(f)
            except Exception:
                pass
            return data
    except Exception:
        pass
    return {
        "recon": {"subdomains": [], "endpoints": [], "technologies": {}, "ports": [], "ips": []},
        "vulnerabilities": [], "exploits": [], "captured_requests": [],
    }


@app.get("/api/scans/active")
def list_active_scans():
    return list(_active_scans.values())


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = ScanRepo.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    vulns = VulnRepo.get_by_scan(scan_id)
    report = scan.get("report_data") or {}
    meta = report.get("metadata", {"target": scan.get("target", ""), "timestamp": str(scan.get("started_at", ""))})
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
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in vulns:
        sev = (v.get("severity") or "INFO").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    passed = sum(1 for v in vulns if v.get("status") == "CONFIRMED")
    failed = sum(1 for v in vulns if v.get("status") == "REJECTED")
    unconfirmed = len(vulns) - passed - failed
    return {
        "scan_id": scan_id, "metadata": meta, "scope": scope,
        "vulnerabilities": vulns, "severity_counts": severity_counts,
        "test_results": {"passed": passed, "failed": failed, "unconfirmed": unconfirmed},
        "context": {
            "subdomains": context.get("subdomains", []),
            "technologies": context.get("technologies", {}),
            "endpoints": context.get("endpoints", []),
            "captured_requests": context.get("captured_requests", []),
            "subdomain_summary": context.get("subdomain_summary", {}),
            "osint": context.get("osint", {}),
            "ports": context.get("ports", []),
            "ips": context.get("ips", []),
            "ssl_info": context.get("ssl_info", {}),
            "headers": context.get("headers", {}),
            "directories": context.get("directories", []),
            "secrets": context.get("secrets", []),
        },
        "exploits": [], "checkpoints": [],
    }


@app.get("/api/scans/{scan_id}/recon")
def get_recon(scan_id: str):
    """Full recon intelligence collected for a scan (live during recon, and after)."""
    try:
        from core.database.pg_store import ReconRepo
        return ReconRepo.get(scan_id)
    except Exception as e:
        raise HTTPException(500, f"recon data unavailable: {e}")


@app.get("/api/scans/{scan_id}/vulnerabilities")
def get_vulnerabilities(scan_id: str):
    return VulnRepo.get_by_scan(scan_id)


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
    return {
        "total_scans": len(scans),
        "total_vulnerabilities": total_vulns,
        "total_critical": total_critical,
        "total_high": total_high,
        "total_medium": total_medium,
        "total_low": total_low,
        "total_info": total_info,
        "unique_targets": len(targets),
        "targets": list(targets),
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
        ScanRepo.create(job_id, body.target, body.tier)
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


@app.get("/api/scans/job/{job_id}/logs")
def get_scan_logs(job_id: str, tail: int = 100):
    log_file = None
    if job_id in _active_scans:
        log_file = Path(_active_scans[job_id]["log_file"])
    else:
        raise HTTPException(404, "Job not found")

    if not log_file or not log_file.exists():
        return {"lines": [], "total": 0}
    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()
    return {"lines": all_lines[-tail:], "total": len(all_lines)}


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
    if job_id not in _active_scans:
        raise HTTPException(404, "Job not found")
    log_file = Path(_active_scans[job_id]["log_file"])
    if not log_file.exists():
        return {"lines": [], "total": 0}
    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()
    return {"lines": all_lines, "total": len(all_lines)}


@app.get("/api/scans/job/{job_id}/logs-download")
def download_scan_logs(job_id: str):
    """Download the complete scan log as a file."""
    from fastapi.responses import FileResponse
    log_file = None
    if job_id in _active_scans:
        log_file = Path(_active_scans[job_id]["log_file"])
    if not log_file or not log_file.exists():
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
    uvicorn.run(app, host="0.0.0.0", port=8900)
