"""
Unified PostgreSQL data layer — replaces all JSON files and SQLite databases.
"""

import hashlib
import json
import logging
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from contextlib import contextmanager

import psycopg2
import psycopg2.extras

from core.memory.database import DatabaseManager

logger = logging.getLogger(__name__)


def _target_slug(target: str) -> str:
    s = re.sub(r"^https?://", "", str(target or "target")).strip("/")
    s = re.sub(r"[^A-Za-z0-9._-]", "_", s)
    return (s or "target")[:60]


def make_run_id(target: str) -> str:
    """
    Canonical, globally-unique run identifier for one scan of one URL.

    Format: <target-slug>_<UTC-timestamp>_<random>. Because it embeds a UTC
    timestamp AND a random suffix, two runs of the SAME url — even in the same
    second — always get distinct ids, so their results never collide or merge.
    This single id is used across the whole DB (scans, vulnerabilities,
    review_queue, live data) as the run's identity.
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{_target_slug(target)}_{ts}_{uuid.uuid4().hex[:8]}"


def finding_uid(scan_id: str, v: Dict[str, Any]) -> str:
    """
    Deterministic finding id, ALWAYS namespaced by the run's scan_id.

    Within one run the same finding maps to the same id (intra-run dedup); across
    runs the scan_id differs, so the same finding produces a different id and a
    separate row — runs never overwrite each other.
    """
    content = "|".join([
        str(v.get("type") or v.get("vuln_type") or "").upper(),
        str(v.get("title") or "").lower().strip(),
        str(v.get("location") or v.get("target") or v.get("affected_endpoint") or "").lower(),
        str(v.get("cve_id") or "").upper(),
    ])
    h = hashlib.sha1(content.encode("utf-8", "ignore")).hexdigest()[:16]
    return f"{scan_id}::{h}"


def _init_schema():
    """Create all tables if they don't exist."""
    with DatabaseManager.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS targets (
                    id SERIAL PRIMARY KEY,
                    url TEXT NOT NULL UNIQUE,
                    scope TEXT DEFAULT '',
                    notes TEXT DEFAULT '',
                    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_scanned TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    tier TEXT DEFAULT 'POC',
                    status TEXT DEFAULT 'pending',
                    started_at TIMESTAMPTZ DEFAULT NOW(),
                    finished_at TIMESTAMPTZ,
                    duration_seconds REAL DEFAULT 0,
                    agents_used INT DEFAULT 0,
                    pid INT,
                    exit_code INT,
                    command TEXT DEFAULT '',
                    log_file TEXT DEFAULT '',
                    error TEXT DEFAULT '',
                    report_data JSONB DEFAULT '{}'::jsonb,
                    metadata JSONB DEFAULT '{}'::jsonb
                );

                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
                    finding_id TEXT UNIQUE,
                    title TEXT NOT NULL,
                    type TEXT DEFAULT '',
                    severity TEXT DEFAULT 'INFO',
                    status TEXT DEFAULT 'UNCONFIRMED',
                    target TEXT DEFAULT '',
                    location TEXT DEFAULT '',
                    details TEXT DEFAULT '',
                    proof TEXT DEFAULT '',
                    remediation TEXT DEFAULT '',
                    tool TEXT DEFAULT '',
                    cwe_id TEXT DEFAULT '',
                    cve_id TEXT DEFAULT '',
                    confidence_score REAL DEFAULT 0.5,
                    extra JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS exploit_results (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
                    title TEXT NOT NULL,
                    type TEXT DEFAULT '',
                    target TEXT DEFAULT '',
                    status TEXT DEFAULT '',
                    details JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS live_progress (
                    id INT PRIMARY KEY DEFAULT 1,
                    scan_id TEXT DEFAULT '',
                    phase TEXT DEFAULT '',
                    progress REAL DEFAULT 0,
                    status TEXT DEFAULT '',
                    data JSONB DEFAULT '{}'::jsonb,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS live_results (
                    id INT PRIMARY KEY DEFAULT 1,
                    scan_id TEXT DEFAULT '',
                    data JSONB DEFAULT '{}'::jsonb,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS findings_v2 (
                    finding_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    severity TEXT DEFAULT 'MEDIUM',
                    affected_endpoint TEXT DEFAULT '',
                    state TEXT DEFAULT '',
                    evidence_ids TEXT[] DEFAULT '{}',
                    extra JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS findings_dedup (
                    signature TEXT PRIMARY KEY,
                    tool TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    data_repr TEXT NOT NULL,
                    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    count INT DEFAULT 1,
                    task_id TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id SERIAL PRIMARY KEY,
                    action TEXT NOT NULL,
                    target TEXT DEFAULT '',
                    details JSONB DEFAULT '{}'::jsonb,
                    previous_hash TEXT DEFAULT '',
                    current_hash TEXT DEFAULT '',
                    timestamp TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS execution_audit (
                    id SERIAL PRIMARY KEY,
                    action TEXT NOT NULL,
                    params JSONB DEFAULT '{}'::jsonb,
                    result JSONB DEFAULT '{}'::jsonb,
                    hash TEXT DEFAULT '',
                    timestamp TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS scan_schedules (
                    schedule_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    tier TEXT DEFAULT 'POC',
                    interval_hours INT DEFAULT 24,
                    enabled BOOLEAN DEFAULT TRUE,
                    phases TEXT[] DEFAULT '{RECON,ACTIVE_SCANNING,EXPLOITATION,REPORTING}',
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    last_run TIMESTAMPTZ,
                    next_run TIMESTAMPTZ DEFAULT NOW(),
                    last_report TEXT DEFAULT '',
                    run_count INT DEFAULT 0,
                    last_delta JSONB DEFAULT '{}'::jsonb
                );

                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    status TEXT DEFAULT 'running',
                    tier TEXT DEFAULT 'POC',
                    total_targets INT DEFAULT 0,
                    report JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    finished_at TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS authorized_scopes (
                    scope_id TEXT PRIMARY KEY,
                    target_cidr TEXT DEFAULT '',
                    target_domain TEXT DEFAULT '',
                    authorization_date TEXT DEFAULT '',
                    expiry_date TEXT DEFAULT '',
                    document_hash TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS baseline_state (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT,
                    target TEXT,
                    item_type TEXT DEFAULT '',
                    key_identifier TEXT DEFAULT '',
                    banner_hash TEXT DEFAULT '',
                    content_length_hash TEXT DEFAULT '',
                    header_hash TEXT DEFAULT '',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS scan_history (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT DEFAULT '',
                    scan_date TEXT DEFAULT '',
                    data JSONB DEFAULT '{}'::jsonb
                );

                CREATE TABLE IF NOT EXISTS cve_cache (
                    cve_id TEXT PRIMARY KEY,
                    cvss REAL DEFAULT 0,
                    severity TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    cwes TEXT DEFAULT '[]',
                    references_json TEXT DEFAULT '[]',
                    published TEXT DEFAULT '',
                    modified TEXT DEFAULT '',
                    product TEXT DEFAULT '',
                    version TEXT DEFAULT '',
                    fetched_at REAL DEFAULT 0,
                    ttl INT DEFAULT 86400
                );

                CREATE TABLE IF NOT EXISTS exploit_cache (
                    id SERIAL PRIMARY KEY,
                    cve_id TEXT DEFAULT '',
                    keyword TEXT DEFAULT '',
                    name TEXT DEFAULT '',
                    url TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    stars INT DEFAULT 0,
                    language TEXT DEFAULT '',
                    reliability REAL DEFAULT 0,
                    clone_url TEXT DEFAULT '',
                    fetched_at REAL DEFAULT 0,
                    ttl INT DEFAULT 86400
                );

                CREATE TABLE IF NOT EXISTS mitre_cache (
                    technique_id TEXT PRIMARY KEY,
                    name TEXT DEFAULT '',
                    tactic TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    mitigations TEXT DEFAULT '[]',
                    detection TEXT DEFAULT '[]',
                    fetched_at REAL DEFAULT 0,
                    ttl INT DEFAULT 604800
                );

                CREATE TABLE IF NOT EXISTS search_cache (
                    query_key TEXT PRIMARY KEY,
                    result_json TEXT DEFAULT '',
                    source TEXT DEFAULT '',
                    fetched_at REAL DEFAULT 0,
                    ttl INT DEFAULT 3600
                );

                CREATE TABLE IF NOT EXISTS decision_log (
                    id SERIAL PRIMARY KEY,
                    timestamp REAL DEFAULT 0,
                    phase TEXT DEFAULT '',
                    decision TEXT DEFAULT '',
                    context TEXT DEFAULT '',
                    result TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS vuln_intel (
                    id TEXT PRIMARY KEY,
                    cvss_v3_base_score REAL DEFAULT 0,
                    cvss_v3_vector TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS experiences (
                    experience_id TEXT PRIMARY KEY,
                    test_type TEXT DEFAULT '',
                    target_fingerprint TEXT DEFAULT '',
                    endpoint_pattern TEXT DEFAULT '',
                    parameter_type TEXT DEFAULT '',
                    identity_context TEXT DEFAULT '',
                    strategy_id TEXT DEFAULT '',
                    tool TEXT DEFAULT '',
                    outcome TEXT DEFAULT '',
                    evidence_quality REAL DEFAULT 0,
                    cost_ms REAL DEFAULT 0,
                    latency_ms REAL DEFAULT 0,
                    failure_reason TEXT DEFAULT '',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS strategies (
                    strategy_id TEXT PRIMARY KEY,
                    test_type TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    tool TEXT DEFAULT '',
                    prerequisites TEXT DEFAULT '',
                    success_rate_global REAL DEFAULT 0,
                    success_rate_target REAL DEFAULT 0,
                    success_rate_type REAL DEFAULT 0,
                    success_rate_recent REAL DEFAULT 0,
                    average_cost_ms REAL DEFAULT 0,
                    average_duration_ms REAL DEFAULT 0,
                    evidence_quality REAL DEFAULT 0,
                    failure_count INT DEFAULT 0,
                    last_used TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS llm_failures (
                    failure_id TEXT PRIMARY KEY,
                    provider TEXT DEFAULT '',
                    model TEXT DEFAULT '',
                    task TEXT DEFAULT '',
                    prompt_category TEXT DEFAULT '',
                    target_fingerprint TEXT DEFAULT '',
                    failure_type TEXT DEFAULT '',
                    failure_reason TEXT DEFAULT '',
                    retry_count INT DEFAULT 0,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS recon_data (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT DEFAULT '',
                    data JSONB DEFAULT '{}'::jsonb,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS review_queue (
                    id TEXT PRIMARY KEY,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    target TEXT DEFAULT '',
                    title TEXT NOT NULL,
                    status TEXT DEFAULT 'NEEDS_MANUAL',
                    category TEXT DEFAULT '',
                    severity TEXT DEFAULT '',
                    steps INT DEFAULT 0,
                    evidence TEXT DEFAULT '',
                    tried_summary TEXT DEFAULT '',
                    manual_guidance TEXT DEFAULT '',
                    history JSONB DEFAULT '[]'::jsonb,
                    scan_id TEXT DEFAULT '',
                    resolved_at TIMESTAMPTZ,
                    resolution_note TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS tool_outputs (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    operation TEXT DEFAULT '',
                    target TEXT DEFAULT '',
                    command TEXT DEFAULT '',
                    stdout TEXT DEFAULT '',
                    stderr TEXT DEFAULT '',
                    exit_code INT DEFAULT -1,
                    duration_s REAL DEFAULT 0,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS agent_activity (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    timestamp DOUBLE PRECISION NOT NULL,
                    action TEXT NOT NULL DEFAULT '',
                    title TEXT NOT NULL DEFAULT '',
                    detail TEXT DEFAULT '',
                    tool TEXT DEFAULT '',
                    target TEXT DEFAULT '',
                    phase TEXT DEFAULT '',
                    input_data TEXT DEFAULT '',
                    output_data TEXT DEFAULT '',
                    status TEXT DEFAULT 'ok',
                    duration_s REAL DEFAULT 0,
                    metadata JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE INDEX IF NOT EXISTS idx_tool_outputs_scan ON tool_outputs(scan_id);
                CREATE INDEX IF NOT EXISTS idx_activity_scan ON agent_activity(scan_id);
                CREATE INDEX IF NOT EXISTS idx_activity_ts ON agent_activity(timestamp);
                CREATE INDEX IF NOT EXISTS idx_review_status ON review_queue(status);
                CREATE INDEX IF NOT EXISTS idx_review_created ON review_queue(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
                CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
                CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
                CREATE INDEX IF NOT EXISTS idx_findings_v2_state ON findings_v2(state);
                CREATE INDEX IF NOT EXISTS idx_baseline_target ON baseline_state(target);
                CREATE INDEX IF NOT EXISTS idx_cve_product ON cve_cache(product, version);
                CREATE INDEX IF NOT EXISTS idx_exploit_cve ON exploit_cache(cve_id);
                CREATE INDEX IF NOT EXISTS idx_exploit_kw ON exploit_cache(keyword);
            """)
            conn.commit()
    logger.info("[PGStore] Schema initialized")


class TargetRepo:
    """CRUD for authorized scan targets."""

    @staticmethod
    def list_all() -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM targets ORDER BY added_at DESC")
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def add(url: str, scope: str = "", notes: str = "") -> Dict:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                try:
                    cur.execute(
                        "INSERT INTO targets (url, scope, notes) VALUES (%s, %s, %s) RETURNING id",
                        (url, scope, notes)
                    )
                    conn.commit()
                    return {"status": "ok", "id": cur.fetchone()[0]}
                except psycopg2.IntegrityError:
                    conn.rollback()
                    return {"status": "error", "detail": "Target already exists"}

    @staticmethod
    def delete(target_id: int):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM targets WHERE id = %s", (target_id,))
                conn.commit()

    @staticmethod
    def update_last_scanned(url: str):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE targets SET last_scanned = NOW() WHERE url = %s", (url,))
                conn.commit()


class ScanRepo:
    """CRUD for scan jobs and their results."""

    @staticmethod
    def create(scan_id: str, target: str, tier: str = "POC", **kwargs) -> str:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO scans (scan_id, target, tier, status, log_file, command)
                    VALUES (%s, %s, %s, 'starting', %s, %s)
                    ON CONFLICT (scan_id) DO UPDATE SET status = 'starting', started_at = NOW()
                """, (scan_id, target, tier,
                      kwargs.get("log_file", ""), kwargs.get("command", "")))
                conn.commit()
        return scan_id

    @staticmethod
    def update_status(scan_id: str, status: str, **kwargs):
        fields = ["status = %s"]
        values = [status]
        for k in ("pid", "exit_code", "error", "command", "log_file"):
            if k in kwargs:
                fields.append(f"{k} = %s")
                values.append(kwargs[k])
        if status in ("completed", "failed", "stopped"):
            fields.append("finished_at = NOW()")
        values.append(scan_id)
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(f"UPDATE scans SET {', '.join(fields)} WHERE scan_id = %s", values)
                conn.commit()

    @staticmethod
    def save_report(scan_id: str, report_data: Dict):
        meta = report_data.get("metadata", {})
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE scans SET report_data = %s, metadata = %s,
                    duration_seconds = %s, agents_used = %s
                    WHERE scan_id = %s
                """, (json.dumps(report_data, default=str),
                      json.dumps(meta, default=str),
                      meta.get("duration_seconds", 0),
                      meta.get("agents_used", 0),
                      scan_id))
                conn.commit()

    @staticmethod
    def get(scan_id: str) -> Optional[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM scans WHERE scan_id = %s", (scan_id,))
                row = cur.fetchone()
                return dict(row) if row else None

    @staticmethod
    def list_all() -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM scans ORDER BY started_at DESC")
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def get_active() -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM scans WHERE status IN ('running', 'starting', 'stopping') "
                    "OR (status IN ('stopped', 'completed', 'failed') "
                    "    AND started_at > NOW() - INTERVAL '1 hour') "
                    "ORDER BY CASE WHEN status IN ('running', 'starting') THEN 0 "
                    "WHEN status = 'stopping' THEN 1 ELSE 2 END, started_at DESC"
                )
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def get_by_target(target: str) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM scans WHERE target = %s ORDER BY started_at DESC", (target,))
                return [dict(r) for r in cur.fetchall()]


class VulnRepo:
    """CRUD for vulnerabilities linked to scans."""

    @staticmethod
    def bulk_insert(scan_id: str, vulns: List[Dict]):
        if not vulns:
            return
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                for v in vulns:
                    # ALWAYS scan-scoped so two runs of the same URL never merge;
                    # any upstream finding_id is preserved in `extra` for traceability.
                    if v.get("finding_id"):
                        v.setdefault("orig_finding_id", v["finding_id"])
                    fid = finding_uid(scan_id, v)
                    cur.execute("""
                        INSERT INTO vulnerabilities
                        (scan_id, finding_id, title, type, severity, status, target, location,
                         details, proof, remediation, tool, cwe_id, cve_id, confidence_score, extra)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (finding_id) DO UPDATE SET
                            severity = EXCLUDED.severity, status = EXCLUDED.status,
                            confidence_score = EXCLUDED.confidence_score, extra = EXCLUDED.extra
                    """, (scan_id, fid, v.get("title", ""), v.get("type", ""),
                          v.get("severity", "INFO"), v.get("status", "UNCONFIRMED"),
                          v.get("target", ""), v.get("location", ""),
                          v.get("details", ""), str(v.get("proof", "")),
                          v.get("remediation", ""), v.get("tool", ""),
                          v.get("cwe_id", ""), v.get("cve_id", ""),
                          v.get("confidence_score", 0.5),
                          json.dumps({k: v.get(k) for k in v
                                      if k not in ("title", "type", "severity", "status",
                                                    "target", "location", "details", "proof",
                                                    "remediation", "tool", "cwe_id", "cve_id",
                                                    "confidence_score", "finding_id")},
                                     default=str)))
                conn.commit()

    @staticmethod
    def get_by_scan(scan_id: str) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM vulnerabilities WHERE scan_id = %s ORDER BY severity, title", (scan_id,))
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def get_all() -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM vulnerabilities ORDER BY created_at DESC LIMIT 1000")
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def compare_scans(scan_a: str, scan_b: str) -> Dict:
        vulns_a = {v["title"]: v for v in VulnRepo.get_by_scan(scan_a)}
        vulns_b = {v["title"]: v for v in VulnRepo.get_by_scan(scan_b)}
        titles_a, titles_b = set(vulns_a.keys()), set(vulns_b.keys())

        new = [{"title": t, "severity": vulns_b[t]["severity"], "type": vulns_b[t]["type"]}
               for t in titles_b - titles_a]
        fixed = [{"title": t, "severity": vulns_a[t]["severity"], "type": vulns_a[t]["type"]}
                 for t in titles_a - titles_b]
        sev_changes = []
        for t in titles_a & titles_b:
            if vulns_a[t]["severity"] != vulns_b[t]["severity"]:
                sev_changes.append({"title": t, "old": vulns_a[t]["severity"], "new": vulns_b[t]["severity"]})

        return {
            "new_in_b": new, "fixed_in_b": fixed,
            "common": list(titles_a & titles_b),
            "severity_changes": sev_changes,
            "delta_summary": {"new": len(new), "fixed": len(fixed),
                              "unchanged": len(titles_a & titles_b), "severity_changed": len(sev_changes)},
        }


class LiveDataRepo:
    """Stores live progress and live results (replaces JSON files)."""

    @staticmethod
    def upsert_progress(scan_id: str, data: Dict):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO live_progress (id, scan_id, phase, progress, status, data, updated_at)
                    VALUES (1, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (id) DO UPDATE SET
                        scan_id = EXCLUDED.scan_id, phase = EXCLUDED.phase,
                        progress = EXCLUDED.progress, status = EXCLUDED.status,
                        data = EXCLUDED.data, updated_at = NOW()
                """, (scan_id,
                      data.get("phase", ""), data.get("progress", 0),
                      data.get("status", ""), json.dumps(data, default=str)))
                conn.commit()

    @staticmethod
    def get_progress() -> Dict:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM live_progress WHERE id = 1")
                row = cur.fetchone()
                if row:
                    d = dict(row)
                    return d.get("data") if isinstance(d.get("data"), dict) else d
                return {}

    @staticmethod
    def upsert_results(scan_id: str, data: Dict):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO live_results (id, scan_id, data, updated_at)
                    VALUES (1, %s, %s, NOW())
                    ON CONFLICT (id) DO UPDATE SET
                        scan_id = EXCLUDED.scan_id, data = EXCLUDED.data, updated_at = NOW()
                """, (scan_id, json.dumps(data, default=str)))
                conn.commit()

    @staticmethod
    def get_results() -> Dict:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM live_results WHERE id = 1")
                row = cur.fetchone()
                if row and isinstance(row.get("data"), dict):
                    return row["data"]
                return {
                    "recon": {"subdomains": [], "endpoints": [], "technologies": {}, "ports": [], "ips": []},
                    "vulnerabilities": [], "exploits": [], "captured_requests": [],
                }


class FindingV2Repo:
    """Replaces findings_v2.json and the JSON-backed FindingStore."""

    @staticmethod
    def store(finding_id: str, title: str, severity: str = "MEDIUM",
              state: str = "", endpoint: str = "", description: str = "",
              evidence_ids: list = None, extra: dict = None):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO findings_v2 (finding_id, title, description, severity, affected_endpoint,
                                             state, evidence_ids, extra)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (finding_id) DO UPDATE SET
                        state = EXCLUDED.state, severity = EXCLUDED.severity, extra = EXCLUDED.extra
                """, (finding_id, title, description, severity, endpoint,
                      state, evidence_ids or [], json.dumps(extra or {}, default=str)))
                conn.commit()

    @staticmethod
    def list_all() -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM findings_v2 ORDER BY created_at DESC")
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def list_confirmed() -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM findings_v2 WHERE state = 'confirmed' ORDER BY created_at DESC")
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def get(finding_id: str) -> Optional[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM findings_v2 WHERE finding_id = %s", (finding_id,))
                row = cur.fetchone()
                return dict(row) if row else None


class DedupRepo:
    """Replaces SQLite dedup tracker."""

    @staticmethod
    def check_and_insert(signature: str, tool: str, finding_type: str,
                         data_repr: str, task_id: str = "") -> bool:
        """Returns True if new (not duplicate), False if duplicate."""
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count FROM findings_dedup WHERE signature = %s", (signature,))
                row = cur.fetchone()
                if row:
                    cur.execute("""
                        UPDATE findings_dedup SET last_seen = NOW(), count = count + 1, task_id = %s
                        WHERE signature = %s
                    """, (task_id, signature))
                    conn.commit()
                    return False
                else:
                    cur.execute("""
                        INSERT INTO findings_dedup (signature, tool, finding_type, data_repr, task_id)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (signature, tool, finding_type, data_repr, task_id))
                    conn.commit()
                    return True

    @staticmethod
    def reset_all():
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM findings_dedup")
                conn.commit()


class AuditRepo:
    """Replaces JSONL audit log files."""

    @staticmethod
    def log_event(action: str, target: str = "", details: dict = None,
                  previous_hash: str = "", current_hash: str = ""):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO audit_log (action, target, details, previous_hash, current_hash)
                    VALUES (%s, %s, %s, %s, %s)
                """, (action, target, json.dumps(details or {}, default=str),
                      previous_hash, current_hash))
                conn.commit()

    @staticmethod
    def get_recent(limit: int = 200) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT %s", (limit,))
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def log_execution(action: str, params: dict = None, result: dict = None, hash_val: str = ""):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO execution_audit (action, params, result, hash)
                    VALUES (%s, %s, %s, %s)
                """, (action, json.dumps(params or {}, default=str),
                      json.dumps(result or {}, default=str), hash_val))
                conn.commit()

    @staticmethod
    def get_execution_log(limit: int = 200) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM execution_audit ORDER BY timestamp DESC LIMIT %s", (limit,))
                return [dict(r) for r in cur.fetchall()]


class ScheduleRepo:
    """Replaces scan_schedules.json."""

    @staticmethod
    def upsert(schedule_id: str, target: str, tier: str = "POC",
               interval_hours: int = 24, phases: list = None):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO scan_schedules (schedule_id, target, tier, interval_hours, phases)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (schedule_id) DO UPDATE SET
                        tier = EXCLUDED.tier, interval_hours = EXCLUDED.interval_hours
                """, (schedule_id, target, tier, interval_hours,
                      phases or ["RECON", "ACTIVE_SCANNING", "EXPLOITATION", "REPORTING"]))
                conn.commit()

    @staticmethod
    def list_all() -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM scan_schedules ORDER BY created_at DESC")
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def delete(schedule_id: str):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM scan_schedules WHERE schedule_id = %s", (schedule_id,))
                conn.commit()

    @staticmethod
    def toggle(schedule_id: str) -> bool:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE scan_schedules SET enabled = NOT enabled WHERE schedule_id = %s RETURNING enabled", (schedule_id,))
                row = cur.fetchone()
                conn.commit()
                return row[0] if row else False

    @staticmethod
    def update_last_run(schedule_id: str, last_report: str = "", delta: dict = None):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE scan_schedules SET
                        last_run = NOW(),
                        next_run = NOW() + (interval_hours || ' hours')::INTERVAL,
                        run_count = run_count + 1,
                        last_report = %s,
                        last_delta = %s
                    WHERE schedule_id = %s
                """, (last_report, json.dumps(delta or {}, default=str), schedule_id))
                conn.commit()


class ReconRepo:
    """Full recon intelligence per scan (infrastructure, tech, endpoints, OSINT, …)
    so the user can see exactly what recon collected — updated live during the scan."""

    @staticmethod
    def save(scan_id: str, target: str, data: Dict) -> None:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO recon_data (scan_id, target, data, updated_at)
                    VALUES (%s, %s, %s, NOW())
                    ON CONFLICT (scan_id) DO UPDATE SET
                        data = EXCLUDED.data, target = EXCLUDED.target, updated_at = NOW()
                """, (scan_id, target, json.dumps(data, default=str)))
                conn.commit()

    @staticmethod
    def get(scan_id: str) -> Dict:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM recon_data WHERE scan_id = %s", (scan_id,))
                row = cur.fetchone()
                if row and isinstance(row.get("data"), dict):
                    return row["data"]
                return {}


class ToolOutputRepo:
    """Per-tool raw stdout/stderr persisted for UI display and debugging."""

    @staticmethod
    def save(scan_id: str, tool_name: str, operation: str, target: str,
             command: str, stdout: str, stderr: str, exit_code: int,
             duration_s: float = 0) -> None:
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO tool_outputs
                        (scan_id, tool_name, operation, target, command,
                         stdout, stderr, exit_code, duration_s)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """, (scan_id, tool_name, operation, target,
                          command[:2000], stdout[:50000], stderr[:10000],
                          exit_code, duration_s))
                    conn.commit()
        except Exception:
            pass

    @staticmethod
    def list_by_scan(scan_id: str) -> List[Dict]:
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("""
                        SELECT id, tool_name, operation, target, command,
                               stdout, stderr, exit_code, duration_s, created_at
                        FROM tool_outputs WHERE scan_id = %s
                        ORDER BY created_at ASC
                    """, (scan_id,))
                    return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []


class ActivityLogRepo:
    """Read-only timeline of what the agent did during a scan."""

    @staticmethod
    def insert(rec: Dict) -> None:
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO agent_activity
                        (id, scan_id, timestamp, action, title, detail, tool, target,
                         phase, input_data, output_data, status, duration_s, metadata)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (id) DO NOTHING
                    """, (rec["id"], rec["scan_id"], rec["timestamp"],
                          rec.get("action", ""), rec.get("title", ""),
                          rec.get("detail", ""), rec.get("tool", ""),
                          rec.get("target", ""), rec.get("phase", ""),
                          rec.get("input_data", ""), rec.get("output_data", ""),
                          rec.get("status", "ok"), rec.get("duration_s", 0),
                          json.dumps(rec.get("metadata", {}), default=str)))
                    conn.commit()
        except Exception:
            pass

    @staticmethod
    def list_by_scan(scan_id: str, limit: int = 500) -> List[Dict]:
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("""
                        SELECT id, scan_id, timestamp, action, title, detail, tool, target,
                               phase, input_data, output_data, status, duration_s, metadata,
                               created_at
                        FROM agent_activity WHERE scan_id = %s
                        ORDER BY timestamp ASC LIMIT %s
                    """, (scan_id, limit))
                    rows = [dict(r) for r in cur.fetchall()]
                    for r in rows:
                        if "created_at" in r:
                            r["created_at"] = str(r["created_at"])
                    return rows
        except Exception:
            return []


class ReviewRepo:
    """Human review queue — agent successes to showcase + failures to pentest manually."""

    @staticmethod
    def record(rec: Dict) -> Dict:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO review_queue
                    (id, target, title, status, category, severity, steps, evidence,
                     tried_summary, manual_guidance, history, scan_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (id) DO NOTHING
                """, (rec["id"], rec.get("target", ""), rec.get("title", ""),
                      rec.get("status", "NEEDS_MANUAL"), rec.get("category", ""),
                      rec.get("severity", ""), int(rec.get("steps", 0)),
                      rec.get("evidence", ""), rec.get("tried_summary", ""),
                      rec.get("manual_guidance", ""),
                      json.dumps(rec.get("history", []), default=str),
                      rec.get("scan_id", "")))
                conn.commit()
        return rec

    @staticmethod
    def all(limit: int = 200) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM review_queue ORDER BY created_at DESC LIMIT %s", (limit,))
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def by_status(status: str, limit: int = 200) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM review_queue WHERE status = %s ORDER BY created_at DESC LIMIT %s",
                            (status, limit))
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def summary() -> Dict:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT status, COUNT(*) FROM review_queue GROUP BY status")
                counts = {row[0]: row[1] for row in cur.fetchall()}
        return {
            "total": sum(counts.values()),
            "success": counts.get("SUCCESS", 0),
            "needs_manual": counts.get("NEEDS_MANUAL", 0),
            "partial": counts.get("PARTIAL", 0),
            "resolved": counts.get("RESOLVED", 0),
        }

    @staticmethod
    def resolve(record_id: str, note: str = "") -> bool:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE review_queue SET status = 'RESOLVED', resolved_at = NOW(),
                        resolution_note = %s WHERE id = %s
                """, (note[:500], record_id))
                updated = cur.rowcount
                conn.commit()
                return updated > 0


class CampaignRepo:
    """Replaces campaign JSON files."""

    @staticmethod
    def create(campaign_id: str, tier: str, total_targets: int):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO campaigns (campaign_id, tier, total_targets)
                    VALUES (%s, %s, %s)
                """, (campaign_id, tier, total_targets))
                conn.commit()

    @staticmethod
    def finish(campaign_id: str, report: Dict):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE campaigns SET status = 'completed', report = %s, finished_at = NOW()
                    WHERE campaign_id = %s
                """, (json.dumps(report, default=str), campaign_id))
                conn.commit()

    @staticmethod
    def list_all() -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM campaigns ORDER BY created_at DESC")
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def get(campaign_id: str) -> Optional[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM campaigns WHERE campaign_id = %s", (campaign_id,))
                row = cur.fetchone()
                return dict(row) if row else None

    @staticmethod
    def get_progress() -> Dict:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM campaigns WHERE status = 'running' ORDER BY created_at DESC LIMIT 1")
                row = cur.fetchone()
                return dict(row) if row else {}
