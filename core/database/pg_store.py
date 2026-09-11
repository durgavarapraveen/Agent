
import hashlib
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

import psycopg2
import psycopg2.extras

from core.memory.database import DatabaseManager
from core.utils.sanitize import safe_json_dumps

logger = logging.getLogger(__name__)

# All jsonb writes go through safe_json_dumps so NUL/control bytes from binary
# tool output (\x00 -> jsonb "0x00 cannot be converted to text") never reach
# Postgres. Kept as a module alias so existing `_dumps(...)` call sites can
# be swapped 1:1 without touching read-side json.loads usage.
_dumps = safe_json_dumps


def _target_slug(target: str) -> str:
    s = re.sub(r"^https?://", "", str(target or "target")).strip("/")
    s = re.sub(r"[^A-Za-z0-9._-]", "_", s)
    return (s or "target")[:60]


def make_run_id(target: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{_target_slug(target)}_{ts}_{uuid.uuid4().hex[:8]}"


_VULN_CATEGORY_KEYWORDS = [
    ("sqli", ["sql injection", "sqli", "sqlite_error", "union select", "sql error", "sql payload"]),
    ("xss", ["xss", "cross-site scripting", "dom xss", "reflected xss", "stored xss", "onerror="]),
    ("cors", ["cors", "access-control-allow-origin"]),
    ("ftp_listing", ["/ftp", "ftp directory", "ftp listing", "ftp/"]),
    ("directory_listing", ["directory listing", "directory traversal", "path traversal"]),
    ("default_creds", ["default cred", "default admin", "admin123", "default password"]),
    ("error_disclosure", ["stack trace", "verbose error", "error page", "express error", "error disclosure"]),
    ("version_disclosure", ["version disclosure", "version leak", "application-version"]),
    ("missing_header", ["missing.*header", "x-frame-options", "content-security-policy", "hsts", "x-content-type"]),
    ("auth_bypass", ["auth bypass", "authentication bypass"]),
    ("metrics_exposure", ["metrics", "prometheus", "/metrics"]),
    ("info_leak", ["info leak", "data exposure", "data leak", "unauthenticated.*expos"]),
    ("idor", ["idor", "insecure direct"]),
    ("ssrf", ["ssrf", "server-side request"]),
    ("rce", ["remote code", "command injection", "rce"]),
    ("open_redirect", ["open redirect"]),
    ("csrf", ["csrf", "cross-site request"]),
    ("clickjacking", ["clickjacking", "frameable"]),
]


def _vuln_category(title: str) -> str:
    t = (title or "").lower()
    for cat, keywords in _VULN_CATEGORY_KEYWORDS:
        for kw in keywords:
            if ".*" in kw:
                if re.search(kw, t):
                    return cat
            elif kw in t:
                return cat
    return ""


def _normalize_location(loc: str) -> str:
    loc = (loc or "").lower().strip()
    loc = re.sub(r"^https?://", "", loc)
    loc = loc.split("?")[0].split("#")[0].rstrip("/")
    return loc


def _host_only(loc: str) -> str:
    loc = _normalize_location(loc)
    return loc.split("/")[0] if loc else ""



# Categories where each endpoint is a *distinct attack surface* — an SQLi at
# /rest/user/login is a different finding from one at /rest/products/search,
# a UNION dump is a different finding from a 500-based error probe. These MUST
# keep the full URL path (and a short title hash) in the dedup key so the
# per-endpoint proofs survive.
_PER_ENDPOINT_CATEGORIES = {"sqli", "xss", "ssrf", "rce", "idor", "auth_bypass",
                              "open_redirect", "csrf"}

# Categories that describe a *host-level fact* — missing security headers, TLS
# config, an FTP listing at any path, CORS wildcard on the origin. Collapse
# path variance so ("/", "/foo", "/bar") don't triple-count.
_HOST_LEVEL_CATEGORIES = {"cors", "ftp_listing", "directory_listing", "default_creds",
                           "error_disclosure", "version_disclosure", "missing_header",
                           "metrics_exposure", "info_leak", "clickjacking"}


def finding_uid(scan_id: str, v: Dict[str, Any]) -> str:
    title_raw = str(v.get("title") or "").lower().strip()
    loc_raw = str(v.get("location") or v.get("target") or v.get("affected_endpoint") or "")
    vtype = str(v.get("type") or v.get("vuln_type") or "").upper()
    cve = str(v.get("cve_id") or "").upper()

    category = _vuln_category(title_raw)

    if category in _PER_ENDPOINT_CATEGORIES:
        # A short hash of the title separates "UNION dump" from "auth bypass"
        # from "error-based probe" on the same URL — all legitimately distinct.
        title_key = hashlib.sha1(title_raw.encode("utf-8", "ignore")).hexdigest()[:8]
        content = "|".join([category, _normalize_location(loc_raw), title_key, cve])
    elif category in _HOST_LEVEL_CATEGORIES:
        content = "|".join([category, _host_only(loc_raw), cve])
    elif category:
        # Fallback for any category not explicitly classified above — treat as
        # per-endpoint (safe default: prefer preserving distinct proofs).
        title_key = hashlib.sha1(title_raw.encode("utf-8", "ignore")).hexdigest()[:8]
        content = "|".join([category, _normalize_location(loc_raw), title_key, cve])
    else:
        content = "|".join([vtype, title_raw, _normalize_location(loc_raw), cve])
    h = hashlib.sha1(content.encode("utf-8", "ignore")).hexdigest()[:16]
    return f"{scan_id}::{h}"


def _init_schema():
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
                    dedup_key TEXT UNIQUE,
                    title TEXT NOT NULL,
                    type TEXT DEFAULT '',
                    target TEXT DEFAULT '',
                    status TEXT DEFAULT '',
                    details JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS live_progress (
                    scan_id TEXT PRIMARY KEY,
                    phase TEXT DEFAULT '',
                    progress REAL DEFAULT 0,
                    status TEXT DEFAULT '',
                    data JSONB DEFAULT '{}'::jsonb,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS live_results (
                    scan_id TEXT PRIMARY KEY,
                    data JSONB DEFAULT '{}'::jsonb,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );

                -- Migration for pre-fix deployments where these tables used a
                -- singleton (id INT PRIMARY KEY DEFAULT 1) so concurrent scans
                -- stomped one another. Drop the legacy id column and re-key on
                -- scan_id. Safe: rows in these tables are ephemeral scan state.
                DO $mig$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name='live_progress' AND column_name='id'
                    ) THEN
                        DELETE FROM live_progress WHERE scan_id IS NULL OR scan_id = '';
                        ALTER TABLE live_progress DROP CONSTRAINT IF EXISTS live_progress_pkey;
                        ALTER TABLE live_progress DROP COLUMN id;
                        ALTER TABLE live_progress ADD PRIMARY KEY (scan_id);
                    END IF;
                    IF EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name='live_results' AND column_name='id'
                    ) THEN
                        DELETE FROM live_results WHERE scan_id IS NULL OR scan_id = '';
                        ALTER TABLE live_results DROP CONSTRAINT IF EXISTS live_results_pkey;
                        ALTER TABLE live_results DROP COLUMN id;
                        ALTER TABLE live_results ADD PRIMARY KEY (scan_id);
                    END IF;
                END
                $mig$;

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

                CREATE TABLE IF NOT EXISTS captured_requests (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    method TEXT DEFAULT 'GET',
                    url TEXT NOT NULL,
                    resource_type TEXT DEFAULT '',
                    status INT DEFAULT 0,
                    is_preflight BOOLEAN DEFAULT FALSE,
                    headers JSONB DEFAULT '{}'::jsonb,
                    post_data TEXT DEFAULT '',
                    source TEXT DEFAULT 'playwright',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS tool_executions (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    command TEXT DEFAULT '',
                    target TEXT DEFAULT '',
                    capability TEXT DEFAULT '',
                    success BOOLEAN DEFAULT TRUE,
                    stdout_bytes INT DEFAULT 0,
                    duration_s REAL DEFAULT 0,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE INDEX IF NOT EXISTS idx_captured_requests_scan ON captured_requests(scan_id);
                CREATE INDEX IF NOT EXISTS idx_tool_executions_scan ON tool_executions(scan_id);
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

                CREATE TABLE IF NOT EXISTS attack_chains (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    chain_id TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    score REAL DEFAULT 0,
                    status TEXT DEFAULT 'detected',
                    steps JSONB DEFAULT '[]'::jsonb,
                    impact TEXT DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_attack_chains_scan ON attack_chains(scan_id);
                -- Additive migration: needed by `bulk_upsert`'s `ON CONFLICT`
                -- clause. Without this, the previous `ON CONFLICT DO NOTHING`
                -- (no target) would raise on the actual conflict rather than
                -- silently skip.
                CREATE UNIQUE INDEX IF NOT EXISTS ux_attack_chains_scan_chain
                    ON attack_chains(scan_id, chain_id) WHERE chain_id <> '';

                CREATE TABLE IF NOT EXISTS post_exploit_data (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    data_type TEXT NOT NULL,
                    title TEXT DEFAULT '',
                    details JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_post_exploit_scan ON post_exploit_data(scan_id);
                CREATE INDEX IF NOT EXISTS idx_post_exploit_type ON post_exploit_data(data_type);

                CREATE TABLE IF NOT EXISTS scan_metadata (
                    scan_id TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value JSONB DEFAULT '{}'::jsonb,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (scan_id, key)
                );

                CREATE TABLE IF NOT EXISTS scan_artifacts (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    name TEXT DEFAULT '',
                    mime_type TEXT DEFAULT 'application/octet-stream',
                    content BYTEA NOT NULL,
                    size_bytes INT NOT NULL DEFAULT 0,
                    metadata JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_scan_artifacts_scan ON scan_artifacts(scan_id);
                CREATE INDEX IF NOT EXISTS idx_scan_artifacts_kind ON scan_artifacts(scan_id, kind);

                CREATE TABLE IF NOT EXISTS auth_bypasses (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
                    host TEXT NOT NULL,
                    method TEXT NOT NULL,
                    login_url TEXT NOT NULL,
                    technique TEXT NOT NULL,        -- 'sqli_bypass' | 'mass_assign' | 'default_creds' | 'credential_replay' | 'sqlmap_dump' | 'hash_crack'
                    username TEXT DEFAULT '',
                    password TEXT DEFAULT '',
                    payload TEXT DEFAULT '',        -- the exact request body / payload that worked
                    token TEXT DEFAULT '',          -- captured JWT / session token (may be long)
                    response_status INT DEFAULT 0,
                    response_snippet TEXT DEFAULT '',  -- proof of entry (JWT header + role)
                    role TEXT DEFAULT '',           -- decoded role if JWT
                    severity TEXT DEFAULT 'critical',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    dedup_key TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_auth_bypass_scan ON auth_bypasses(scan_id);
                CREATE UNIQUE INDEX IF NOT EXISTS ux_auth_bypass_dedup ON auth_bypasses(scan_id, dedup_key);

                CREATE TABLE IF NOT EXISTS live_agents (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
                    agent_id TEXT NOT NULL,
                    label TEXT NOT NULL DEFAULT '',
                    phase TEXT DEFAULT '',
                    target TEXT DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'queued',  -- queued|running|completed|failed
                    current_tool TEXT DEFAULT '',
                    current_step TEXT DEFAULT '',
                    steps_taken INT NOT NULL DEFAULT 0,
                    findings_count INT NOT NULL DEFAULT 0,
                    cost_usd REAL NOT NULL DEFAULT 0,
                    started_at TIMESTAMPTZ DEFAULT NULL,
                    finished_at TIMESTAMPTZ DEFAULT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    metadata JSONB DEFAULT '{}'::jsonb
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_live_agents_scan_agent
                    ON live_agents(scan_id, agent_id);
                CREATE INDEX IF NOT EXISTS idx_live_agents_scan ON live_agents(scan_id);
                CREATE INDEX IF NOT EXISTS idx_live_agents_status ON live_agents(scan_id, status);

                CREATE TABLE IF NOT EXISTS scan_llm_memory (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
                    phase TEXT NOT NULL DEFAULT '',
                    kind TEXT NOT NULL DEFAULT 'summary',  -- summary|decision|reasoning|reflection
                    content TEXT NOT NULL DEFAULT '',
                    tool TEXT DEFAULT '',
                    target TEXT DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_llm_memory_scan ON scan_llm_memory(scan_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_llm_memory_kind ON scan_llm_memory(scan_id, kind);

                CREATE TABLE IF NOT EXISTS target_intel (
                    target TEXT PRIMARY KEY,
                    working_login_endpoints JSONB DEFAULT '[]'::jsonb,
                    working_body_shapes JSONB DEFAULT '[]'::jsonb,
                    waf_detected TEXT DEFAULT '',
                    successful_payloads JSONB DEFAULT '{}'::jsonb,
                    blocked_payloads JSONB DEFAULT '{}'::jsonb,
                    known_endpoints JSONB DEFAULT '[]'::jsonb,
                    known_subdomains JSONB DEFAULT '[]'::jsonb,
                    known_tech JSONB DEFAULT '{}'::jsonb,
                    prior_scan_ids JSONB DEFAULT '[]'::jsonb,
                    metadata JSONB DEFAULT '{}'::jsonb,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS agent_reasoning (
                    id SERIAL PRIMARY KEY,
                    scan_id TEXT REFERENCES scans(scan_id) ON DELETE CASCADE,
                    agent_id TEXT NOT NULL,
                    step INT DEFAULT 0,
                    thought TEXT NOT NULL DEFAULT '',
                    tool_planned TEXT DEFAULT '',
                    tool_args JSONB DEFAULT '{}'::jsonb,
                    tool_result_preview TEXT DEFAULT '',
                    tool_status INT DEFAULT NULL,
                    duration_ms INT DEFAULT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                -- Additive migration for existing installs missing the new columns.
                ALTER TABLE agent_reasoning
                    ADD COLUMN IF NOT EXISTS tool_args JSONB DEFAULT '{}'::jsonb;
                ALTER TABLE agent_reasoning
                    ADD COLUMN IF NOT EXISTS tool_result_preview TEXT DEFAULT '';
                ALTER TABLE agent_reasoning
                    ADD COLUMN IF NOT EXISTS tool_status INT DEFAULT NULL;
                ALTER TABLE agent_reasoning
                    ADD COLUMN IF NOT EXISTS duration_ms INT DEFAULT NULL;
                CREATE INDEX IF NOT EXISTS idx_reasoning_scan ON agent_reasoning(scan_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_reasoning_agent ON agent_reasoning(scan_id, agent_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS learned_skills (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    method TEXT DEFAULT 'GET',
                    url_template TEXT DEFAULT '',   -- {base} placeholder allowed
                    headers JSONB DEFAULT '{}'::jsonb,
                    body_template TEXT DEFAULT '',
                    expected_signature TEXT DEFAULT '',   -- regex or literal in response body
                    tech_shape JSONB DEFAULT '{}'::jsonb, -- {server:'nginx', has_php:true, ...}
                    confirmed_count INT NOT NULL DEFAULT 0,
                    last_confirmed_scan TEXT DEFAULT '',
                    last_used_at TIMESTAMPTZ DEFAULT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_learned_skills_name ON learned_skills(name);

                CREATE TABLE IF NOT EXISTS authored_tools (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    parameters_schema JSONB DEFAULT '{}'::jsonb,
                    code TEXT NOT NULL DEFAULT '',
                    review_status TEXT NOT NULL DEFAULT 'pending',   -- pending|approved|rejected
                    review_notes TEXT DEFAULT '',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_authored_tools_name ON authored_tools(name);

                -- (security_kb table removed — uses shared rag_documents via
                -- SecurityRAGPipeline; see core/intel/security_kb.py)

                -- ── Hot-path indexes surfaced by audit #112 ─────────────────
                -- These are all `IF NOT EXISTS`, additive on existing DBs.
                -- Every column below is used in an ORDER BY / filter on a
                -- table that's already known to grow unbounded during long
                -- deployments.
                CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp
                    ON audit_log(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_execution_audit_timestamp
                    ON execution_audit(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_findings_dedup_last_seen
                    ON findings_dedup(last_seen DESC);
                CREATE INDEX IF NOT EXISTS idx_scans_started_at
                    ON scans(started_at DESC);
                CREATE INDEX IF NOT EXISTS idx_experiences_test_type
                    ON experiences(test_type);
                CREATE INDEX IF NOT EXISTS idx_experiences_created_at
                    ON experiences(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_llm_failures_created_at
                    ON llm_failures(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_strategies_test_type
                    ON strategies(test_type);
            """)
            conn.commit()

            # ── One-shot dedupe migration ─────────────────────────────
            # post_exploit_data and captured_requests were being INSERTed
            # every time the live_results singleton was refreshed, so a
            # single scan's credentials/requests could appear 100+ times.
            # Delete dupes (keep MIN(id)), then add unique indexes so
            # ON CONFLICT DO NOTHING can prevent future dupes.
            try:
                cur.execute("""
                    DELETE FROM post_exploit_data a
                    USING post_exploit_data b
                    WHERE a.id > b.id
                      AND a.scan_id  = b.scan_id
                      AND a.data_type= b.data_type
                      AND a.title    = b.title
                      AND md5(a.details::text) = md5(b.details::text);
                """)
                cur.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS ux_post_exploit_dedup
                    ON post_exploit_data(scan_id, data_type, title, md5(details::text));
                """)
                cur.execute("""
                    DELETE FROM captured_requests a
                    USING captured_requests b
                    WHERE a.id > b.id
                      AND a.scan_id = b.scan_id
                      AND a.method  = b.method
                      AND a.url     = b.url
                      AND a.status  = b.status
                      AND COALESCE(a.post_data,'') = COALESCE(b.post_data,'');
                """)
                cur.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS ux_captured_requests_dedup
                    ON captured_requests(scan_id, method, url, status,
                                          md5(COALESCE(post_data, '')));
                """)
                # tool_outputs — same (tool, target, stdout) inserted repeatedly
                cur.execute("""
                    DELETE FROM tool_outputs a
                    USING tool_outputs b
                    WHERE a.id > b.id
                      AND a.scan_id   = b.scan_id
                      AND a.tool_name = b.tool_name
                      AND a.target    = b.target
                      AND md5(COALESCE(a.stdout, '')) = md5(COALESCE(b.stdout, ''));
                """)
                cur.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS ux_tool_outputs_dedup
                    ON tool_outputs(scan_id, tool_name, target,
                                     md5(COALESCE(stdout, '')));
                """)
                # tool_executions — same (tool, command, target) inserted repeatedly
                cur.execute("""
                    DELETE FROM tool_executions a
                    USING tool_executions b
                    WHERE a.id > b.id
                      AND a.scan_id = b.scan_id
                      AND a.tool    = b.tool
                      AND a.command = b.command
                      AND COALESCE(a.target, '') = COALESCE(b.target, '');
                """)
                cur.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS ux_tool_executions_dedup
                    ON tool_executions(scan_id, tool, command, COALESCE(target, ''));
                """)
                # vulnerabilities — case-variant / path-variant duplicates of
                # site-level findings (e.g. "FTP directory listing exposed"
                # with type=INFORMATION_DISCLOSURE vs ENDPOINT). Collapse by
                # lower-title + host (strip scheme+port+path).
                cur.execute("""
                    WITH ranked AS (
                        SELECT id,
                               LEAST(id, MIN(id) OVER (
                                 PARTITION BY scan_id,
                                              LOWER(title),
                                              regexp_replace(
                                                LOWER(COALESCE(location, target, '')),
                                                '^https?://([^/:?#]+).*$', '\\1')
                               )) AS keep_id
                        FROM vulnerabilities
                    )
                    DELETE FROM vulnerabilities v
                    USING ranked r
                    WHERE v.id = r.id AND v.id <> r.keep_id;
                """)
                conn.commit()
            except Exception as _e:
                logger.warning(f"[PGStore] dedupe migration warning (non-fatal): {_e}")
                conn.rollback()

    logger.info("[PGStore] Schema initialized")


class TargetRepo:

    @staticmethod
    def list_all(limit: int = 500, offset: int = 0) -> List[Dict]:
        limit = max(1, min(int(limit or 500), 2000))
        offset = max(0, int(offset or 0))
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM targets ORDER BY added_at DESC LIMIT %s OFFSET %s",
                    (limit, offset))
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
                """, (_dumps(report_data, default=str),
                      _dumps(meta, default=str),
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
    def list_all(limit: int = 500, offset: int = 0) -> List[Dict]:
        # Bounded pagination — previously an unbounded scan of `scans` that
        # blew up on long-running deployments.
        limit = max(1, min(int(limit or 500), 2000))
        offset = max(0, int(offset or 0))
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM scans ORDER BY started_at DESC LIMIT %s OFFSET %s",
                    (limit, offset))
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def bootstrap_recover() -> int:
        recovered = 0
        try:
            import os
            try:
                import psutil
            except ImportError:
                psutil = None  # fall through to os.kill probe

            def _alive(pid):
                if not pid:
                    return False
                if psutil is not None:
                    try:
                        return psutil.pid_exists(int(pid))
                    except Exception:
                        return False
                if os.name == "nt":
                    return False  # can't probe safely without psutil
                try:
                    os.kill(int(pid), 0)
                    return True
                except (OSError, Exception):
                    return False

            with DatabaseManager.get_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        "SELECT scan_id, pid, status FROM scans "
                        "WHERE status IN ('running','starting','stopping')")
                    rows = cur.fetchall()
                for r in rows:
                    if _alive(r.get("pid")):
                        continue
                    new_status = "stopped" if r.get("status") == "stopping" else "failed"
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE scans SET status = %s, finished_at = NOW(), "
                            "error = COALESCE(NULLIF(error,''), %s) "
                            "WHERE scan_id = %s",
                            (new_status,
                             "orphaned: process not alive at API startup",
                             r["scan_id"]))
                    recovered += 1
                conn.commit()
            if recovered:
                logger.warning("bootstrap_recover: reconciled %d orphaned scans", recovered)
        except Exception as e:
            logger.exception("bootstrap_recover failed: %s", e)
        return recovered

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

    @staticmethod
    def bulk_insert(scan_id: str, vulns: List[Dict]):
        if not vulns:
            return
        # P0-2: canonical fingerprint dedup BEFORE we hand the batch to
        # Postgres. Two agents that discovered the same vuln collapse to
        # one row here; the DB is no longer the deduper of last resort.
        try:
            from core.validation.dedup import fingerprint
            collapsed: Dict[str, Dict] = {}
            for v in vulns:
                fp = fingerprint(
                    cve_id=str(v.get("cve_id") or ""),
                    file_path=str(v.get("location") or v.get("affected_endpoint") or ""),
                    function_name=str(v.get("parameter") or ""),
                    package_version="",
                    target=str(v.get("target") or ""),
                    title=str(v.get("title") or ""),
                    vuln_type=str(v.get("type") or v.get("vuln_type") or ""),
                )
                existing = collapsed.get(fp)
                if existing is None:
                    collapsed[fp] = v
                    continue
                # Merge: keep longer proof/details; union evidence-ish fields.
                for k in ("details", "proof", "remediation"):
                    if len(str(v.get(k) or "")) > len(str(existing.get(k) or "")):
                        existing[k] = v.get(k)
                if (v.get("confidence_score") or 0) > (existing.get("confidence_score") or 0):
                    existing["confidence_score"] = v["confidence_score"]
                # Prefer CONFIRMED over any other status.
                if str(v.get("status") or "").upper() == "CONFIRMED":
                    existing["status"] = "CONFIRMED"
            if len(collapsed) != len(vulns):
                try:
                    from core.observability.scan_metrics import get_metrics
                    get_metrics().inc("duplicate_findings", by=(len(vulns) - len(collapsed)))
                except Exception as _e:
                    logger.warning("pg_store.py: swallowed exception: %s", _e)
                logger.info(
                    "VulnRepo.bulk_insert: pre-persist dedup collapsed %d -> %d",
                    len(vulns), len(collapsed))
            vulns = list(collapsed.values())
        except Exception as _e:
            logger.debug(f"pre-persist dedup skipped: {_e}")
        # Build one tuple per vuln, then send them in a single round trip via
        # psycopg2.extras.execute_values. Previously this loop performed N
        # sequential INSERTs (one per finding), which was the dominant DB
        # cost on any scan with many findings and amplified pool-poisoning
        # cascades.
        #
        # Two vulns from the same phase can share a `finding_uid` — the
        # deterministic id is derived from scan_id + title + type + location,
        # and the LLM planner regularly proposes near-duplicate exploits
        # against the same endpoint. Postgres refuses to touch the same row
        # twice in one `INSERT ... ON CONFLICT DO UPDATE` statement, so we
        # dedupe by `finding_id` WITHIN THE BATCH before handing it to
        # `execute_values`. Later rows for the same fid win because "later"
        # usually means more evidence.
        by_fid: Dict[str, tuple] = {}
        for v in vulns:
            if v.get("finding_id"):
                v.setdefault("orig_finding_id", v["finding_id"])
            fid = finding_uid(scan_id, v)
            row = (
                scan_id, fid, v.get("title", ""), v.get("type", ""),
                (v.get("severity") or "INFO").upper(),
                (v.get("status") or "UNCONFIRMED").upper(),
                v.get("target", ""), v.get("location", ""),
                v.get("details", ""), str(v.get("proof", "")),
                v.get("remediation", ""), v.get("tool", ""),
                v.get("cwe_id", ""), v.get("cve_id", ""),
                v.get("confidence_score", 0.5),
                _dumps({k: v.get(k) for k in v
                            if k not in ("title", "type", "severity", "status",
                                          "target", "location", "details", "proof",
                                          "remediation", "tool", "cwe_id", "cve_id",
                                          "confidence_score", "finding_id")},
                            default=str),
            )
            # Prefer the row with the LONGER details/proof, since the
            # ON CONFLICT DO UPDATE picks the longer of the two anyway.
            existing = by_fid.get(fid)
            if existing is None:
                by_fid[fid] = row
            else:
                # Choose the row we'd prefer to KEEP if the DB were doing it.
                existing_ev = len(existing[8] or "") + len(existing[9] or "")
                new_ev = len(row[8] or "") + len(row[9] or "")
                if new_ev >= existing_ev:
                    by_fid[fid] = row

        rows: List[tuple] = list(by_fid.values())
        if not rows:
            return
        _upsert_sql = """
            INSERT INTO vulnerabilities
            (scan_id, finding_id, title, type, severity, status, target, location,
             details, proof, remediation, tool, cwe_id, cve_id, confidence_score, extra)
            VALUES %s
            ON CONFLICT (finding_id) DO UPDATE SET
                severity = CASE
                    WHEN array_position(ARRAY['CRITICAL','HIGH','MEDIUM','LOW','INFO'], EXCLUDED.severity) IS NULL THEN vulnerabilities.severity
                    WHEN array_position(ARRAY['CRITICAL','HIGH','MEDIUM','LOW','INFO'], vulnerabilities.severity) IS NULL THEN EXCLUDED.severity
                    WHEN array_position(ARRAY['CRITICAL','HIGH','MEDIUM','LOW','INFO'], EXCLUDED.severity)
                       < array_position(ARRAY['CRITICAL','HIGH','MEDIUM','LOW','INFO'], vulnerabilities.severity)
                    THEN EXCLUDED.severity ELSE vulnerabilities.severity END,
                status = CASE WHEN EXCLUDED.status = 'CONFIRMED' THEN EXCLUDED.status ELSE vulnerabilities.status END,
                details = CASE WHEN length(EXCLUDED.details) > length(COALESCE(vulnerabilities.details, '')) THEN EXCLUDED.details ELSE vulnerabilities.details END,
                proof = CASE WHEN length(EXCLUDED.proof) > length(COALESCE(vulnerabilities.proof, '')) THEN EXCLUDED.proof ELSE vulnerabilities.proof END,
                location = COALESCE(NULLIF(EXCLUDED.location, ''), vulnerabilities.location),
                tool = COALESCE(NULLIF(EXCLUDED.tool, ''), vulnerabilities.tool),
                confidence_score = EXCLUDED.confidence_score, extra = EXCLUDED.extra
        """
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                # Fast path — one round trip via execute_values.
                try:
                    psycopg2.extras.execute_values(
                        cur, _upsert_sql, rows, page_size=200,
                    )
                    conn.commit()
                    return
                except Exception as batch_exc:
                    # One row aborted the whole batch. Roll back and fall through
                    # to a per-row path guarded by SAVEPOINTs so a single bad row
                    # (e.g. oversized JSONB, encoding issue) can't lose everyone
                    # else's findings.
                    conn.rollback()
                    logger.warning(
                        "VulnRepo.bulk_insert: batch failed (%s); falling back "
                        "to per-row inserts", batch_exc)

                inserted = 0
                dropped: List[Dict] = []
                _one_sql = _upsert_sql.replace("VALUES %s", "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)")
                for row in rows:
                    try:
                        cur.execute("SAVEPOINT sp_vuln")
                        cur.execute(_one_sql, row)
                        cur.execute("RELEASE SAVEPOINT sp_vuln")
                        inserted += 1
                    except Exception as row_exc:
                        try:
                            cur.execute("ROLLBACK TO SAVEPOINT sp_vuln")
                        except Exception as _e:
                            logger.warning("pg_store.py: swallowed exception: %s", _e)
                        dropped.append({"finding_id": row[1], "error": str(row_exc)[:200]})
                conn.commit()
                if dropped:
                    logger.error(
                        "VulnRepo.bulk_insert: %d row(s) dropped; kept %d. First few: %s",
                        len(dropped), inserted, dropped[:3])

    @staticmethod
    def get_by_scan(scan_id: str) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM vulnerabilities WHERE scan_id = %s ORDER BY severity, title", (scan_id,))
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def get_all(limit: int = 1000, cursor: Optional[int] = None) -> List[Dict]:
        """Keyset (cursor) pagination on id DESC. Pass the last returned row's
        ``id`` as ``cursor`` to fetch the next page. Replaces the previous
        hardcoded ``LIMIT 1000`` (which silently truncated large scans)."""
        limit = max(1, min(int(limit or 1000), 5000))
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if cursor is not None:
                    cur.execute("SELECT * FROM vulnerabilities WHERE id < %s "
                                "ORDER BY id DESC LIMIT %s", (int(cursor), limit))
                else:
                    cur.execute("SELECT * FROM vulnerabilities ORDER BY id DESC LIMIT %s",
                                (limit,))
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

    @staticmethod
    def upsert_progress(scan_id: str, data: Dict):
        if not scan_id:
            raise ValueError("upsert_progress requires scan_id")
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO live_progress (scan_id, phase, progress, status, data, updated_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (scan_id) DO UPDATE SET
                        phase = EXCLUDED.phase,
                        progress = EXCLUDED.progress, status = EXCLUDED.status,
                        data = EXCLUDED.data, updated_at = NOW()
                """, (scan_id,
                      data.get("phase", ""), data.get("progress", 0),
                      data.get("status", ""), _dumps(data, default=str)))
                conn.commit()

    @staticmethod
    def get_progress(scan_id: str = None) -> Dict:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if scan_id:
                    cur.execute("SELECT * FROM live_progress WHERE scan_id = %s", (scan_id,))
                else:
                    cur.execute("SELECT * FROM live_progress ORDER BY updated_at DESC LIMIT 1")
                row = cur.fetchone()
                if row:
                    d = dict(row)
                    return d.get("data") if isinstance(d.get("data"), dict) else d
                return {}

    @staticmethod
    def upsert_results(scan_id: str, data: Dict):
        if not scan_id:
            raise ValueError("upsert_results requires scan_id")
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO live_results (scan_id, data, updated_at)
                    VALUES (%s, %s, NOW())
                    ON CONFLICT (scan_id) DO UPDATE SET
                        data = EXCLUDED.data, updated_at = NOW()
                """, (scan_id, _dumps(data, default=str)))
                conn.commit()

    @staticmethod
    def get_results(scan_id: str = None) -> Dict:
        empty = {
            "recon": {"subdomains": [], "endpoints": [], "technologies": {}, "ports": [], "ips": []},
            "vulnerabilities": [], "exploits": [], "captured_requests": [],
        }
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if scan_id:
                    cur.execute("SELECT * FROM live_results WHERE scan_id = %s", (scan_id,))
                else:
                    cur.execute("SELECT * FROM live_results ORDER BY updated_at DESC LIMIT 1")
                row = cur.fetchone()
                if row and isinstance(row.get("data"), dict):
                    return row["data"]
                return empty


class ExploitResultRepo:

    @staticmethod
    def insert(scan_id: str, result: Dict):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                title = result.get("title") or result.get("name") or ""
                target = result.get("target") or result.get("url") or ""
                etype = result.get("type", "")
                if not title or title == "Exploit":
                    title = f"{etype or 'exploit'}: {result.get('vuln_type', '')} @ {target}"[:200] or "Exploit attempt"
                dk_raw = f"{scan_id}|{title}|{target}|{result.get('vuln_id', '')}|{result.get('chain_id', '')}|{result.get('step', '')}"
                dk = hashlib.sha1(dk_raw.encode("utf-8", "ignore")).hexdigest()[:32]
                cur.execute("""
                    INSERT INTO exploit_results (scan_id, dedup_key, title, type, target, status, details)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (dedup_key) DO UPDATE SET
                        status = EXCLUDED.status,
                        details = EXCLUDED.details
                """, (scan_id, dk, title, etype, target,
                      result.get("status") or ("SUCCESS" if result.get("success") else "ATTEMPTED"),
                      _dumps(result, default=str)))
                conn.commit()

    @staticmethod
    def bulk_insert(scan_id: str, results: List[Dict]):
        if not results:
            return
        seen = set()
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                for r in results:
                    title = r.get("title") or r.get("name") or ""
                    target = r.get("target") or r.get("url") or ""
                    etype = r.get("type", "")
                    status = r.get("status") or ("SUCCESS" if r.get("success") else "ATTEMPTED")
                    if not title or title == "Exploit":
                        title = f"{etype or 'exploit'}: {r.get('vuln_type', '')} @ {target}"[:200] or "Exploit attempt"
                    dedup_key = f"{scan_id}|{title}|{target}|{r.get('vuln_id', '')}|{r.get('chain_id', '')}|{r.get('step', '')}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    dk = hashlib.sha1(dedup_key.encode("utf-8", "ignore")).hexdigest()[:32]
                    cur.execute("""
                        INSERT INTO exploit_results (scan_id, dedup_key, title, type, target, status, details)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (dedup_key) DO UPDATE SET
                            status = EXCLUDED.status,
                            details = EXCLUDED.details
                    """, (scan_id, dk, title, etype, target, status,
                          _dumps(r, default=str)))
                conn.commit()

    @staticmethod
    def get_by_scan(scan_id: str) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM exploit_results WHERE scan_id = %s ORDER BY created_at", (scan_id,))
                rows = []
                for r in cur.fetchall():
                    d = dict(r)
                    if isinstance(d.get("details"), dict):
                        merged = {**d.pop("details"), **d}
                        rows.append(merged)
                    else:
                        rows.append(d)
                return rows


class FindingV2Repo:

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
                      state, evidence_ids or [], _dumps(extra or {}, default=str)))
                conn.commit()

    @staticmethod
    def list_all(limit: int = 1000, offset: int = 0) -> List[Dict]:
        limit = max(1, min(int(limit or 1000), 5000))
        offset = max(0, int(offset or 0))
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM findings_v2 ORDER BY created_at DESC LIMIT %s OFFSET %s",
                    (limit, offset))
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

    @staticmethod
    def check_and_insert(signature: str, tool: str, finding_type: str,
                         data_repr: str, task_id: str = "") -> bool:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO findings_dedup (signature, tool, finding_type, data_repr, task_id)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (signature) DO UPDATE SET
                        last_seen = NOW(),
                        count = findings_dedup.count + 1,
                        task_id = EXCLUDED.task_id
                    RETURNING (xmax = 0) AS inserted
                """, (signature, tool, finding_type, data_repr, task_id))
                row = cur.fetchone()
                conn.commit()
                # `xmax = 0` on the returned row is True when the row was newly
                # inserted, False when the ON CONFLICT UPDATE branch fired.
                return bool(row and row[0])

    @staticmethod
    def list_all(limit: int = 500) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM findings_dedup ORDER BY last_seen DESC LIMIT %s", (limit,))
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def reset_all():
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM findings_dedup")
                conn.commit()


class AuditRepo:

    @staticmethod
    def log_event(action: str, target: str = "", details: dict = None,
                  previous_hash: str = "", current_hash: str = ""):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO audit_log (action, target, details, previous_hash, current_hash)
                    VALUES (%s, %s, %s, %s, %s)
                """, (action, target, _dumps(details or {}, default=str),
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
                """, (action, _dumps(params or {}, default=str),
                      _dumps(result or {}, default=str), hash_val))
                conn.commit()

    @staticmethod
    def get_execution_log(limit: int = 200) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM execution_audit ORDER BY timestamp DESC LIMIT %s", (limit,))
                return [dict(r) for r in cur.fetchall()]


class ScheduleRepo:

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
    def list_all(limit: int = 500, offset: int = 0) -> List[Dict]:
        limit = max(1, min(int(limit or 500), 2000))
        offset = max(0, int(offset or 0))
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM scan_schedules ORDER BY created_at DESC LIMIT %s OFFSET %s",
                    (limit, offset))
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
                """, (last_report, _dumps(delta or {}, default=str), schedule_id))
                conn.commit()


class ReconRepo:

    @staticmethod
    def save(scan_id: str, target: str, data: Dict) -> None:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO recon_data (scan_id, target, data, updated_at)
                    VALUES (%s, %s, %s, NOW())
                    ON CONFLICT (scan_id) DO UPDATE SET
                        data = EXCLUDED.data, target = EXCLUDED.target, updated_at = NOW()
                """, (scan_id, target, _dumps(data, default=str)))
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
                        ON CONFLICT (scan_id, tool_name, target, md5(COALESCE(stdout,'')))
                        DO NOTHING
                    """, (scan_id, tool_name, operation, target,
                          command[:2000], stdout[:50000], stderr[:10000],
                          exit_code, duration_s))
                    conn.commit()
        except Exception as _e:
            logger.warning("pg_store.py: swallowed exception: %s", _e)

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


class CapturedRequestRepo:

    @staticmethod
    def save(scan_id: str, method: str, url: str, resource_type: str = "",
             status: int = 0, is_preflight: bool = False,
             headers: dict = None, post_data: str = "",
             source: str = "playwright") -> None:
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO captured_requests
                        (scan_id, method, url, resource_type, status,
                         is_preflight, headers, post_data, source)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """, (scan_id, method, url[:2000], resource_type,
                          status, is_preflight,
                          _dumps(headers or {}),
                          (post_data or "")[:4000], source))
                    conn.commit()
        except Exception as _e:
            logger.warning("pg_store.py: swallowed exception: %s", _e)

    @staticmethod
    def save_batch(scan_id: str, requests: list) -> int:
        saved = 0
        seen = set()  # in-batch dedupe as well
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    for r in requests:
                        if not isinstance(r, dict) or not r.get("url"):
                            continue
                        method = r.get("method", "GET")
                        url = r.get("url", "")[:2000]
                        status = r.get("status", 0)
                        post_data = (r.get("post_data", "") or "")[:4000]
                        key = (method, url, status, hashlib.md5(post_data.encode("utf-8", "ignore")).hexdigest())
                        if key in seen:
                            continue
                        seen.add(key)
                        cur.execute("""
                            INSERT INTO captured_requests
                            (scan_id, method, url, resource_type, status,
                             is_preflight, headers, post_data, source)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT (scan_id, method, url, status, md5(COALESCE(post_data,'')))
                            DO NOTHING
                        """, (scan_id, method, url,
                              r.get("resource_type", ""),
                              status,
                              r.get("is_preflight", False),
                              _dumps(r.get("headers", {})),
                              post_data,
                              r.get("source", "playwright")))
                        if cur.rowcount:
                            saved += 1
                    conn.commit()
        except Exception as _e:
            logger.warning("pg_store.py: swallowed exception: %s", _e)
        return saved

    @staticmethod
    def list_by_scan(scan_id: str) -> List[Dict]:
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("""
                        SELECT method, url, resource_type, status,
                               is_preflight, headers, post_data, source, created_at
                        FROM captured_requests WHERE scan_id = %s
                        ORDER BY created_at ASC
                    """, (scan_id,))
                    return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []


class ToolExecutionRepo:

    @staticmethod
    def save(scan_id: str, tool: str, command: str, target: str = "",
             capability: str = "", success: bool = True,
             stdout_bytes: int = 0, duration_s: float = 0) -> None:
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO tool_executions
                        (scan_id, tool, command, target, capability,
                         success, stdout_bytes, duration_s)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (scan_id, tool, command, COALESCE(target,''))
                        DO NOTHING
                    """, (scan_id, tool, command[:2000], target,
                          capability, success, stdout_bytes, duration_s))
                    conn.commit()
        except Exception as _e:
            logger.warning("pg_store.py: swallowed exception: %s", _e)

    @staticmethod
    def save_batch(scan_id: str, executions: list) -> int:
        saved = 0
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    for e in executions:
                        if not isinstance(e, dict):
                            continue
                        cur.execute("""
                            INSERT INTO tool_executions
                            (scan_id, tool, command, target, capability,
                             success, stdout_bytes, duration_s)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT (scan_id, tool, command, COALESCE(target,''))
                            DO NOTHING
                        """, (scan_id,
                              e.get("tool", ""),
                              (e.get("command", "") or "")[:2000],
                              e.get("target", ""),
                              e.get("capability", ""),
                              e.get("success", True),
                              e.get("stdout_bytes", 0),
                              e.get("duration_s", 0)))
                        if cur.rowcount:
                            saved += 1
                    conn.commit()
        except Exception as _e:
            logger.warning("pg_store.py: swallowed exception: %s", _e)
        return saved

    @staticmethod
    def list_by_scan(scan_id: str) -> List[Dict]:
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("""
                        SELECT tool, command, target, capability,
                               success, stdout_bytes, duration_s, created_at
                        FROM tool_executions WHERE scan_id = %s
                        ORDER BY created_at ASC
                    """, (scan_id,))
                    return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []


class ActivityLogRepo:

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
                          _dumps(rec.get("metadata", {}), default=str)))
                    conn.commit()
        except Exception as _e:
            logger.warning("pg_store.py: swallowed exception: %s", _e)

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
                      _dumps(rec.get("history", []), default=str),
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
                """, (_dumps(report, default=str), campaign_id))
                conn.commit()

    @staticmethod
    def list_all(limit: int = 200, offset: int = 0) -> List[Dict]:
        limit = max(1, min(int(limit or 200), 2000))
        offset = max(0, int(offset or 0))
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM campaigns ORDER BY created_at DESC LIMIT %s OFFSET %s",
                    (limit, offset))
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


class AttackChainRepo:

    @staticmethod
    def bulk_upsert(scan_id: str, chains):
        if not chains:
            return
        if isinstance(chains, dict):
            chains = list(chains.values()) if chains else []
        if not isinstance(chains, list):
            return

        rows = []
        for c in chains:
            if not isinstance(c, dict):
                continue
            chain_id = c.get("chain_id") or c.get("id") or ""
            rows.append((
                scan_id, chain_id,
                c.get("description", ""),
                float(c.get("score", 0)),
                c.get("status", "detected"),
                _dumps(c.get("steps") or c.get("path") or [], default=str),
                c.get("impact") or c.get("final_impact", ""),
            ))

        if not rows:
            return

        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                # `ON CONFLICT` needs an explicit target; the partial unique
                # index `ux_attack_chains_scan_chain` covers (scan_id, chain_id)
                # WHERE chain_id <> ''. Rows with an empty chain_id are not
                # covered and will just insert as new rows — that's the
                # correct behavior (no natural key to dedupe on).
                psycopg2.extras.execute_values(
                    cur,
                    """
                    INSERT INTO attack_chains
                        (scan_id, chain_id, description, score, status, steps, impact)
                    VALUES %s
                    ON CONFLICT (scan_id, chain_id) WHERE chain_id <> ''
                        DO UPDATE SET
                            description = EXCLUDED.description,
                            score = EXCLUDED.score,
                            status = EXCLUDED.status,
                            steps = EXCLUDED.steps,
                            impact = EXCLUDED.impact
                    """,
                    rows,
                    page_size=100,
                )
                conn.commit()

    @staticmethod
    def get_by_scan(scan_id: str) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM attack_chains WHERE scan_id = %s ORDER BY score DESC", (scan_id,))
                return [dict(r) for r in cur.fetchall()]


class PostExploitRepo:

    @staticmethod
    def bulk_upsert(scan_id: str, data_type: str, items):
        if not items:
            return
        if isinstance(items, dict):
            items = [items]
        if not isinstance(items, list):
            return
        seen = set()  # in-batch dedupe
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                for item in items:
                    title = ""
                    if isinstance(item, dict):
                        title = item.get("title") or item.get("type") or item.get("name") or data_type
                    else:
                        title = str(item)[:200]
                        item = {"value": str(item)}
                    details_json = _dumps(item, default=str)
                    key = (title, hashlib.md5(details_json.encode("utf-8", "ignore")).hexdigest())
                    if key in seen:
                        continue
                    seen.add(key)
                    cur.execute("""
                        INSERT INTO post_exploit_data (scan_id, data_type, title, details)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (scan_id, data_type, title, md5(details::text))
                        DO NOTHING
                    """, (scan_id, data_type, title, details_json))
                conn.commit()

    @staticmethod
    def get_by_scan(scan_id: str, data_type: str = None) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if data_type:
                    cur.execute("SELECT * FROM post_exploit_data WHERE scan_id = %s AND data_type = %s ORDER BY created_at",
                                (scan_id, data_type))
                else:
                    cur.execute("SELECT * FROM post_exploit_data WHERE scan_id = %s ORDER BY data_type, created_at",
                                (scan_id,))
                return [dict(r) for r in cur.fetchall()]


class ScanMetadataRepo:

    @staticmethod
    def upsert(scan_id: str, key: str, value):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO scan_metadata (scan_id, key, value, updated_at)
                    VALUES (%s, %s, %s, NOW())
                    ON CONFLICT (scan_id, key) DO UPDATE SET
                        value = EXCLUDED.value, updated_at = NOW()
                """, (scan_id, key, _dumps(value, default=str)))
                conn.commit()

    @staticmethod
    def get(scan_id: str, key: str) -> Any:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT value FROM scan_metadata WHERE scan_id = %s AND key = %s",
                            (scan_id, key))
                row = cur.fetchone()
                return row[0] if row else None

    @staticmethod
    def get_all(scan_id: str) -> Dict[str, Any]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT key, value FROM scan_metadata WHERE scan_id = %s", (scan_id,))
                return {r[0]: r[1] for r in cur.fetchall()}


class ScanArtifactRepo:

    @staticmethod
    def insert(scan_id: str, kind: str, name: str, content,
                mime_type: str = "application/octet-stream",
                metadata: dict = None) -> int:
        if content is None:
            return 0
        if isinstance(content, str):
            content_bytes = content.encode("utf-8")
        elif isinstance(content, (bytes, bytearray)):
            content_bytes = bytes(content)
        else:
            content_bytes = str(content).encode("utf-8")
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO scan_artifacts
                            (scan_id, kind, name, mime_type, content, size_bytes, metadata)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (scan_id, kind, name or "", mime_type,
                          psycopg2.Binary(content_bytes), len(content_bytes),
                          _dumps(metadata or {}, default=str)))
                    aid = cur.fetchone()[0]
                    conn.commit()
                    return aid
        except Exception as e:
            logger.warning(f"[ScanArtifactRepo] insert failed ({kind}/{name}): {e}")
            return 0

    @staticmethod
    def list_by_scan(scan_id: str, kind: str = None) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if kind:
                    cur.execute("""
                        SELECT id, scan_id, kind, name, mime_type, size_bytes,
                               metadata, created_at
                        FROM scan_artifacts WHERE scan_id = %s AND kind = %s
                        ORDER BY created_at DESC
                    """, (scan_id, kind))
                else:
                    cur.execute("""
                        SELECT id, scan_id, kind, name, mime_type, size_bytes,
                               metadata, created_at
                        FROM scan_artifacts WHERE scan_id = %s
                        ORDER BY kind, created_at DESC
                    """, (scan_id,))
                return [dict(r) for r in cur.fetchall()]

    @staticmethod
    def get(artifact_id: int) -> Optional[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, scan_id, kind, name, mime_type, size_bytes,
                           metadata, content, created_at
                    FROM scan_artifacts WHERE id = %s
                """, (artifact_id,))
                row = cur.fetchone()
                if row and row.get("content") is not None:
                    row["content"] = bytes(row["content"])
                return dict(row) if row else None

    @staticmethod
    def counts_by_kind(scan_id: str) -> Dict[str, int]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT kind, COUNT(*), COALESCE(SUM(size_bytes), 0)
                    FROM scan_artifacts WHERE scan_id = %s GROUP BY kind
                """, (scan_id,))
                return {r[0]: {"count": r[1], "total_bytes": int(r[2])}
                        for r in cur.fetchall()}


def _encrypt_secret_field(value: str) -> Optional[str]:
    if value is None or value == "":
        return None
    import base64 as _b64
    from core.security.encryption import encrypt
    return _b64.b64encode(encrypt(value.encode("utf-8"))).decode("ascii")


def _decrypt_secret_field(value: Optional[str]) -> str:
    if not value:
        return ""
    import base64 as _b64
    from core.security.encryption import decrypt
    try:
        return decrypt(_b64.b64decode(value)).decode("utf-8", errors="replace")
    except Exception:
        # Legacy plaintext row (pre-fix) — return as-is. Operators should run
        # the one-shot migration to re-encrypt legacy rows.
        return str(value)


class AuthBypassRepo:

    @staticmethod
    def insert(scan_id: str, host: str, technique: str, login_url: str, *,
               method: str = "POST", username: str = "", password: str = "",
               payload: str = "", token: str = "",
               response_status: int = 0, response_snippet: str = "",
               role: str = "", severity: str = "critical") -> Optional[int]:
        dk_raw = f"{scan_id}|{host}|{technique}|{username}|{login_url}"
        dk = hashlib.sha1(dk_raw.encode("utf-8", "ignore")).hexdigest()[:32]
        try:
            enc_password = _encrypt_secret_field(password) or ""
            enc_token = _encrypt_secret_field(token) or ""
        except Exception as e:
            logger.error(f"AuthBypassRepo.insert: encryption failed, refusing to store plaintext: {e}")
            return None
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO auth_bypasses
                          (scan_id, host, method, login_url, technique, username, password,
                           payload, token, response_status, response_snippet, role, severity, dedup_key)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (scan_id, dedup_key) DO NOTHING
                        RETURNING id
                    """, (scan_id, host, method, login_url, technique, username, enc_password,
                          (payload or "")[:4000], enc_token,
                          int(response_status or 0), (response_snippet or "")[:2000],
                          role, severity, dk))
                    row = cur.fetchone()
                    conn.commit()
                    return row[0] if row else None
        except Exception:
            return None

    @staticmethod
    def get_by_scan(scan_id: str, reveal_secrets: bool = False) -> List[Dict[str, Any]]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, host, method, login_url, technique, username, password,
                           payload, token, response_status, response_snippet, role, severity,
                           created_at
                    FROM auth_bypasses WHERE scan_id = %s
                    ORDER BY created_at ASC
                """, (scan_id,))
                rows = [dict(r) for r in cur.fetchall()]

        for r in rows:
            if reveal_secrets:
                r["password"] = _decrypt_secret_field(r.get("password"))
                r["token"] = _decrypt_secret_field(r.get("token"))
            else:
                r["password"] = "[REDACTED]" if r.get("password") else ""
                r["token"] = "[REDACTED]" if r.get("token") else ""
        return rows

    @staticmethod
    def count_by_scan(scan_id: str) -> int:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM auth_bypasses WHERE scan_id = %s", (scan_id,))
                return int(cur.fetchone()[0] or 0)


class LiveAgentRepo:

    @staticmethod
    def upsert(scan_id: str, agent_id: str, *, label: str = "", phase: str = "",
               target: str = "", status: str = "queued", current_tool: str = "",
               current_step: str = "", steps_taken: Optional[int] = None,
               findings_count: Optional[int] = None, cost_usd: Optional[float] = None,
               started: bool = False, finished: bool = False,
               metadata: Optional[Dict] = None) -> None:
        sets = ["label = COALESCE(NULLIF(EXCLUDED.label,''), live_agents.label)",
                "phase = COALESCE(NULLIF(EXCLUDED.phase,''), live_agents.phase)",
                "target = COALESCE(NULLIF(EXCLUDED.target,''), live_agents.target)",
                "status = EXCLUDED.status",
                "current_tool = EXCLUDED.current_tool",
                "current_step = EXCLUDED.current_step",
                "updated_at = NOW()"]
        if steps_taken is not None:
            sets.append("steps_taken = EXCLUDED.steps_taken")
        if findings_count is not None:
            sets.append("findings_count = EXCLUDED.findings_count")
        if cost_usd is not None:
            sets.append("cost_usd = EXCLUDED.cost_usd")
        if started:
            sets.append("started_at = COALESCE(live_agents.started_at, NOW())")
        if finished:
            sets.append("finished_at = NOW()")
        if metadata is not None:
            sets.append("metadata = EXCLUDED.metadata")
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(f"""
                        INSERT INTO live_agents
                          (scan_id, agent_id, label, phase, target, status,
                           current_tool, current_step, steps_taken, findings_count,
                           cost_usd, started_at, finished_at, metadata)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                                CASE WHEN %s THEN NOW() ELSE NULL END,
                                CASE WHEN %s THEN NOW() ELSE NULL END,
                                %s)
                        ON CONFLICT (scan_id, agent_id) DO UPDATE SET
                          {', '.join(sets)}
                    """, (scan_id, agent_id, label, phase, target, status,
                          current_tool, current_step, steps_taken or 0,
                          findings_count or 0, cost_usd or 0.0,
                          started, finished, _dumps(metadata or {})))
                    conn.commit()
        except Exception as _e:
            logger.warning("pg_store.py: swallowed exception: %s", _e)

    @staticmethod
    def list_by_scan(scan_id: str) -> List[Dict[str, Any]]:
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("""
                        SELECT * FROM live_agents WHERE scan_id = %s
                        ORDER BY
                          CASE status WHEN 'running' THEN 0 WHEN 'queued' THEN 1
                                       WHEN 'failed' THEN 2 ELSE 3 END,
                          COALESCE(started_at, updated_at) DESC
                    """, (scan_id,))
                    return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []

    @staticmethod
    def counts_by_scan(scan_id: str) -> Dict[str, int]:
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT status, COUNT(*) FROM live_agents
                        WHERE scan_id = %s GROUP BY status
                    """, (scan_id,))
                    return {r[0]: int(r[1]) for r in cur.fetchall()}
        except Exception:
            return {}


class LLMMemoryRepo:

    @staticmethod
    def append(scan_id: str, phase: str, content: str, *,
                kind: str = "summary", tool: str = "", target: str = "") -> None:
        if not content or not content.strip():
            return
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO scan_llm_memory
                          (scan_id, phase, kind, content, tool, target)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (scan_id, phase or "", kind, content[:16000], tool or "", target or ""))
                    conn.commit()
        except Exception as _e:
            logger.warning("pg_store.py: swallowed exception: %s", _e)

    @staticmethod
    def get_by_scan(scan_id: str, kind: Optional[str] = None,
                     limit: int = 200) -> List[Dict[str, Any]]:
        try:
            with DatabaseManager.get_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    if kind:
                        cur.execute("""
                            SELECT * FROM scan_llm_memory
                            WHERE scan_id = %s AND kind = %s
                            ORDER BY created_at ASC LIMIT %s
                        """, (scan_id, kind, limit))
                    else:
                        cur.execute("""
                            SELECT * FROM scan_llm_memory
                            WHERE scan_id = %s
                            ORDER BY created_at ASC LIMIT %s
                        """, (scan_id, limit))
                    return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []
