import json
import uuid
from typing import List, Dict, Any
from datetime import datetime
import logging
from psycopg2.extras import RealDictCursor

from core.memory.database import DatabaseManager

logger = logging.getLogger(__name__)

class KnowledgeStore:
    """PostgreSQL-based persistent knowledge store.

    DEPRECATED. This `kb_*` schema was an early prototype that ran alongside
    the canonical `scans / vulnerabilities / findings_v2` tables and has
    since drifted from them (audit #153/#154). New code MUST write through
    the canonical repos in `core/database/pg_store.py`. This class is kept
    only so existing callers keep functioning while they migrate; every call
    logs a one-time deprecation warning.

    Removal target: after every caller has been migrated to `pg_store`
    repositories, delete this module and drop the `kb_*` tables. Until then
    set `KB_STRICT_DEPRECATION=1` to convert the warning into a `RuntimeError`
    (useful when running the test suite so new callers can't sneak in).
    """
    _deprecation_warned = False

    def __init__(self, db_path: str = None):
        # db_path is ignored now as we use the global Postgres pool
        if not KnowledgeStore._deprecation_warned:
            import os as _os_kb
            msg = ("core.knowledge.persistent_store.KnowledgeStore is DEPRECATED. "
                    "Use the canonical repos in core.database.pg_store instead.")
            if _os_kb.environ.get("KB_STRICT_DEPRECATION", "").strip() == "1":
                raise RuntimeError(msg)
            logger.warning(msg)
            KnowledgeStore._deprecation_warned = True
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema in PostgreSQL."""
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cursor:
                # Targets
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS kb_targets (
                        target_id TEXT PRIMARY KEY,
                        url_or_path TEXT UNIQUE,
                        target_type TEXT,
                        scope_validated BOOLEAN,
                        created_at TEXT
                    )
                ''')
                
                # Assets (domains, IPs, ports, services)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS kb_assets (
                        asset_id TEXT PRIMARY KEY,
                        target_id TEXT,
                        asset_type TEXT,
                        value TEXT,
                        metadata TEXT,
                        created_at TEXT,
                        FOREIGN KEY(target_id) REFERENCES kb_targets(target_id)
                    )
                ''')
                
                # Technologies
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS kb_technologies (
                        tech_id TEXT PRIMARY KEY,
                        asset_id TEXT,
                        name TEXT,
                        version TEXT,
                        confidence REAL,
                        source TEXT,
                        created_at TEXT,
                        FOREIGN KEY(asset_id) REFERENCES kb_assets(asset_id)
                    )
                ''')
                
                # Endpoints
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS kb_endpoints (
                        endpoint_id TEXT PRIMARY KEY,
                        asset_id TEXT,
                        path TEXT,
                        http_method TEXT,
                        status_code INTEGER,
                        content_type TEXT,
                        requires_auth BOOLEAN,
                        metadata TEXT,
                        discovered_at TEXT,
                        FOREIGN KEY(asset_id) REFERENCES kb_assets(asset_id)
                    )
                ''')
                
                # APIs
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS kb_apis (
                        api_id TEXT PRIMARY KEY,
                        asset_id TEXT,
                        api_type TEXT,
                        base_url TEXT,
                        endpoints_count INTEGER,
                        auth_type TEXT,
                        metadata TEXT,
                        discovered_at TEXT,
                        FOREIGN KEY(asset_id) REFERENCES kb_assets(asset_id)
                    )
                ''')
                
                # Findings
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS kb_findings (
                        finding_id TEXT PRIMARY KEY,
                        target_id TEXT,
                        title TEXT,
                        description TEXT,
                        severity TEXT,
                        confidence REAL,
                        status TEXT,
                        category TEXT,
                        cwe TEXT,
                        cve TEXT,
                        affected_asset TEXT,
                        affected_endpoint TEXT,
                        evidence TEXT,
                        remediation TEXT,
                        source_agent_id TEXT,
                        created_at TEXT,
                        updated_at TEXT,
                        FOREIGN KEY(target_id) REFERENCES kb_targets(target_id)
                    )
                ''')
                
                # Evidence
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS kb_evidence (
                        evidence_id TEXT PRIMARY KEY,
                        finding_id TEXT,
                        evidence_type TEXT,
                        content TEXT,
                        tool_name TEXT,
                        created_at TEXT,
                        FOREIGN KEY(finding_id) REFERENCES kb_findings(finding_id)
                    )
                ''')
                
                # Attack Paths
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS kb_attack_paths (
                        path_id TEXT PRIMARY KEY,
                        target_id TEXT,
                        name TEXT,
                        description TEXT,
                        steps TEXT,
                        status TEXT,
                        confidence REAL,
                        created_at TEXT,
                        FOREIGN KEY(target_id) REFERENCES kb_targets(target_id)
                    )
                ''')

                # Exploit Results
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS kb_exploit_results (
                        result_id TEXT PRIMARY KEY,
                        target_id TEXT,
                        vuln_id TEXT,
                        exploit_id TEXT,
                        payload TEXT,
                        success BOOLEAN,
                        proof TEXT,
                        severity TEXT,
                        executed_at TEXT,
                        FOREIGN KEY(target_id) REFERENCES kb_targets(target_id)
                    )
                ''')

                # Post Exploitation Findings
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS kb_post_exploit_findings (
                        pe_id TEXT PRIMARY KEY,
                        target_id TEXT,
                        type TEXT,
                        host TEXT,
                        technique TEXT,
                        detail TEXT,
                        severity TEXT,
                        metadata TEXT,
                        created_at TEXT,
                        FOREIGN KEY(target_id) REFERENCES kb_targets(target_id)
                    )
                ''')
                
                # Agents execution
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS kb_agents (
                        agent_id TEXT PRIMARY KEY,
                        task_id TEXT,
                        role TEXT,
                        capability TEXT,
                        state TEXT,
                        created_at TEXT,
                        completed_at TEXT
                    )
                ''')
                
                # Tasks execution
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS kb_tasks (
                        task_id TEXT PRIMARY KEY,
                        title TEXT,
                        objective TEXT,
                        capability TEXT,
                        priority INTEGER,
                        status TEXT,
                        assigned_agent_id TEXT,
                        created_at TEXT,
                        completed_at TEXT
                    )
                ''')

                # FK columns need indexes — Postgres does NOT create them
                # automatically for foreign keys, and every `WHERE fk = %s`
                # query on the kb_* tables previously did a full scan
                # (audit #154). All additive; safe on existing DBs.
                for stmt in (
                    "CREATE INDEX IF NOT EXISTS idx_kb_assets_target ON kb_assets(target_id)",
                    "CREATE INDEX IF NOT EXISTS idx_kb_technologies_asset ON kb_technologies(asset_id)",
                    "CREATE INDEX IF NOT EXISTS idx_kb_endpoints_asset ON kb_endpoints(asset_id)",
                    "CREATE INDEX IF NOT EXISTS idx_kb_apis_asset ON kb_apis(asset_id)",
                    "CREATE INDEX IF NOT EXISTS idx_kb_findings_target ON kb_findings(target_id)",
                    "CREATE INDEX IF NOT EXISTS idx_kb_evidence_finding ON kb_evidence(finding_id)",
                    "CREATE INDEX IF NOT EXISTS idx_kb_attack_paths_target ON kb_attack_paths(target_id)",
                    "CREATE INDEX IF NOT EXISTS idx_kb_exploit_results_target ON kb_exploit_results(target_id)",
                    "CREATE INDEX IF NOT EXISTS idx_kb_post_exploit_findings_target ON kb_post_exploit_findings(target_id)",
                ):
                    try:
                        cursor.execute(stmt)
                    except Exception as e:
                        logger.debug("kb_* index skipped: %s", e)
                conn.commit()
    
    def add_target(self, target_id: str, url_or_path: str, target_type: str):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cursor:
                try:
                    cursor.execute('''
                        INSERT INTO kb_targets (target_id, url_or_path, target_type, scope_validated, created_at)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (target_id) DO NOTHING
                    ''', (target_id, url_or_path, target_type, False, datetime.now().isoformat()))
                    conn.commit()
                    logger.debug(f"Added target: {target_id}")
                except Exception as e:
                    logger.debug(f"Failed to add target {target_id}: {e}")
                    conn.rollback()
    
    def add_asset(self, arg1: str = None, arg2: str = None, arg3: str = None, arg4: str = None,
                  asset_id: str = None, target_id: str = None, asset_type: str = None, value: str = None,
                  metadata: Any = None) -> str:
        if asset_id is None and target_id is None and asset_type is None and value is None:
            if arg4 is not None:
                asset_id, target_id, asset_type, value = arg1, arg2, arg3, arg4
            elif arg3 is not None:
                target_id, asset_type, value = arg1, arg2, arg3
                asset_id = f"ast_{uuid.uuid4().hex[:8]}"
            else:
                asset_id = arg1 or f"ast_{uuid.uuid4().hex[:8]}"
                target_id = arg2
        if not asset_id:
            asset_id = f"ast_{uuid.uuid4().hex[:8]}"
        
        meta_str = json.dumps(metadata) if isinstance(metadata, (dict, list)) else (metadata or "{}")
        
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cursor:
                try:
                    cursor.execute('''
                        INSERT INTO kb_assets (asset_id, target_id, asset_type, value, metadata, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (asset_id) DO NOTHING
                    ''', (asset_id, target_id, asset_type, value, meta_str, datetime.now().isoformat()))
                    conn.commit()
                except Exception:
                    conn.rollback()
        return asset_id
    
    def add_technology(self, arg1: str, arg2: str, arg3: str = None, arg4: str = None,
                       confidence: float = 1.0, source: str = "", tech_id: str = None, 
                       asset_id: str = None, name: str = None, version: str = None) -> str:
        if asset_id is None and name is None:
            if arg4 is not None:
                tech_id, asset_id, name = arg1, arg2, arg3
                version = arg4
            elif arg3 is not None:
                asset_id, name, version = arg1, arg2, arg3
                tech_id = tech_id or f"tch_{uuid.uuid4().hex[:8]}"
            else:
                asset_id, name = arg1, arg2
                tech_id = tech_id or f"tch_{uuid.uuid4().hex[:8]}"
        
        if not tech_id:
            tech_id = f"tch_{uuid.uuid4().hex[:8]}"
        if not asset_id:
            asset_id = "default_asset"
        
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cursor:
                try:
                    cursor.execute('''
                        INSERT INTO kb_technologies (tech_id, asset_id, name, version, confidence, source, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (tech_id) DO NOTHING
                    ''', (tech_id, asset_id, name, version, confidence, source, datetime.now().isoformat()))
                    conn.commit()
                except Exception:
                    conn.rollback()
        return tech_id
    
    def add_endpoint(self, endpoint_id: str = None, asset_id: str = None, path: str = "", http_method: str = "GET",
                    status_code: int = None, requires_auth: bool = False, target_id: str = None,
                    metadata: Any = None) -> str:
        if not endpoint_id:
            endpoint_id = f"ep_{uuid.uuid4().hex[:8]}"
        if not asset_id:
            asset_id = target_id or "default_asset"
        meta_str = json.dumps(metadata) if isinstance(metadata, (dict, list)) else (metadata or "{}")
        
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cursor:
                try:
                    cursor.execute('''
                        INSERT INTO kb_endpoints (endpoint_id, asset_id, path, http_method, status_code, 
                                              requires_auth, metadata, discovered_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (endpoint_id) DO NOTHING
                    ''', (endpoint_id, asset_id, path, http_method, status_code, requires_auth, 
                          meta_str, datetime.now().isoformat()))
                    conn.commit()
                except Exception:
                    conn.rollback()
        return endpoint_id
    
    def add_api(self, api_id: str = None, asset_id: str = None, api_type: str = "", base_url: str = "", auth_type: str = None) -> str:
        if not api_id:
            api_id = f"api_{uuid.uuid4().hex[:8]}"
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cursor:
                try:
                    cursor.execute('''
                        INSERT INTO kb_apis (api_id, asset_id, api_type, base_url, auth_type, discovered_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (api_id) DO NOTHING
                    ''', (api_id, asset_id, api_type, base_url, auth_type, datetime.now().isoformat()))
                    conn.commit()
                except Exception:
                    conn.rollback()
        return api_id
    
    def add_finding(self, finding_id: str = None, target_id: str = None, title: str = "Unknown", description: str = "",
                   severity: str = "MEDIUM", confidence: float = 0.5, status: str = "OBSERVED",
                   category: str = "", cwe: str = None, cve: str = None, affected_asset: str = "",
                   affected_endpoint: str = "", evidence: str = "", remediation: str = "",
                   source_agent_id: str = "") -> str:
        if not finding_id:
            finding_id = f"fnd_{uuid.uuid4().hex[:8]}"
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cursor:
                try:
                    cursor.execute('''
                        INSERT INTO kb_findings (finding_id, target_id, title, description, severity, 
                                             confidence, status, category, cwe, cve, affected_asset,
                                             affected_endpoint, evidence, remediation, source_agent_id,
                                             created_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (finding_id) DO NOTHING
                    ''', (finding_id, target_id, title, description, severity, confidence, status, 
                          category, cwe, cve, affected_asset, affected_endpoint, evidence, remediation,
                          source_agent_id, datetime.now().isoformat(), datetime.now().isoformat()))
                    conn.commit()
                except Exception:
                    conn.rollback()
        return finding_id
    
    def add_evidence(self, evidence_id: str = None, finding_id: str = None, evidence_type: str = "screenshot", content: str = "", tool_name: str = None) -> str:
        if not evidence_id:
            evidence_id = f"evd_{uuid.uuid4().hex[:8]}"
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cursor:
                try:
                    cursor.execute('''
                        INSERT INTO kb_evidence (evidence_id, finding_id, evidence_type, content, tool_name, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (evidence_id) DO NOTHING
                    ''', (evidence_id, finding_id, evidence_type, content, tool_name, datetime.now().isoformat()))
                    conn.commit()
                except Exception:
                    conn.rollback()
        return evidence_id

    def add_exploit_result(self, target_id: str, vuln_id: str = "", exploit_id: str = "", payload: str = "",
                          success: bool = False, proof: str = "", severity: str = "MEDIUM",
                          executed_at: str = None, result_id: str = None) -> str:
        if not result_id:
            result_id = f"xres_{uuid.uuid4().hex[:8]}"
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cursor:
                try:
                    cursor.execute('''
                        INSERT INTO kb_exploit_results (result_id, target_id, vuln_id, exploit_id, payload, success, proof, severity, executed_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (result_id) DO NOTHING
                    ''', (result_id, target_id, vuln_id, exploit_id, payload, success, proof, severity, executed_at or datetime.now().isoformat()))
                    conn.commit()
                except Exception:
                    conn.rollback()
        return result_id

    def add_post_exploit_finding(self, target_id: str, type: str = "", host: str = "", technique: str = "",
                                detail: str = "", severity: str = "MEDIUM", metadata: Any = None, pe_id: str = None) -> str:
        if not pe_id:
            pe_id = f"pe_{uuid.uuid4().hex[:8]}"
        meta_str = json.dumps(metadata) if isinstance(metadata, (dict, list)) else (metadata or "{}")
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cursor:
                try:
                    cursor.execute('''
                        INSERT INTO kb_post_exploit_findings (pe_id, target_id, type, host, technique, detail, severity, metadata, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (pe_id) DO NOTHING
                    ''', (pe_id, target_id, type, host, technique, detail, severity, meta_str, datetime.now().isoformat()))
                    conn.commit()
                except Exception:
                    conn.rollback()
        return pe_id
    
    def get_target_findings(self, target_id: str) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute('SELECT * FROM kb_findings WHERE target_id = %s', (target_id,))
                return cursor.fetchall()
    
    def get_target_assets(self, target_id: str) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute('SELECT * FROM kb_assets WHERE target_id = %s', (target_id,))
                return cursor.fetchall()
    
    def get_asset_technologies(self, asset_id: str) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute('SELECT * FROM kb_technologies WHERE asset_id = %s', (asset_id,))
                return cursor.fetchall()
    
    def get_asset_endpoints(self, asset_id: str) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute('SELECT * FROM kb_endpoints WHERE asset_id = %s', (asset_id,))
                return cursor.fetchall()
    
    def update_finding_status(self, finding_id: str, status: str):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('''
                    UPDATE kb_findings SET status = %s, updated_at = %s WHERE finding_id = %s
                ''', (status, datetime.now().isoformat(), finding_id))
                conn.commit()
    
    def get_all_findings(self, target_id: str) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # In PostgreSQL, we can use string_agg instead of GROUP_CONCAT
                cursor.execute('''
                    SELECT f.*, string_agg(e.content, '|') as evidence_list
                    FROM kb_findings f
                    LEFT JOIN kb_evidence e ON f.finding_id = e.finding_id
                    WHERE f.target_id = %s
                    GROUP BY f.finding_id
                ''', (target_id,))
                return cursor.fetchall()
    
    def export_database_summary(self) -> Dict[str, Any]:
        summary = {}
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                for table in ['kb_targets', 'kb_assets', 'kb_endpoints', 'kb_apis', 'kb_findings', 'kb_attack_paths', 'kb_agents', 'kb_tasks']:
                    cursor.execute(f'SELECT COUNT(*) as count FROM {table}')
                    summary[table] = cursor.fetchone()['count']
        return summary
