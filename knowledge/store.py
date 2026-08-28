import sqlite3
import json
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class KnowledgeStore:
    """SQLite-based persistent knowledge store."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _get_connection(self):
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_database(self):
        """Initialize database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Targets
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                target_id TEXT PRIMARY KEY,
                url_or_path TEXT UNIQUE,
                target_type TEXT,
                scope_validated BOOLEAN,
                created_at TEXT
            )
        ''')
        
        # Assets (domains, IPs, ports, services)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                target_id TEXT,
                asset_type TEXT,
                value TEXT,
                metadata TEXT,
                created_at TEXT,
                FOREIGN KEY(target_id) REFERENCES targets(target_id)
            )
        ''')
        
        # Technologies
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS technologies (
                tech_id TEXT PRIMARY KEY,
                asset_id TEXT,
                name TEXT,
                version TEXT,
                confidence REAL,
                source TEXT,
                created_at TEXT,
                FOREIGN KEY(asset_id) REFERENCES assets(asset_id)
            )
        ''')
        
        # URLs and Endpoints
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS endpoints (
                endpoint_id TEXT PRIMARY KEY,
                asset_id TEXT,
                path TEXT,
                http_method TEXT,
                status_code INTEGER,
                content_type TEXT,
                requires_auth BOOLEAN,
                metadata TEXT,
                discovered_at TEXT,
                FOREIGN KEY(asset_id) REFERENCES assets(asset_id)
            )
        ''')
        
        # APIs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS apis (
                api_id TEXT PRIMARY KEY,
                asset_id TEXT,
                api_type TEXT,
                base_url TEXT,
                endpoints_count INTEGER,
                auth_type TEXT,
                metadata TEXT,
                discovered_at TEXT,
                FOREIGN KEY(asset_id) REFERENCES assets(asset_id)
            )
        ''')
        
        # Findings
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
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
                FOREIGN KEY(target_id) REFERENCES targets(target_id)
            )
        ''')
        
        # Evidence
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                finding_id TEXT,
                evidence_type TEXT,
                content TEXT,
                tool_name TEXT,
                created_at TEXT,
                FOREIGN KEY(finding_id) REFERENCES findings(finding_id)
            )
        ''')
        
        # Attack Paths
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_paths (
                path_id TEXT PRIMARY KEY,
                target_id TEXT,
                name TEXT,
                description TEXT,
                steps TEXT,
                status TEXT,
                confidence REAL,
                created_at TEXT,
                FOREIGN KEY(target_id) REFERENCES targets(target_id)
            )
        ''')

        # Exploit Results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exploit_results (
                result_id TEXT PRIMARY KEY,
                target_id TEXT,
                vuln_id TEXT,
                exploit_id TEXT,
                payload TEXT,
                success BOOLEAN,
                proof TEXT,
                severity TEXT,
                executed_at TEXT,
                FOREIGN KEY(target_id) REFERENCES targets(target_id)
            )
        ''')

        # Post Exploitation Findings
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS post_exploit_findings (
                pe_id TEXT PRIMARY KEY,
                target_id TEXT,
                type TEXT,
                host TEXT,
                technique TEXT,
                detail TEXT,
                severity TEXT,
                metadata TEXT,
                created_at TEXT,
                FOREIGN KEY(target_id) REFERENCES targets(target_id)
            )
        ''')
        
        # Agents execution
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agents (
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
            CREATE TABLE IF NOT EXISTS tasks (
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
        
        conn.commit()
        conn.close()
    
    def add_target(self, target_id: str, url_or_path: str, target_type: str):
        """Add a target."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO targets (target_id, url_or_path, target_type, scope_validated, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (target_id, url_or_path, target_type, False, datetime.now().isoformat()))
            conn.commit()
            logger.debug(f"Added target: {target_id}")
        except sqlite3.IntegrityError:
            logger.debug(f"Target already exists: {target_id}")
        finally:
            conn.close()
    
    def add_asset(self, arg1: str = None, arg2: str = None, arg3: str = None, arg4: str = None,
                  asset_id: str = None, target_id: str = None, asset_type: str = None, value: str = None,
                  metadata: Any = None) -> str:
        """Add an asset (domain, IP, port, service, etc). Supports flexible signature."""
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
        
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO assets (asset_id, target_id, asset_type, value, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (asset_id, target_id, asset_type, value, meta_str, datetime.now().isoformat()))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()
        return asset_id
    
    def add_technology(self, arg1: str, arg2: str, arg3: str = None, arg4: str = None,
                       confidence: float = 1.0, source: str = "", tech_id: str = None, 
                       asset_id: str = None, name: str = None, version: str = None) -> str:
        """Add a technology discovery. Supports flexible positional signatures."""
        if asset_id is None and name is None:
            if arg4 is not None:
                # 4+ positional: tech_id, asset_id, name, version
                tech_id, asset_id, name = arg1, arg2, arg3
                version = arg4
            elif arg3 is not None:
                # 3 positional: asset_id, name, version
                asset_id, name, version = arg1, arg2, arg3
                tech_id = tech_id or f"tch_{uuid.uuid4().hex[:8]}"
            else:
                asset_id, name = arg1, arg2
                tech_id = tech_id or f"tch_{uuid.uuid4().hex[:8]}"
        
        if not tech_id:
            tech_id = f"tch_{uuid.uuid4().hex[:8]}"
        if not asset_id:
            asset_id = "default_asset"
        
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO technologies (tech_id, asset_id, name, version, confidence, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (tech_id, asset_id, name, version, confidence, source, datetime.now().isoformat()))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()
        return tech_id
    
    def add_endpoint(self, endpoint_id: str = None, asset_id: str = None, path: str = "", http_method: str = "GET",
                    status_code: int = None, requires_auth: bool = False, target_id: str = None,
                    metadata: Any = None) -> str:
        """Add an endpoint discovery."""
        if not endpoint_id:
            endpoint_id = f"ep_{uuid.uuid4().hex[:8]}"
        if not asset_id:
            asset_id = target_id or "default_asset"
        meta_str = json.dumps(metadata) if isinstance(metadata, (dict, list)) else (metadata or "{}")
        
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO endpoints (endpoint_id, asset_id, path, http_method, status_code, 
                                      requires_auth, metadata, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (endpoint_id, asset_id, path, http_method, status_code, requires_auth, 
                  meta_str, datetime.now().isoformat()))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()
        return endpoint_id
    
    def add_api(self, api_id: str = None, asset_id: str = None, api_type: str = "", base_url: str = "", auth_type: str = None) -> str:
        """Add an API discovery."""
        if not api_id:
            api_id = f"api_{uuid.uuid4().hex[:8]}"
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO apis (api_id, asset_id, api_type, base_url, auth_type, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (api_id, asset_id, api_type, base_url, auth_type, datetime.now().isoformat()))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()
        return api_id
    
    def add_finding(self, finding_id: str = None, target_id: str = None, title: str = "Unknown", description: str = "",
                   severity: str = "MEDIUM", confidence: float = 0.5, status: str = "OBSERVED",
                   category: str = "", cwe: str = None, cve: str = None, affected_asset: str = "",
                   affected_endpoint: str = "", evidence: str = "", remediation: str = "",
                   source_agent_id: str = "") -> str:
        """Add a finding."""
        if not finding_id:
            finding_id = f"fnd_{uuid.uuid4().hex[:8]}"
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO findings (finding_id, target_id, title, description, severity, 
                                     confidence, status, category, cwe, cve, affected_asset,
                                     affected_endpoint, evidence, remediation, source_agent_id,
                                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (finding_id, target_id, title, description, severity, confidence, status, 
                  category, cwe, cve, affected_asset, affected_endpoint, evidence, remediation,
                  source_agent_id, datetime.now().isoformat(), datetime.now().isoformat()))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()
        return finding_id
    
    def add_evidence(self, evidence_id: str = None, finding_id: str = None, evidence_type: str = "screenshot", content: str = "", tool_name: str = None) -> str:
        """Add evidence for a finding."""
        if not evidence_id:
            evidence_id = f"evd_{uuid.uuid4().hex[:8]}"
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO evidence (evidence_id, finding_id, evidence_type, content, tool_name, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (evidence_id, finding_id, evidence_type, content, tool_name, datetime.now().isoformat()))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()
        return evidence_id

    def add_exploit_result(self, target_id: str, vuln_id: str = "", exploit_id: str = "", payload: str = "",
                          success: bool = False, proof: str = "", severity: str = "MEDIUM",
                          executed_at: str = None, result_id: str = None) -> str:
        """Add an exploit result."""
        if not result_id:
            result_id = f"xres_{uuid.uuid4().hex[:8]}"
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO exploit_results (result_id, target_id, vuln_id, exploit_id, payload, success, proof, severity, executed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (result_id, target_id, vuln_id, exploit_id, payload, success, proof, severity, executed_at or datetime.now().isoformat()))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()
        return result_id

    def add_post_exploit_finding(self, target_id: str, type: str = "", host: str = "", technique: str = "",
                                detail: str = "", severity: str = "MEDIUM", metadata: Any = None, pe_id: str = None) -> str:
        """Add a post-exploitation finding."""
        if not pe_id:
            pe_id = f"pe_{uuid.uuid4().hex[:8]}"
        meta_str = json.dumps(metadata) if isinstance(metadata, (dict, list)) else (metadata or "{}")
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO post_exploit_findings (pe_id, target_id, type, host, technique, detail, severity, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (pe_id, target_id, type, host, technique, detail, severity, meta_str, datetime.now().isoformat()))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        finally:
            conn.close()
        return pe_id
    
    def get_target_findings(self, target_id: str) -> List[Dict]:
        """Get all findings for a target."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM findings WHERE target_id = ?', (target_id,))
        findings = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return findings
    
    def get_target_assets(self, target_id: str) -> List[Dict]:
        """Get all assets for a target."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM assets WHERE target_id = ?', (target_id,))
        assets = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return assets
    
    def get_asset_technologies(self, asset_id: str) -> List[Dict]:
        """Get technologies for an asset."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM technologies WHERE asset_id = ?', (asset_id,))
        techs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return techs
    
    def get_asset_endpoints(self, asset_id: str) -> List[Dict]:
        """Get endpoints for an asset."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM endpoints WHERE asset_id = ?', (asset_id,))
        endpoints = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return endpoints
    
    def update_finding_status(self, finding_id: str, status: str):
        """Update finding status."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE findings SET status = ?, updated_at = ? WHERE finding_id = ?
        ''', (status, datetime.now().isoformat(), finding_id))
        conn.commit()
        conn.close()
    
    def get_all_findings(self, target_id: str) -> List[Dict]:
        """Get all findings with evidence."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.*, GROUP_CONCAT(e.content, '|') as evidence_list
            FROM findings f
            LEFT JOIN evidence e ON f.finding_id = e.finding_id
            WHERE f.target_id = ?
            GROUP BY f.finding_id
        ''', (target_id,))
        findings = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return findings
    
    def export_database_summary(self) -> Dict[str, Any]:
        """Export a summary of the database."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        summary = {}
        for table in ['targets', 'assets', 'endpoints', 'apis', 'findings', 'attack_paths', 'agents', 'tasks']:
            cursor.execute(f'SELECT COUNT(*) as count FROM {table}')
            summary[table] = cursor.fetchone()['count']
        
        conn.close()
        return summary
