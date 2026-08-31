"""
KnowledgeBase - SQLite cache for intelligence data.
Prevents redundant API calls. TTL-based expiry.
Phase 1 of Enterprise system.
"""

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Default TTLs (seconds)
TTL_CVE = 86400        # 24 hours
TTL_EXPLOIT = 86400    # 24 hours
TTL_MITRE = 604800     # 7 days
TTL_SHODAN = 86400     # 24 hours
TTL_SEARCH = 3600      # 1 hour


class KnowledgeBase:
    """SQLite-backed intelligence cache with TTL expiry."""

    def __init__(self, db_path: str = "knowledge_base.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Create tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                cvss REAL,
                severity TEXT,
                description TEXT,
                cwes TEXT,
                references_json TEXT,
                published TEXT,
                modified TEXT,
                product TEXT,
                version TEXT,
                fetched_at REAL,
                ttl INTEGER DEFAULT 86400
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS exploit_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                keyword TEXT,
                name TEXT,
                url TEXT,
                description TEXT,
                stars INTEGER,
                language TEXT,
                reliability REAL,
                clone_url TEXT,
                fetched_at REAL,
                ttl INTEGER DEFAULT 86400
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS mitre_cache (
                technique_id TEXT PRIMARY KEY,
                name TEXT,
                tactic TEXT,
                description TEXT,
                mitigations TEXT,
                detection TEXT,
                fetched_at REAL,
                ttl INTEGER DEFAULT 604800
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS search_cache (
                query_key TEXT PRIMARY KEY,
                result_json TEXT,
                source TEXT,
                fetched_at REAL,
                ttl INTEGER DEFAULT 3600
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS decision_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                phase TEXT,
                decision TEXT,
                context TEXT,
                result TEXT
            )
        """)

        # Index for faster lookups
        c.execute("CREATE INDEX IF NOT EXISTS idx_cve_product ON cve_cache(product, version)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_exploit_cve ON exploit_cache(cve_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_exploit_kw ON exploit_cache(keyword)")

        conn.commit()
        conn.close()
        logger.info(f"KnowledgeBase initialized: {self.db_path}")

    # ═══════════════════════════════════════════════════════════════
    # CVE Cache
    # ═══════════════════════════════════════════════════════════════

    def cache_cves(self, cves: List[Dict]):
        """Store CVE results in cache."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = time.time()

        for cve in cves:
            c.execute("""
                INSERT OR REPLACE INTO cve_cache
                (cve_id, cvss, severity, description, cwes, references_json,
                 published, modified, product, version, fetched_at, ttl)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve.get("cve_id", ""),
                cve.get("cvss", 0.0),
                cve.get("severity", ""),
                cve.get("description", ""),
                json.dumps(cve.get("cwes", [])),
                json.dumps(cve.get("references", [])),
                cve.get("published", ""),
                cve.get("modified", ""),
                cve.get("product", ""),
                cve.get("version", ""),
                now,
                TTL_CVE,
            ))

        conn.commit()
        conn.close()
        logger.debug(f"Cached {len(cves)} CVEs")

    def get_cached_cves(self, product: str, version: str = "") -> Optional[List[Dict]]:
        """Get cached CVEs if not expired."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = time.time()

        if version:
            c.execute("""
                SELECT * FROM cve_cache
                WHERE product = ? AND version = ? AND (fetched_at + ttl) > ?
                ORDER BY cvss DESC
            """, (product, version, now))
        else:
            c.execute("""
                SELECT * FROM cve_cache
                WHERE product = ? AND (fetched_at + ttl) > ?
                ORDER BY cvss DESC
            """, (product, now))

        rows = c.fetchall()
        conn.close()

        if not rows:
            return None

        columns = [
            "cve_id", "cvss", "severity", "description", "cwes",
            "references_json", "published", "modified", "product",
            "version", "fetched_at", "ttl"
        ]

        results = []
        for row in rows:
            cve = dict(zip(columns, row))
            cve["cwes"] = json.loads(cve.get("cwes", "[]"))
            cve["references"] = json.loads(cve.get("references_json", "[]"))
            del cve["references_json"]
            del cve["fetched_at"]
            del cve["ttl"]
            results.append(cve)

        logger.debug(f"Cache hit: {len(results)} CVEs for '{product} {version}'")
        return results

    # ═══════════════════════════════════════════════════════════════
    # Exploit Cache
    # ═══════════════════════════════════════════════════════════════

    def cache_exploits(self, exploits: List[Dict], cve_id: str = "", keyword: str = ""):
        """Store exploit search results."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = time.time()

        for exp in exploits:
            c.execute("""
                INSERT INTO exploit_cache
                (cve_id, keyword, name, url, description, stars, language,
                 reliability, clone_url, fetched_at, ttl)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve_id or exp.get("cve", ""),
                keyword,
                exp.get("name", ""),
                exp.get("url", ""),
                exp.get("description", ""),
                exp.get("stars", 0),
                exp.get("language", ""),
                exp.get("reliability", 0.0),
                exp.get("clone_url", ""),
                now,
                TTL_EXPLOIT,
            ))

        conn.commit()
        conn.close()

    def get_cached_exploits(self, cve_id: str = "", keyword: str = "") -> Optional[List[Dict]]:
        """Get cached exploits if not expired."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = time.time()

        if cve_id:
            c.execute("""
                SELECT name, url, description, stars, language, reliability, clone_url
                FROM exploit_cache
                WHERE cve_id = ? AND (fetched_at + ttl) > ?
                ORDER BY stars DESC
            """, (cve_id, now))
        elif keyword:
            c.execute("""
                SELECT name, url, description, stars, language, reliability, clone_url
                FROM exploit_cache
                WHERE keyword = ? AND (fetched_at + ttl) > ?
                ORDER BY stars DESC
            """, (keyword, now))
        else:
            conn.close()
            return None

        rows = c.fetchall()
        conn.close()

        if not rows:
            return None

        columns = ["name", "url", "description", "stars", "language", "reliability", "clone_url"]
        return [dict(zip(columns, row)) for row in rows]

    # ═══════════════════════════════════════════════════════════════
    # MITRE Cache
    # ═══════════════════════════════════════════════════════════════

    def cache_mitre(self, techniques: List[Dict]):
        """Store MITRE technique data."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = time.time()

        for tech in techniques:
            c.execute("""
                INSERT OR REPLACE INTO mitre_cache
                (technique_id, name, tactic, description, mitigations, detection, fetched_at, ttl)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tech.get("id", ""),
                tech.get("name", ""),
                tech.get("tactic", ""),
                tech.get("description", ""),
                json.dumps(tech.get("mitigations", [])),
                json.dumps(tech.get("detection", [])),
                now,
                TTL_MITRE,
            ))

        conn.commit()
        conn.close()

    def get_cached_mitre(self, technique_id: str) -> Optional[Dict]:
        """Get cached MITRE technique."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = time.time()

        c.execute("""
            SELECT technique_id, name, tactic, description, mitigations, detection
            FROM mitre_cache
            WHERE technique_id = ? AND (fetched_at + ttl) > ?
        """, (technique_id, now))

        row = c.fetchone()
        conn.close()

        if not row:
            return None

        return {
            "id": row[0], "name": row[1], "tactic": row[2],
            "description": row[3],
            "mitigations": json.loads(row[4]),
            "detection": json.loads(row[5]),
        }

    # ═══════════════════════════════════════════════════════════════
    # Generic Search Cache
    # ═══════════════════════════════════════════════════════════════

    def cache_search(self, query_key: str, result: any, source: str = "generic"):
        """Cache any search result by query key."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO search_cache
            (query_key, result_json, source, fetched_at, ttl)
            VALUES (?, ?, ?, ?, ?)
        """, (query_key, json.dumps(result, default=str), source, time.time(), TTL_SEARCH))
        conn.commit()
        conn.close()

    def get_cached_search(self, query_key: str) -> Optional[any]:
        """Get cached search result."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = time.time()

        c.execute("""
            SELECT result_json FROM search_cache
            WHERE query_key = ? AND (fetched_at + ttl) > ?
        """, (query_key, now))

        row = c.fetchone()
        conn.close()

        if row:
            return json.loads(row[0])
        return None

    # ═══════════════════════════════════════════════════════════════
    # Decision Log
    # ═══════════════════════════════════════════════════════════════

    def log_decision(self, phase: str, decision: str, context: str = "", result: str = ""):
        """Log brain decision for audit trail."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO decision_log (timestamp, phase, decision, context, result)
            VALUES (?, ?, ?, ?, ?)
        """, (time.time(), phase, decision, context[:1000], result[:1000]))
        conn.commit()
        conn.close()

    def get_decisions(self, phase: str = "", limit: int = 50) -> List[Dict]:
        """Get decision log entries."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        if phase:
            c.execute("""
                SELECT timestamp, phase, decision, context, result
                FROM decision_log WHERE phase = ?
                ORDER BY timestamp DESC LIMIT ?
            """, (phase, limit))
        else:
            c.execute("""
                SELECT timestamp, phase, decision, context, result
                FROM decision_log
                ORDER BY timestamp DESC LIMIT ?
            """, (limit,))

        rows = c.fetchall()
        conn.close()

        return [
            {"timestamp": r[0], "phase": r[1], "decision": r[2],
             "context": r[3], "result": r[4]}
            for r in rows
        ]

    # ═══════════════════════════════════════════════════════════════
    # Cache Management
    # ═══════════════════════════════════════════════════════════════

    def invalidate_expired(self):
        """Remove all expired entries."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        now = time.time()

        for table in ["cve_cache", "exploit_cache", "mitre_cache", "search_cache"]:
            c.execute(f"DELETE FROM {table} WHERE (fetched_at + ttl) < ?", (now,))

        deleted = conn.total_changes
        conn.commit()
        conn.close()
        logger.info(f"Invalidated {deleted} expired cache entries")

    def get_stats(self) -> Dict:
        """Get cache statistics."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        stats = {}
        for table in ["cve_cache", "exploit_cache", "mitre_cache", "search_cache", "decision_log"]:
            c.execute(f"SELECT COUNT(*) FROM {table}")
            stats[table] = c.fetchone()[0]

        conn.close()
        return stats

    def clear_all(self):
        """Clear entire cache (for testing)."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        for table in ["cve_cache", "exploit_cache", "mitre_cache", "search_cache"]:
            c.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()
        logger.info("Cache cleared")