
import json
import logging
import time
from typing import Dict, List, Optional

from core.memory.database import DatabaseManager

logger = logging.getLogger(__name__)

TTL_CVE = 86400
TTL_EXPLOIT = 86400
TTL_MITRE = 604800
TTL_SHODAN = 86400
TTL_SEARCH = 3600


class KnowledgeBase:

    def __init__(self, db_path: str = None):
        pass

    # ── CVE Cache ──

    def cache_cves(self, cves: List[Dict]):
        now = time.time()
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                for cve in cves:
                    cur.execute("""
                        INSERT INTO cve_cache
                        (cve_id, cvss, severity, description, cwes, references_json,
                         published, modified, product, version, fetched_at, ttl)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (cve_id) DO UPDATE SET
                            cvss=EXCLUDED.cvss, severity=EXCLUDED.severity, description=EXCLUDED.description,
                            cwes=EXCLUDED.cwes, references_json=EXCLUDED.references_json,
                            fetched_at=EXCLUDED.fetched_at
                    """, (cve.get("cve_id", ""), cve.get("cvss", 0.0), cve.get("severity", ""),
                          cve.get("description", ""), json.dumps(cve.get("cwes", [])),
                          json.dumps(cve.get("references", [])), cve.get("published", ""),
                          cve.get("modified", ""), cve.get("product", ""), cve.get("version", ""),
                          now, TTL_CVE))
                conn.commit()
        logger.debug(f"Cached {len(cves)} CVEs")

    def get_cached_cves(self, product: str, version: str = "") -> Optional[List[Dict]]:
        now = time.time()
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                if version:
                    cur.execute("""
                        SELECT cve_id,cvss,severity,description,cwes,references_json,published,modified,product,version
                        FROM cve_cache WHERE product=%s AND version=%s AND (fetched_at+ttl)>%s ORDER BY cvss DESC
                    """, (product, version, now))
                else:
                    cur.execute("""
                        SELECT cve_id,cvss,severity,description,cwes,references_json,published,modified,product,version
                        FROM cve_cache WHERE product=%s AND (fetched_at+ttl)>%s ORDER BY cvss DESC
                    """, (product, now))
                rows = cur.fetchall()
        if not rows:
            return None
        results = []
        for r in rows:
            results.append({
                "cve_id": r[0], "cvss": r[1], "severity": r[2], "description": r[3],
                "cwes": json.loads(r[4] or "[]"), "references": json.loads(r[5] or "[]"),
                "published": r[6], "modified": r[7], "product": r[8], "version": r[9],
            })
        return results

    # ── Exploit Cache ──

    def cache_exploits(self, exploits: List[Dict], cve_id: str = "", keyword: str = ""):
        now = time.time()
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                for exp in exploits:
                    cur.execute("""
                        INSERT INTO exploit_cache
                        (cve_id, keyword, name, url, description, stars, language, reliability, clone_url, fetched_at, ttl)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """, (cve_id or exp.get("cve", ""), keyword, exp.get("name", ""),
                          exp.get("url", ""), exp.get("description", ""), exp.get("stars", 0),
                          exp.get("language", ""), exp.get("reliability", 0.0),
                          exp.get("clone_url", ""), now, TTL_EXPLOIT))
                conn.commit()

    def get_cached_exploits(self, cve_id: str = "", keyword: str = "") -> Optional[List[Dict]]:
        now = time.time()
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                if cve_id:
                    cur.execute("""
                        SELECT name,url,description,stars,language,reliability,clone_url
                        FROM exploit_cache WHERE cve_id=%s AND (fetched_at+ttl)>%s ORDER BY stars DESC
                    """, (cve_id, now))
                elif keyword:
                    cur.execute("""
                        SELECT name,url,description,stars,language,reliability,clone_url
                        FROM exploit_cache WHERE keyword=%s AND (fetched_at+ttl)>%s ORDER BY stars DESC
                    """, (keyword, now))
                else:
                    return None
                rows = cur.fetchall()
        if not rows:
            return None
        cols = ["name", "url", "description", "stars", "language", "reliability", "clone_url"]
        return [dict(zip(cols, r)) for r in rows]

    # ── MITRE Cache ──

    def cache_mitre(self, techniques: List[Dict]):
        now = time.time()
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                for tech in techniques:
                    cur.execute("""
                        INSERT INTO mitre_cache (technique_id,name,tactic,description,mitigations,detection,fetched_at,ttl)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (technique_id) DO UPDATE SET
                            name=EXCLUDED.name, fetched_at=EXCLUDED.fetched_at
                    """, (tech.get("id", ""), tech.get("name", ""), tech.get("tactic", ""),
                          tech.get("description", ""), json.dumps(tech.get("mitigations", [])),
                          json.dumps(tech.get("detection", [])), now, TTL_MITRE))
                conn.commit()

    def get_cached_mitre(self, technique_id: str) -> Optional[Dict]:
        now = time.time()
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT technique_id,name,tactic,description,mitigations,detection
                    FROM mitre_cache WHERE technique_id=%s AND (fetched_at+ttl)>%s
                """, (technique_id, now))
                row = cur.fetchone()
        if not row:
            return None
        return {
            "id": row[0], "name": row[1], "tactic": row[2], "description": row[3],
            "mitigations": json.loads(row[4]), "detection": json.loads(row[5]),
        }

    # ── Generic Search Cache ──

    def cache_search(self, query_key: str, result, source: str = "generic"):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO search_cache (query_key, result_json, source, fetched_at, ttl)
                    VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (query_key) DO UPDATE SET
                        result_json=EXCLUDED.result_json, fetched_at=EXCLUDED.fetched_at
                """, (query_key, json.dumps(result, default=str), source, time.time(), TTL_SEARCH))
                conn.commit()

    def get_cached_search(self, query_key: str) -> Optional:
        now = time.time()
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT result_json FROM search_cache WHERE query_key=%s AND (fetched_at+ttl)>%s",
                            (query_key, now))
                row = cur.fetchone()
        if row:
            return json.loads(row[0])
        return None

    # ── Decision Log ──

    def log_decision(self, phase: str, decision: str, context: str = "", result: str = ""):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO decision_log (timestamp, phase, decision, context, result)
                    VALUES (%s,%s,%s,%s,%s)
                """, (time.time(), phase, decision, context[:1000], result[:1000]))
                conn.commit()

    def get_decisions(self, phase: str = "", limit: int = 50) -> List[Dict]:
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                if phase:
                    cur.execute("""
                        SELECT timestamp,phase,decision,context,result FROM decision_log
                        WHERE phase=%s ORDER BY timestamp DESC LIMIT %s
                    """, (phase, limit))
                else:
                    cur.execute("""
                        SELECT timestamp,phase,decision,context,result FROM decision_log
                        ORDER BY timestamp DESC LIMIT %s
                    """, (limit,))
                rows = cur.fetchall()
        return [{"timestamp": r[0], "phase": r[1], "decision": r[2], "context": r[3], "result": r[4]} for r in rows]

    # ── Cache Management ──

    def invalidate_expired(self):
        now = time.time()
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                for table in ["cve_cache", "exploit_cache", "mitre_cache", "search_cache"]:
                    cur.execute(f"DELETE FROM {table} WHERE (fetched_at + ttl) < %s", (now,))
                conn.commit()
        logger.info("Invalidated expired cache entries")

    def get_stats(self) -> Dict:
        stats = {}
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                for table in ["cve_cache", "exploit_cache", "mitre_cache", "search_cache", "decision_log"]:
                    cur.execute(f"SELECT COUNT(*) FROM {table}")
                    stats[table] = cur.fetchone()[0]
        return stats

    def clear_all(self):
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                for table in ["cve_cache", "exploit_cache", "mitre_cache", "search_cache"]:
                    cur.execute(f"DELETE FROM {table}")
                conn.commit()
        logger.info("Cache cleared")
