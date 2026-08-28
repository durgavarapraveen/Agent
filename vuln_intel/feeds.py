"""
Vulnerability Intelligence Feeds Module.
Queries NIST NVD API v2.0, EPSS API, and CISA KEV catalog for real-time CVE lookup and exploit intelligence.
"""

import json
import logging
import sqlite3
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Any

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"


@dataclass
class FeedResult:
    """Container for feed item results."""
    data: Any = field(default_factory=dict)
    stale: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class CacheDB:
    """In-memory and SQLite cache storage helper for vulnerability intelligence feeds."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS feed_cache "
                    "(key TEXT PRIMARY KEY, value TEXT, updated_at TIMESTAMP)"
                )
        except Exception as e:
            logger.debug(f"CacheDB init notice: {e}")

    def get(self, key: str) -> Optional[Any]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.cursor()
                cur.execute("SELECT value FROM feed_cache WHERE key=?", (key,))
                row = cur.fetchone()
                if row:
                    return json.loads(row[0])
        except Exception:
            pass
        return None

    def set(self, key: str, value: Any):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO feed_cache (key, value, updated_at) VALUES (?, ?, ?)",
                    (key, json.dumps(value), datetime.now().isoformat())
                )
        except Exception:
            pass


class FeedClient:
    """Async & synchronous multi-source vulnerability intelligence feed client (EPSS, KEV, NVD)."""

    def __init__(self, timeout: int = 5, api_key: Optional[str] = None):
        self.timeout = timeout
        self.api_key = api_key
        self.cache = CacheDB()
        self._kev_set_cache: Optional[Set[str]] = None

    def _get_headers(self) -> Dict[str, str]:
        headers = {"User-Agent": "VulnerabilityIntelligenceFeed/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    async def epss(self, cve_ids: List[str]) -> FeedResult:
        """Fetch EPSS probabilities for a list of CVE IDs."""
        if not cve_ids:
            return FeedResult(data={"data": []}, stale=False)

        cve_param = ",".join(cve_ids[:50])
        url = f"{EPSS_API_URL}?cve={cve_param}"

        try:
            req = urllib.request.Request(url, headers=self._get_headers(), method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return FeedResult(data=data, stale=False)
        except Exception as e:
            logger.warning(f"EPSS_FETCH_FAILED: {e}")

        return FeedResult(data={"data": []}, stale=True)

    async def kev_cve_ids(self) -> Set[str]:
        """Return the set of known exploited CVE IDs from CISA KEV catalog."""
        if self._kev_set_cache is not None:
            return self._kev_set_cache

        cve_set = set()
        try:
            req = urllib.request.Request(CISA_KEV_URL, headers=self._get_headers(), method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    for vuln in data.get("vulnerabilities", []):
                        cid = str(vuln.get("cveID", "")).strip().upper()
                        if cid:
                            cve_set.add(cid)
                    self._kev_set_cache = cve_set
                    return cve_set
        except Exception as e:
            logger.warning(f"CISA_KEV_FETCH_FAILED: {e}")

        self._kev_set_cache = cve_set
        return cve_set


class CVEDatabase:
    """NIST NVD REST API v2.0 client with in-memory caching and CISA KEV exploit intelligence."""

    def __init__(self, api_key: Optional[str] = None, timeout: int = 5):
        self.api_key = api_key
        self.timeout = timeout
        self.cache: Dict[str, List[Dict[str, Any]]] = {}
        self.cisa_kev_cache: Optional[Dict[str, Any]] = None

    def _get_headers(self) -> Dict[str, str]:
        headers = {"User-Agent": "VulnerabilityIntelligenceFeed/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def search_cve_for_software(self, software: str, version: str) -> List[Dict[str, Any]]:
        """
        Query NVD API v2.0 for matching CVEs based on software name and version.
        Uses in-memory caching indexed by '{software}:{version}'.
        """
        soft_clean = (software or "").strip().lower()
        ver_clean = (version or "").strip().lower()
        cache_key = f"{soft_clean}:{ver_clean}"

        if cache_key in self.cache:
            logger.debug(f"CVE_CACHE_HIT: key='{cache_key}'")
            return self.cache[cache_key]

        if not soft_clean:
            return []

        keyword = f"{soft_clean} {ver_clean}".strip()
        params = {"keywordSearch": keyword, "resultsPerPage": 5}
        query_str = urllib.parse.urlencode(params)
        url = f"{NVD_API_URL}?{query_str}"

        results = []
        try:
            req = urllib.request.Request(url, headers=self._get_headers(), method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    results = self._parse_nvd_response(data)
        except Exception as e:
            logger.warning(f"NVD_API_REQUEST_FAILED: keyword='{keyword}' error='{e}'")
            results = []

        self.cache[cache_key] = results
        return results

    def _parse_nvd_response(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        cve_items = []
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "UNKNOWN")

            # Parse English description
            descriptions = cve_data.get("descriptions", [])
            desc_text = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc_text = d.get("value", "")
                    break

            # Parse CVSS v3.1 / v3.0 score
            metrics = cve_data.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v30 = metrics.get("cvssMetricV30", [])

            cvss_score = 0.0
            if cvss_v31:
                cvss_score = cvss_v31[0].get("cvssData", {}).get("baseScore", 0.0)
            elif cvss_v30:
                cvss_score = cvss_v30[0].get("cvssData", {}).get("baseScore", 0.0)

            # References
            refs = [r.get("url") for r in cve_data.get("references", []) if r.get("url")]

            cve_items.append({
                "cve_id": cve_id,
                "description": desc_text,
                "cvss_score": float(cvss_score),
                "references": refs[:5]
            })

        return cve_items

    def fetch_cisa_kev_catalog(self) -> Dict[str, Any]:
        """Fetch and cache the official CISA KEV catalog feed."""
        if self.cisa_kev_cache is not None:
            return self.cisa_kev_cache

        try:
            req = urllib.request.Request(CISA_KEV_URL, headers=self._get_headers(), method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    self.cisa_kev_cache = data
                    return data
        except Exception as e:
            logger.warning(f"CISA_KEV_FETCH_FAILED: {e}")

        self.cisa_kev_cache = {"vulnerabilities": []}
        return self.cisa_kev_cache

    def get_exploit_availability(self, cve_id: str) -> Dict[str, Any]:
        """
        Check whether a CVE ID is listed in the CISA Known Exploited Vulnerabilities (KEV) catalog
        or public Exploit-DB references.
        """
        cve_clean = (cve_id or "").strip().upper()
        if not cve_clean:
            return {"has_public_exploit": False, "exploit_url": "", "source": "none"}

        kev_data = self.fetch_cisa_kev_catalog()
        vulnerabilities = kev_data.get("vulnerabilities", [])

        for item in vulnerabilities:
            if item.get("cveID", "").upper() == cve_clean:
                return {
                    "has_public_exploit": True,
                    "exploit_url": f"https://nvd.nist.gov/vuln/detail/{cve_clean}",
                    "source": "CISA Known Exploited Vulnerabilities (KEV) Catalog",
                    "action_required": item.get("requiredAction", ""),
                    "short_description": item.get("shortDescription", "")
                }

        # Exploit-DB search reference fallback
        return {
            "has_public_exploit": False,
            "exploit_url": f"https://www.exploit-db.com/search?cve={cve_clean}",
            "source": "Exploit-DB Reference"
        }
