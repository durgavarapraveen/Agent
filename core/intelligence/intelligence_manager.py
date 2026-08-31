"""
IntelligenceManager - Glue between brain, fetcher, cache, and installer.
Brain calls this. Manager handles cache-first lookup, API fallback, caching.
Phase 1 of Enterprise system.
"""

import logging
import re
from typing import Dict, List, Optional, Tuple

from core.config import get_config
from core.intelligence_fetcher import IntelligenceFetcher
from core.knowledge_base import KnowledgeBase
from core.tool_installer import ToolInstaller

logger = logging.getLogger(__name__)


class IntelligenceManager:
    """
    Single entry point for all intelligence operations.
    Brain calls this instead of fetcher/cache/installer directly.

    Usage:
        intel = IntelligenceManager()
        cves = await intel.lookup_cves("apache", "2.4.49")
        exploits = await intel.find_exploits("CVE-2021-41773")
        mitre = await intel.get_mitre_techniques("sqli")
        intel.ensure_tool("ffuf")
    """

    def __init__(self):
        config = get_config()
        self.fetcher = IntelligenceFetcher(
            shodan_key=config.get("SHODAN_API_KEY", ""),
            github_token=config.get("GITHUB_TOKEN", ""),
        )
        self.kb = KnowledgeBase(
            db_path=config.get("KNOWLEDGE_DB", "knowledge_base.db")
        )
        self.installer = ToolInstaller()

    # ═══════════════════════════════════════════════════════════════
    # CVE Lookup (cache-first)
    # ═══════════════════════════════════════════════════════════════

    async def lookup_cves(self, product: str, version: str = "",
                           max_results: int = 10) -> List[Dict]:
        """
        Find CVEs for a product/version. Cache-first, API fallback.

        Called by brain after finding service+version in recon.
        """
        product_clean = product.lower().strip()
        version_clean = version.strip()

        # 1. Check cache
        cached = self.kb.get_cached_cves(product_clean, version_clean)
        if cached:
            logger.info(f"Cache hit: {len(cached)} CVEs for '{product_clean} {version_clean}'")
            self.kb.log_decision(
                "intelligence", f"CVE cache hit for {product_clean} {version_clean}",
                f"Found {len(cached)} cached CVEs"
            )
            return cached

        # 2. Fetch from NVD
        logger.info(f"Cache miss: Fetching CVEs for '{product_clean} {version_clean}'")
        cves = await self.fetcher.search_nvd(product_clean, version_clean, max_results)

        # 3. Cache results
        if cves:
            self.kb.cache_cves(cves)
            self.kb.log_decision(
                "intelligence", f"Fetched {len(cves)} CVEs for {product_clean} {version_clean}",
                f"Top CVE: {cves[0]['cve_id']} (CVSS {cves[0]['cvss']})" if cves else ""
            )

        return cves

    # ═══════════════════════════════════════════════════════════════
    # Exploit Lookup (cache-first)
    # ═══════════════════════════════════════════════════════════════

    async def find_exploits(self, cve_id: str = "", keyword: str = "",
                             max_results: int = 5) -> List[Dict]:
        """
        Find exploit code/PoCs. Cache-first, GitHub API fallback.

        Called by brain after identifying a vulnerability.
        """
        # 1. Check cache
        cached = self.kb.get_cached_exploits(cve_id=cve_id, keyword=keyword)
        if cached:
            logger.info(f"Cache hit: {len(cached)} exploits for '{cve_id or keyword}'")
            return cached

        # 2. Fetch from GitHub
        exploits = await self.fetcher.search_github_exploits(
            cve_id=cve_id, keyword=keyword, max_results=max_results
        )

        # 3. Cache
        if exploits:
            self.kb.cache_exploits(exploits, cve_id=cve_id, keyword=keyword)

        return exploits

    # ═══════════════════════════════════════════════════════════════
    # MITRE Lookup (cache-first)
    # ═══════════════════════════════════════════════════════════════

    async def get_mitre_techniques(self, vuln_type: str = "",
                                     technique_id: str = "") -> List[Dict]:
        """
        Get MITRE ATT&CK techniques. Cache-first.

        Called by brain to map vulnerabilities to attack techniques.
        """
        if technique_id:
            # Check cache
            cached = self.kb.get_cached_mitre(technique_id)
            if cached:
                return [cached]

            # Fetch
            results = await self.fetcher.search_mitre(technique_id=technique_id)
            if results:
                self.kb.cache_mitre(results)
            return results

        if vuln_type:
            # Map vuln type to techniques
            results = await self.fetcher.search_mitre_for_vuln(vuln_type)
            if results:
                self.kb.cache_mitre(results)
            return results

        return []

    # ═══════════════════════════════════════════════════════════════
    # Shodan Lookup
    # ═══════════════════════════════════════════════════════════════

    async def lookup_shodan(self, ip: str) -> Optional[Dict]:
        """Lookup IP on Shodan. Cache-first."""
        cache_key = f"shodan:{ip}"
        cached = self.kb.get_cached_search(cache_key)
        if cached:
            return cached

        result = await self.fetcher.search_shodan(ip=ip)
        if result:
            self.kb.cache_search(cache_key, result, source="shodan")
        return result

    # ═══════════════════════════════════════════════════════════════
    # Tool Installation
    # ═══════════════════════════════════════════════════════════════

    def ensure_tool(self, tool_name: str) -> bool:
        """Ensure a tool is installed. Install if missing."""
        return self.installer.install(tool_name)

    def ensure_tools(self, tool_names: List[str]) -> Dict[str, bool]:
        """Ensure multiple tools are installed."""
        return self.installer.validate_tools(tool_names)

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if tool is available (without installing)."""
        return self.installer.is_installed(tool_name)

    # ═══════════════════════════════════════════════════════════════
    # Combined Intelligence (for brain prompts)
    # ═══════════════════════════════════════════════════════════════

    async def enrich_service(self, service: str, version: str = "",
                              ip: str = "") -> Dict:
        """
        Full intelligence enrichment for a discovered service.
        Called by brain after recon finds a service+version.

        Returns combined CVE, exploit, MITRE, and Shodan data.
        """
        result = {
            "service": service,
            "version": version,
            "cves": [],
            "exploits": [],
            "mitre_techniques": [],
            "shodan": None,
            "summary": "",
        }

        # Get CVEs
        cves = await self.lookup_cves(service, version)
        result["cves"] = cves

        # For top CVEs, find exploits
        exploits = []
        for cve in cves[:3]:  # Top 3 CVEs only (rate limit)
            cve_exploits = await self.find_exploits(cve_id=cve["cve_id"])
            exploits.extend(cve_exploits)
        result["exploits"] = exploits

        # Get MITRE techniques for the service type
        mitre = await self.get_mitre_techniques(vuln_type=service)
        result["mitre_techniques"] = mitre

        # Shodan lookup if IP provided
        if ip:
            shodan = await self.lookup_shodan(ip)
            result["shodan"] = shodan

        # Build summary for brain
        result["summary"] = self._build_summary(result)

        return result

    async def enrich_vulnerability(self, vuln_type: str, location: str = "",
                                     cve_id: str = "") -> Dict:
        """
        Enrich a discovered vulnerability with intelligence.
        Called by brain after analysis phase finds a vuln.
        """
        result = {
            "vuln_type": vuln_type,
            "location": location,
            "cve": None,
            "exploits": [],
            "mitre_techniques": [],
            "summary": "",
        }

        # Get CVE details if we have a CVE ID
        if cve_id:
            cves = await self.lookup_cves(cve_id)
            if cves:
                result["cve"] = cves[0]

        # Find exploits
        if cve_id:
            result["exploits"] = await self.find_exploits(cve_id=cve_id)
        else:
            result["exploits"] = await self.find_exploits(keyword=f"{vuln_type} exploit")

        # Get MITRE techniques
        result["mitre_techniques"] = await self.get_mitre_techniques(vuln_type=vuln_type)

        # Summary
        exploit_count = len(result["exploits"])
        mitre_count = len(result["mitre_techniques"])
        result["summary"] = (
            f"Vulnerability: {vuln_type} at {location}. "
            f"Found {exploit_count} exploits, {mitre_count} MITRE techniques."
        )

        return result

    def _build_summary(self, data: Dict) -> str:
        """Build human-readable summary for brain prompt."""
        parts = [f"Service: {data['service']} {data.get('version', '')}"]

        cves = data.get("cves", [])
        if cves:
            critical = [c for c in cves if c.get("cvss", 0) >= 9.0]
            high = [c for c in cves if 7.0 <= c.get("cvss", 0) < 9.0]
            parts.append(
                f"CVEs: {len(cves)} total ({len(critical)} critical, {len(high)} high)"
            )
            for cve in cves[:3]:
                parts.append(
                    f"  - {cve['cve_id']} (CVSS {cve['cvss']}): "
                    f"{cve['description'][:100]}..."
                )

        exploits = data.get("exploits", [])
        if exploits:
            parts.append(f"Exploits: {len(exploits)} found")
            for exp in exploits[:3]:
                parts.append(
                    f"  - {exp['name']} ({exp.get('stars', 0)} stars, "
                    f"reliability {exp.get('reliability', 0):.0%})"
                )

        mitre = data.get("mitre_techniques", [])
        if mitre:
            parts.append(f"MITRE: {', '.join(t['id'] for t in mitre[:5])}")

        return "\n".join(parts)

    # ═══════════════════════════════════════════════════════════════
    # Service Version Parser (for brain to call)
    # ═══════════════════════════════════════════════════════════════

    def parse_services_from_ports(self, ports_data: Dict) -> List[Tuple[str, str, str]]:
        """
        Extract (host, product, version) tuples from shared context ports data.
        Used by brain to know what to look up.
        """
        services = []
        for host, port_list in ports_data.items():
            for port_info in port_list:
                service = port_info.get("service", "")
                version = port_info.get("version", "")
                product = port_info.get("product", service)

                if product and product not in ("unknown", "?", ""):
                    # Clean product name
                    product_clean = re.sub(r'[^\w.-]', '', product).lower()
                    version_clean = re.sub(r'[^\d.]', '', version)

                    if product_clean:
                        services.append((host, product_clean, version_clean))

        return services

    # ═══════════════════════════════════════════════════════════════
    # Cache Stats
    # ═══════════════════════════════════════════════════════════════

    def get_stats(self) -> Dict:
        """Get intelligence system stats."""
        return {
            "cache": self.kb.get_stats(),
            "tools": self.installer.get_status(),
        }