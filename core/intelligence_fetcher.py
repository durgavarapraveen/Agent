"""
IntelligenceFetcher - Search NVD, GitHub, MITRE, Shodan for real-time vuln data.
Phase 1 of Enterprise system. Brain calls this after finding service+version.
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional
from urllib.parse import quote_plus

import httpx

logger = logging.getLogger(__name__)


class IntelligenceFetcher:
    """Fetch real-time vulnerability intelligence from public APIs."""

    def __init__(self, shodan_key: str = "", github_token: str = ""):
        self.shodan_key = shodan_key
        self.github_token = github_token
        self.timeout = 30
        self._rate_limits = {
            "nvd": {"remaining": 50, "reset": 0},
            "github": {"remaining": 60, "reset": 0},
        }

    # ═══════════════════════════════════════════════════════════════
    # NVD (NIST) - CVE Search
    # ═══════════════════════════════════════════════════════════════

    async def search_nvd(self, product: str, version: str = "",
                         max_results: int = 10) -> List[Dict]:
        """
        Search NVD for CVEs by product name and version.
        Free API, no key required. Rate limit: 5 req/30s without key.

        Example: search_nvd("apache", "2.4.49") → list of CVEs
        """
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # Build keyword search
        keyword = f"{product} {version}".strip()
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results, 50),
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(base_url, params=params)

                if resp.status_code == 403:
                    logger.warning("NVD rate limited. Waiting 30s...")
                    await asyncio.sleep(30)
                    resp = await client.get(base_url, params=params)

                if resp.status_code != 200:
                    logger.error(f"NVD API {resp.status_code}: {resp.text[:200]}")
                    return []

                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])

                results = []
                for item in vulnerabilities[:max_results]:
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id", "")

                    # Extract CVSS score
                    cvss_score = 0.0
                    cvss_vector = ""
                    metrics = cve_data.get("metrics", {})

                    # Try CVSS 3.1 first, then 3.0, then 2.0
                    for cvss_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if cvss_key in metrics and metrics[cvss_key]:
                            cvss_data = metrics[cvss_key][0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore", 0.0)
                            cvss_vector = cvss_data.get("vectorString", "")
                            break

                    # Extract description
                    descriptions = cve_data.get("descriptions", [])
                    description = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break

                    # Extract references (exploit links, patches)
                    references = []
                    for ref in cve_data.get("references", [])[:5]:
                        references.append({
                            "url": ref.get("url", ""),
                            "source": ref.get("source", ""),
                            "tags": ref.get("tags", []),
                        })

                    # Extract CWE
                    cwes = []
                    for weakness in cve_data.get("weaknesses", []):
                        for desc in weakness.get("description", []):
                            if desc.get("value", "").startswith("CWE-"):
                                cwes.append(desc["value"])

                    results.append({
                        "cve_id": cve_id,
                        "cvss": cvss_score,
                        "cvss_vector": cvss_vector,
                        "severity": self._cvss_to_severity(cvss_score),
                        "description": description[:500],
                        "cwes": cwes,
                        "references": references,
                        "published": cve_data.get("published", ""),
                        "modified": cve_data.get("lastModified", ""),
                        "product": product,
                        "version": version,
                    })

                logger.info(f"NVD: Found {len(results)} CVEs for '{keyword}'")
                return results

        except httpx.TimeoutException:
            logger.error(f"NVD timeout for '{keyword}'")
            return []
        except Exception as e:
            logger.error(f"NVD search error: {e}")
            return []

    async def search_nvd_by_cve(self, cve_id: str) -> Optional[Dict]:
        """Fetch specific CVE details by ID."""
        base_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cveId": cve_id}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(base_url, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        # Reuse search_nvd parsing
                        results = await self.search_nvd(cve_id)
                        return results[0] if results else None
        except Exception as e:
            logger.error(f"NVD CVE lookup error: {e}")
        return None

    # ═══════════════════════════════════════════════════════════════
    # GitHub - Exploit Search
    # ═══════════════════════════════════════════════════════════════

    async def search_github_exploits(self, cve_id: str = "",
                                      keyword: str = "",
                                      max_results: int = 5) -> List[Dict]:
        """
        Search GitHub for exploit code / PoCs.
        Free: 10 req/min unauthenticated, 30 req/min with token.

        Example: search_github_exploits(cve_id="CVE-2024-1234")
        """
        base_url = "https://api.github.com/search/repositories"

        query = cve_id or keyword
        if not query:
            return []

        # Search for exploit/PoC repos
        search_query = f"{query} exploit OR poc OR vulnerability"
        params = {
            "q": search_query,
            "sort": "stars",
            "order": "desc",
            "per_page": min(max_results, 30),
        }

        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(base_url, params=params, headers=headers)

                if resp.status_code == 403:
                    logger.warning("GitHub rate limited")
                    return []

                if resp.status_code != 200:
                    logger.error(f"GitHub API {resp.status_code}: {resp.text[:200]}")
                    return []

                data = resp.json()
                items = data.get("items", [])

                results = []
                for repo in items[:max_results]:
                    results.append({
                        "name": repo.get("full_name", ""),
                        "url": repo.get("html_url", ""),
                        "description": (repo.get("description") or "")[:300],
                        "stars": repo.get("stargazers_count", 0),
                        "language": repo.get("language", ""),
                        "updated": repo.get("updated_at", ""),
                        "clone_url": repo.get("clone_url", ""),
                        "cve": cve_id,
                        "reliability": self._score_exploit_repo(repo),
                    })

                logger.info(f"GitHub: Found {len(results)} exploit repos for '{query}'")
                return results

        except Exception as e:
            logger.error(f"GitHub search error: {e}")
            return []

    def _score_exploit_repo(self, repo: Dict) -> float:
        """Score exploit reliability: 0.0-1.0"""
        score = 0.3  # Base score
        stars = repo.get("stargazers_count", 0)
        if stars >= 100:
            score += 0.3
        elif stars >= 20:
            score += 0.2
        elif stars >= 5:
            score += 0.1

        desc = (repo.get("description") or "").lower()
        if any(w in desc for w in ["poc", "proof of concept", "exploit", "rce"]):
            score += 0.2

        if repo.get("language") in ["Python", "Go", "C", "Shell", "Ruby"]:
            score += 0.1

        return min(score, 1.0)

    # ═══════════════════════════════════════════════════════════════
    # MITRE ATT&CK - Technique Search
    # ═══════════════════════════════════════════════════════════════

    async def search_mitre(self, technique_id: str = "",
                            keyword: str = "") -> List[Dict]:
        """
        Search MITRE ATT&CK for techniques.
        Uses the MITRE ATT&CK STIX data (free, no key).

        Example: search_mitre(technique_id="T1190")
        Example: search_mitre(keyword="sql injection")
        """
        # Use MITRE ATT&CK TAXII server or local mapping
        # For speed, use the pre-built mapping for common techniques
        techniques = self._get_mitre_mapping()

        results = []

        if technique_id:
            # Exact match
            tech = techniques.get(technique_id.upper())
            if tech:
                results.append(tech)
        elif keyword:
            # Keyword search
            keyword_lower = keyword.lower()
            for tid, tech in techniques.items():
                if (keyword_lower in tech.get("name", "").lower() or
                    keyword_lower in tech.get("description", "").lower()):
                    results.append(tech)

        logger.info(f"MITRE: Found {len(results)} techniques")
        return results[:10]

    async def search_mitre_for_vuln(self, vuln_type: str) -> List[Dict]:
        """Map vulnerability type to MITRE techniques."""
        vuln_to_mitre = {
            "sqli": ["T1190", "T1505"],
            "sql_injection": ["T1190", "T1505"],
            "xss": ["T1189", "T1059.007"],
            "rce": ["T1203", "T1059"],
            "lfi": ["T1083", "T1005"],
            "rfi": ["T1105", "T1059"],
            "ssrf": ["T1090", "T1557"],
            "idor": ["T1078", "T1530"],
            "auth_bypass": ["T1078", "T1556"],
            "file_upload": ["T1105", "T1505.003"],
            "command_injection": ["T1059", "T1203"],
            "deserialization": ["T1203", "T1059"],
            "xxe": ["T1005", "T1190"],
            "csrf": ["T1185", "T1557"],
            "directory_traversal": ["T1083", "T1005"],
            "privilege_escalation": ["T1548", "T1068"],
            "lateral_movement": ["T1021", "T1570"],
            "credential_access": ["T1110", "T1003"],
        }

        vuln_lower = vuln_type.lower().replace(" ", "_")
        technique_ids = vuln_to_mitre.get(vuln_lower, [])

        results = []
        for tid in technique_ids:
            techs = await self.search_mitre(technique_id=tid)
            results.extend(techs)

        return results

    def _get_mitre_mapping(self) -> Dict[str, Dict]:
        """Pre-built MITRE ATT&CK technique mapping (most common ones)."""
        return {
            "T1190": {
                "id": "T1190", "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.",
                "mitigations": ["Application Isolation", "Exploit Protection", "Network Segmentation", "Update Software", "WAF"],
                "detection": ["Application logs", "Network IDS", "WAF logs"],
            },
            "T1059": {
                "id": "T1059", "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                "mitigations": ["Code Signing", "Disable or Remove Feature", "Execution Prevention"],
                "detection": ["Command execution logs", "Process monitoring", "Script execution logs"],
            },
            "T1059.007": {
                "id": "T1059.007", "name": "JavaScript",
                "tactic": "Execution",
                "description": "Adversaries may abuse JavaScript for execution.",
                "mitigations": ["Disable or Remove Feature", "Restrict Web-Based Content"],
                "detection": ["Script execution logs"],
            },
            "T1078": {
                "id": "T1078", "name": "Valid Accounts",
                "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
                "description": "Adversaries may obtain and abuse credentials of existing accounts.",
                "mitigations": ["MFA", "Password Policies", "Privileged Account Management"],
                "detection": ["Authentication logs", "Logon session monitoring"],
            },
            "T1110": {
                "id": "T1110", "name": "Brute Force",
                "tactic": "Credential Access",
                "description": "Adversaries may use brute force techniques to gain access to accounts.",
                "mitigations": ["Account Lockout", "MFA", "Password Policies"],
                "detection": ["Authentication logs", "Account lockout alerts"],
            },
            "T1203": {
                "id": "T1203", "name": "Exploitation for Client Execution",
                "tactic": "Execution",
                "description": "Adversaries may exploit software vulnerabilities in client applications to execute code.",
                "mitigations": ["Application Isolation", "Exploit Protection"],
                "detection": ["Application crash logs", "Process monitoring"],
            },
            "T1189": {
                "id": "T1189", "name": "Drive-by Compromise",
                "tactic": "Initial Access",
                "description": "Adversaries may gain access through a user visiting a website during normal browsing.",
                "mitigations": ["Exploit Protection", "Restrict Web-Based Content", "Update Software"],
                "detection": ["Network IDS", "Web proxy logs"],
            },
            "T1505": {
                "id": "T1505", "name": "Server Software Component",
                "tactic": "Persistence",
                "description": "Adversaries may abuse legitimate server software components to establish persistent access.",
                "mitigations": ["Audit", "Code Signing", "Disable or Remove Feature"],
                "detection": ["Application logs", "File monitoring"],
            },
            "T1505.003": {
                "id": "T1505.003", "name": "Web Shell",
                "tactic": "Persistence",
                "description": "Adversaries may place web shells on web servers to establish persistent access.",
                "mitigations": ["Disable or Remove Feature", "File System Permissions"],
                "detection": ["File monitoring", "Network traffic", "Process monitoring"],
            },
            "T1548": {
                "id": "T1548", "name": "Abuse Elevation Control Mechanism",
                "tactic": "Privilege Escalation, Defense Evasion",
                "description": "Adversaries may circumvent mechanisms designed to control elevated privileges.",
                "mitigations": ["Execution Prevention", "Operating System Configuration", "Privileged Account Management"],
                "detection": ["Command execution", "File monitoring", "Process monitoring"],
            },
            "T1068": {
                "id": "T1068", "name": "Exploitation for Privilege Escalation",
                "tactic": "Privilege Escalation",
                "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.",
                "mitigations": ["Application Isolation", "Exploit Protection", "Update Software"],
                "detection": ["Process monitoring", "Application crash logs"],
            },
            "T1083": {
                "id": "T1083", "name": "File and Directory Discovery",
                "tactic": "Discovery",
                "description": "Adversaries may enumerate files and directories.",
                "mitigations": [],
                "detection": ["Command execution", "File monitoring", "Process monitoring"],
            },
            "T1005": {
                "id": "T1005", "name": "Data from Local System",
                "tactic": "Collection",
                "description": "Adversaries may search local system sources such as file systems or databases.",
                "mitigations": ["Data Loss Prevention"],
                "detection": ["Command execution", "File monitoring"],
            },
            "T1105": {
                "id": "T1105", "name": "Ingress Tool Transfer",
                "tactic": "Command and Control",
                "description": "Adversaries may transfer tools or files from an external system into a compromised environment.",
                "mitigations": ["Network Intrusion Prevention"],
                "detection": ["File monitoring", "Network traffic", "Process monitoring"],
            },
            "T1021": {
                "id": "T1021", "name": "Remote Services",
                "tactic": "Lateral Movement",
                "description": "Adversaries may use valid accounts to log into a service for remote access.",
                "mitigations": ["Disable or Remove Feature", "MFA", "Network Segmentation"],
                "detection": ["Authentication logs", "Logon session monitoring"],
            },
            "T1003": {
                "id": "T1003", "name": "OS Credential Dumping",
                "tactic": "Credential Access",
                "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
                "mitigations": ["Active Directory Configuration", "Credential Access Protection", "Operating System Configuration", "Password Policies", "Privileged Account Management", "User Training"],
                "detection": ["Command execution", "Process access", "Process creation"],
            },
            "T1530": {
                "id": "T1530", "name": "Data from Cloud Storage",
                "tactic": "Collection",
                "description": "Adversaries may access data from improperly secured cloud storage.",
                "mitigations": ["Audit", "Encrypt Sensitive Information", "Filter Network Traffic", "MFA", "Restrict File and Directory Permissions", "User Account Management"],
                "detection": ["Cloud storage logs"],
            },
            "T1556": {
                "id": "T1556", "name": "Modify Authentication Process",
                "tactic": "Credential Access, Defense Evasion, Persistence",
                "description": "Adversaries may modify authentication mechanisms to access user credentials.",
                "mitigations": ["Audit", "MFA", "Operating System Configuration", "Privileged Account Management", "Privileged Process Integrity"],
                "detection": ["Authentication logs", "File monitoring", "Windows event logs"],
            },
            "T1090": {
                "id": "T1090", "name": "Proxy",
                "tactic": "Command and Control",
                "description": "Adversaries may use a connection proxy to direct network traffic between systems.",
                "mitigations": ["Filter Network Traffic", "Network Intrusion Prevention", "SSL/TLS Inspection"],
                "detection": ["Network traffic", "Process monitoring"],
            },
            "T1185": {
                "id": "T1185", "name": "Browser Session Hijacking",
                "tactic": "Collection",
                "description": "Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behavior, and intercept information.",
                "mitigations": ["User Training"],
                "detection": ["Authentication logs", "Process monitoring"],
            },
            "T1557": {
                "id": "T1557", "name": "Adversary-in-the-Middle",
                "tactic": "Credential Access, Collection",
                "description": "Adversaries may attempt to position themselves between two or more networked devices to support follow-on behaviors.",
                "mitigations": ["Disable or Remove Feature", "Encrypt Sensitive Information", "Filter Network Traffic", "Limit Access to Resource Over Network", "Network Intrusion Prevention", "Network Segmentation"],
                "detection": ["Network traffic", "Service creation", "Windows event logs"],
            },
            "T1570": {
                "id": "T1570", "name": "Lateral Tool Transfer",
                "tactic": "Lateral Movement",
                "description": "Adversaries may transfer tools between compromised systems.",
                "mitigations": ["Filter Network Traffic", "Network Intrusion Prevention"],
                "detection": ["Command execution", "File creation", "Named pipe monitoring", "Network traffic"],
            },
            "T1134": {
                "id": "T1134", "name": "Access Token Manipulation",
                "tactic": "Defense Evasion, Privilege Escalation",
                "description": "Adversaries may modify access tokens to operate under a different user or system security context.",
                "mitigations": ["Privileged Account Management", "User Account Management"],
                "detection": ["Access token monitoring", "Process monitoring"],
            },
        }

    # ═══════════════════════════════════════════════════════════════
    # Shodan - Internet Reconnaissance
    # ═══════════════════════════════════════════════════════════════

    async def search_shodan(self, ip: str = "", query: str = "") -> Optional[Dict]:
        """
        Search Shodan for host information.
        Requires API key. Free tier: 1 query/month for search, unlimited host lookups.

        Example: search_shodan(ip="93.184.216.34")
        """
        if not self.shodan_key:
            logger.debug("Shodan API key not configured, skipping")
            return None

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                if ip:
                    # Host lookup (free, unlimited)
                    url = f"https://api.shodan.io/shodan/host/{ip}"
                    params = {"key": self.shodan_key}
                    resp = await client.get(url, params=params)
                elif query:
                    # Search (limited on free tier)
                    url = "https://api.shodan.io/shodan/host/search"
                    params = {"key": self.shodan_key, "query": query}
                    resp = await client.get(url, params=params)
                else:
                    return None

                if resp.status_code == 401:
                    logger.error("Shodan: Invalid API key")
                    return None
                if resp.status_code == 402:
                    logger.warning("Shodan: Requires paid plan for this query")
                    return None
                if resp.status_code != 200:
                    logger.error(f"Shodan {resp.status_code}: {resp.text[:200]}")
                    return None

                data = resp.json()

                if ip:
                    return {
                        "ip": data.get("ip_str", ip),
                        "hostnames": data.get("hostnames", []),
                        "os": data.get("os"),
                        "ports": data.get("ports", []),
                        "vulns": data.get("vulns", []),
                        "org": data.get("org", ""),
                        "isp": data.get("isp", ""),
                        "country": data.get("country_code", ""),
                        "services": [
                            {
                                "port": svc.get("port"),
                                "transport": svc.get("transport"),
                                "product": svc.get("product", ""),
                                "version": svc.get("version", ""),
                                "banner": (svc.get("data") or "")[:200],
                            }
                            for svc in data.get("data", [])[:20]
                        ],
                    }

                # Search results
                return {
                    "total": data.get("total", 0),
                    "matches": [
                        {
                            "ip": m.get("ip_str"),
                            "port": m.get("port"),
                            "org": m.get("org", ""),
                            "product": m.get("product", ""),
                            "version": m.get("version", ""),
                        }
                        for m in data.get("matches", [])[:10]
                    ],
                }

        except Exception as e:
            logger.error(f"Shodan error: {e}")
            return None

    # ═══════════════════════════════════════════════════════════════
    # Convenience: Search All Sources
    # ═══════════════════════════════════════════════════════════════

    async def search_all(self, product: str, version: str = "",
                          ip: str = "") -> Dict:
        """
        Search all intelligence sources in parallel.
        Returns combined results.
        """
        tasks = {
            "cves": self.search_nvd(product, version),
        }

        # Add GitHub search if we have a product
        if product:
            tasks["exploits"] = self.search_github_exploits(
                keyword=f"{product} {version} exploit".strip()
            )

        # Add MITRE mapping
        tasks["mitre"] = self.search_mitre(keyword=product)

        # Add Shodan if IP provided
        if ip and self.shodan_key:
            tasks["shodan"] = self.search_shodan(ip=ip)

        # Execute all in parallel
        keys = list(tasks.keys())
        results_list = await asyncio.gather(
            *tasks.values(), return_exceptions=True
        )

        combined = {}
        for key, result in zip(keys, results_list):
            if isinstance(result, Exception):
                logger.error(f"Intelligence source '{key}' failed: {result}")
                combined[key] = []
            else:
                combined[key] = result

        # Summary
        cve_count = len(combined.get("cves", []))
        exploit_count = len(combined.get("exploits", []))
        mitre_count = len(combined.get("mitre", []))

        logger.info(
            f"Intelligence: {cve_count} CVEs, {exploit_count} exploits, "
            f"{mitre_count} MITRE techniques for '{product} {version}'"
        )

        return combined

    # ═══════════════════════════════════════════════════════════════
    # Helpers
    # ═══════════════════════════════════════════════════════════════

    @staticmethod
    def _cvss_to_severity(cvss: float) -> str:
        if cvss >= 9.0:
            return "CRITICAL"
        elif cvss >= 7.0:
            return "HIGH"
        elif cvss >= 4.0:
            return "MEDIUM"
        elif cvss > 0:
            return "LOW"
        return "NONE"

    @staticmethod
    def extract_service_version(banner: str) -> tuple:
        """
        Extract product and version from service banner.
        Example: "Apache/2.4.49" → ("apache", "2.4.49")
        """
        patterns = [
            r"([\w.-]+)/([\d.]+)",           # Apache/2.4.49
            r"([\w.-]+)\s+([\d.]+)",          # OpenSSH 8.2
            r"([\w.-]+)\s+version\s+([\d.]+)",  # MySQL version 8.0
        ]

        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1).lower(), match.group(2)

        return banner.strip().lower(), ""