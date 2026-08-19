"""
Kali Reconnaissance Agents - Use REAL Kali tools via Docker
Auto-installs missing tools. Works on Windows/Linux/Mac.
"""

import asyncio
import logging
import re
from typing import Any
from urllib.parse import urlparse

from agents.base import BaseAgent
from core.models import AgentResult, Finding, FindingSeverity, FindingStatus
from agents.kali_executor import KaliDockerExecutor

logger = logging.getLogger(__name__)


def _domain(target: str) -> str:
    """Extract clean domain from target"""
    p = urlparse(target if "://" in target else f"https://{target}")
    return (p.hostname or p.path.split("/")[0]).split("#")[0]


def _url(target: str) -> str:
    """Get clean base URL"""
    p = urlparse(target if "://" in target else f"https://{target}")
    return f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")


# ============================================================================
# SUBDOMAIN DISCOVERY - amass, subfinder, assetfinder, dnsenum, fierce
# ============================================================================

class SubdomainDiscoveryAgent(BaseAgent):
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Subdomain Discovery Specialist", "subdomain_discovery", context)

    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Subdomain discovery complete")
        domain = _domain(self.context.target)
        logger.info(f"SubdomainDiscoveryAgent: Scanning {domain}")

        subdomains = set()
        ips = set()

        # subfinder (fast, passive)
        logger.info("  Running subfinder...")
        r = KaliDockerExecutor.run(f"subfinder -d {domain} -silent -t 20 -timeout 20", timeout=90)
        if r["status"] == "success":
            for line in r["stdout"].strip().split("\n"):
                line = line.strip()
                if line and "." in line:
                    subdomains.add(line)
            logger.info(f"  subfinder: {len(subdomains)} subdomains")

        # assetfinder (fast, passive)
        logger.info("  Running assetfinder...")
        r = KaliDockerExecutor.run(f"assetfinder --subs-only {domain}", timeout=60)
        if r["status"] == "success":
            for line in r["stdout"].strip().split("\n"):
                line = line.strip()
                if line and "." in line:
                    subdomains.add(line)

        # amass passive (thorough)
        logger.info("  Running amass passive...")
        r = KaliDockerExecutor.run(f"amass enum -passive -d {domain} -timeout 2", timeout=180)
        if r["status"] == "success":
            for line in r["stdout"].strip().split("\n"):
                line = line.strip()
                if line and "." in line:
                    subdomains.add(line)

        # dnsenum
        logger.info("  Running dnsenum...")
        r = KaliDockerExecutor.run(f"dnsenum --noreverse -o /tmp/dnsenum.xml {domain}", timeout=60)
        if r["status"] == "success":
            for m in re.finditer(r'([a-zA-Z0-9][a-zA-Z0-9-]*\.' + re.escape(domain) + r')', r["stdout"]):
                subdomains.add(m.group(1))
            for m in re.finditer(r'(\d+\.\d+\.\d+\.\d+)', r["stdout"]):
                ips.add(m.group(1))

        # dig for IPs
        r = KaliDockerExecutor.run(f"dig {domain} +short", timeout=15)
        if r["status"] == "success":
            for line in r["stdout"].strip().split("\n"):
                line = line.strip()
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                    ips.add(line)

        # whois
        r = KaliDockerExecutor.run(f"whois {domain} | head -50", timeout=30)
        whois_data = r["stdout"][:1000] if r["status"] == "success" else ""

        result.discoveries.append({
            "type": "subdomain_discovery",
            "target": domain,
            "subdomains": sorted(subdomains),
            "ips": sorted(ips),
            "whois": whois_data,
            "count": len(subdomains),
            "tools": ["subfinder", "assetfinder", "amass", "dnsenum", "dig", "whois"]
        })
        logger.info(f"SubdomainDiscoveryAgent: {len(subdomains)} subdomains, {len(ips)} IPs")
        return result


# ============================================================================
# PORT SCANNING - nmap, masscan, rustscan
# ============================================================================

class PortScanAgent(BaseAgent):
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Port Scan Specialist", "port_scanning", context)

    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Port scanning complete")
        domain = _domain(self.context.target)
        logger.info(f"PortScanAgent: Scanning {domain}")

        open_ports = {}
        services = {}

        # nmap top 1000 ports with service detection
        logger.info("  Running nmap top 1000 ports with service detection...")
        r = KaliDockerExecutor.run(
            f"nmap -sV --top-ports 1000 -T4 --host-timeout 180s {domain}",
            timeout=300
        )
        nmap_raw = ""
        if r["status"] == "success":
            nmap_raw = r["stdout"]
            for line in r["stdout"].split("\n"):
                m = re.search(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?', line)
                if m:
                    port = int(m.group(1))
                    open_ports[port] = m.group(2)
                    if m.group(3):
                        services[port] = m.group(3).strip()

        # nmap script scan for common vulns on open ports
        vulns = []
        if open_ports:
            ports_str = ",".join(str(p) for p in list(open_ports.keys())[:10])
            logger.info(f"  Running nmap vuln scripts on ports {ports_str}...")
            r = KaliDockerExecutor.run(
                f"nmap -sV --script=vuln,default -p {ports_str} --host-timeout 120s {domain}",
                timeout=200
            )
            if r["status"] == "success":
                for line in r["stdout"].split("\n"):
                    if "VULNERABLE" in line or "CVE-" in line:
                        vulns.append(line.strip())

        result.discoveries.append({
            "type": "port_scan",
            "target": domain,
            "open_ports": open_ports,
            "services": services,
            "vulnerabilities": vulns[:20],
            "nmap_summary": nmap_raw[:2000],
            "port_count": len(open_ports),
            "tools": ["nmap"]
        })

        # Create findings for open sensitive ports
        for port, svc in open_ports.items():
            if port in [21, 23, 3306, 5432, 6379, 27017, 9200, 11211]:
                sev = FindingSeverity.HIGH if port in [21, 23, 3306, 6379, 27017] else FindingSeverity.MEDIUM
                result.findings.append(Finding(
                    title=f"Sensitive Service Exposed: {svc} on port {port}",
                    description=f"Port {port} ({svc}) is publicly accessible. This service typically should not be exposed to the internet.",
                    severity=sev, confidence=0.90,
                    status=FindingStatus.CANDIDATE, category="exposed_service",
                    affected_asset=f"{domain}:{port}", source_agent_id=self.agent_id
                ))

        logger.info(f"PortScanAgent: {len(open_ports)} ports, {len(vulns)} nmap vulns")
        return result


# ============================================================================
# DIRECTORY BRUTEFORCE - gobuster, feroxbuster, dirsearch, ffuf
# ============================================================================

class DirectoryBruteforceAgent(BaseAgent):
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Directory Discovery Specialist", "directory_bruteforce", context)

    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Directory discovery complete")
        url = _url(self.context.target)
        logger.info(f"DirectoryBruteforceAgent: Scanning {url}")

        found = []

        # gobuster with common wordlist
        logger.info("  Running gobuster...")
        r = KaliDockerExecutor.run(
            f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt "
            f"-q -t 30 --timeout 10s --no-error -k",
            timeout=180
        )
        if r["status"] == "success":
            for line in r["stdout"].split("\n"):
                m = re.search(r'(/\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)', line)
                if m:
                    found.append({
                        "path": m.group(1),
                        "status": int(m.group(2)),
                        "size": int(m.group(3)),
                        "tool": "gobuster"
                    })

        # feroxbuster (recursive, fast)
        if not found:
            logger.info("  Running feroxbuster fallback...")
            r = KaliDockerExecutor.run(
                f"feroxbuster -u {url} -w /usr/share/wordlists/dirb/common.txt "
                f"-q -t 30 --timeout 10 -k -d 1 --no-recursion",
                timeout=180
            )
            if r["status"] == "success":
                for line in r["stdout"].split("\n"):
                    m = re.search(r'(\d+)\s+.*?(https?://\S+)', line)
                    if m:
                        found.append({
                            "path": m.group(2),
                            "status": int(m.group(1)),
                            "tool": "feroxbuster"
                        })

        # Check specific high-value paths with curl
        logger.info("  Checking high-value paths...")
        high_value = [
            "/.git/HEAD", "/.env", "/.aws/credentials", "/config.php",
            "/backup.sql", "/.htpasswd", "/wp-config.php", "/phpinfo.php",
            "/actuator/env", "/debug/pprof", "/swagger.json",
        ]
        for path in high_value:
            r = KaliDockerExecutor.run(
                f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 -k {url}{path}",
                timeout=10
            )
            if r["status"] == "success":
                code = r["stdout"].strip()
                if code in ["200", "301", "302", "401", "403"]:
                    found.append({"path": path, "status": int(code), "tool": "curl", "high_value": True})
                    # Findings for sensitive files
                    if code == "200" and path in ["/.git/HEAD", "/.env", "/.aws/credentials",
                                                    "/wp-config.php", "/backup.sql", "/phpinfo.php"]:
                        result.findings.append(Finding(
                            title=f"Sensitive File Exposed: {path}",
                            description=f"{path} is accessible (HTTP 200). May leak credentials or source code.",
                            severity=FindingSeverity.HIGH, confidence=0.95,
                            status=FindingStatus.CANDIDATE, category="information_disclosure",
                            affected_asset=f"{url}{path}", source_agent_id=self.agent_id
                        ))

        # robots.txt
        r = KaliDockerExecutor.run(f"curl -s --max-time 5 -k {url}/robots.txt", timeout=10)
        robots = r["stdout"][:1000] if r["status"] == "success" and "Disallow" in r["stdout"] else ""

        result.discoveries.append({
            "type": "directory_discovery",
            "target": url,
            "found_directories": found,
            "robots_txt": robots,
            "count": len(found),
            "tools": ["gobuster", "feroxbuster", "curl"]
        })
        logger.info(f"DirectoryBruteforceAgent: Found {len(found)} directories")
        return result


# ============================================================================
# TECH DETECTION - whatweb, wafw00f, httpx
# ============================================================================

class TechStackAgent(BaseAgent):
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Tech Stack Specialist", "tech_detection", context)

    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Technology detection complete")
        url = _url(self.context.target)
        logger.info(f"TechStackAgent: Scanning {url}")

        technologies = set()

        # whatweb - primary tech detector
        logger.info("  Running whatweb...")
        r = KaliDockerExecutor.run(f"whatweb -a 3 --no-errors {url}", timeout=60)
        whatweb_raw = ""
        if r["status"] == "success":
            whatweb_raw = r["stdout"][:2000]
            # Parse [Tech] tags
            for m in re.findall(r'\[([^\]]+)\]', whatweb_raw):
                if m and len(m) < 100:
                    technologies.add(m.strip())

        # wafw00f - WAF detection
        logger.info("  Running wafw00f...")
        r = KaliDockerExecutor.run(f"wafw00f {url}", timeout=60)
        waf_info = ""
        if r["status"] == "success":
            waf_info = r["stdout"][:500]
            for m in re.finditer(r'is behind\s+(.+?)\s', r["stdout"]):
                technologies.add(f"WAF: {m.group(1).strip()}")

        # httpx - fingerprinting
        logger.info("  Running httpx...")
        domain = _domain(self.context.target)
        r = KaliDockerExecutor.run(
            f"echo {domain} | httpx -silent -tech-detect -title -server -status-code",
            timeout=60
        )
        httpx_data = ""
        if r["status"] == "success":
            httpx_data = r["stdout"][:1000]

        # HTTP headers via curl for extra context
        r = KaliDockerExecutor.run(f"curl -sI --max-time 10 -k {url}", timeout=15)
        headers_dict = {}
        if r["status"] == "success":
            for line in r["stdout"].split("\n"):
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers_dict[k.strip().lower()] = v.strip()

            if headers_dict.get("server"):
                technologies.add(f"Server: {headers_dict['server']}")
            if headers_dict.get("x-powered-by"):
                technologies.add(f"X-Powered-By: {headers_dict['x-powered-by']}")

        result.discoveries.append({
            "type": "technology_stack",
            "target": url,
            "technologies": sorted(technologies),
            "waf_info": waf_info,
            "httpx_data": httpx_data,
            "headers": headers_dict,
            "tech_count": len(technologies),
            "tools": ["whatweb", "wafw00f", "httpx", "curl"]
        })
        logger.info(f"TechStackAgent: Found {len(technologies)} technologies")
        return result


# ============================================================================
# VULNERABILITY DETECTION - nuclei, nikto, sslscan
# ============================================================================

class VulnerabilityDetectionAgent(BaseAgent):
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Vulnerability Detection Specialist", "vulnerability_detection", context)

    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Vulnerability detection complete")
        url = _url(self.context.target)
        domain = _domain(self.context.target)
        logger.info(f"VulnerabilityDetectionAgent: Scanning {url}")

        # nuclei - template-based vuln scanner (industry standard)
        logger.info("  Running nuclei (medium+high+critical)...")
        r = KaliDockerExecutor.run(
            f"nuclei -u {url} -severity medium,high,critical "
            f"-silent -stats=false -timeout 10 -rate-limit 50 -c 25",
            timeout=300
        )
        nuclei_findings = []
        if r["status"] == "success":
            for line in r["stdout"].strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                # [template-id] [protocol] [severity] target
                m = re.match(r'\[(.+?)\]\s+\[(.+?)\]\s+\[(.+?)\]\s+(.+)', line)
                if m:
                    template = m.group(1)
                    severity = m.group(3).upper()
                    target_str = m.group(4)
                    nuclei_findings.append({
                        "template": template,
                        "severity": severity,
                        "target": target_str
                    })
                    sev = {
                        "CRITICAL": FindingSeverity.CRITICAL,
                        "HIGH": FindingSeverity.HIGH,
                        "MEDIUM": FindingSeverity.MEDIUM,
                        "LOW": FindingSeverity.LOW,
                    }.get(severity, FindingSeverity.INFO)
                    result.findings.append(Finding(
                        title=f"Nuclei: {template}",
                        description=f"[{severity}] Vulnerability template '{template}' matched on {target_str}",
                        severity=sev, confidence=0.90,
                        status=FindingStatus.CANDIDATE, category="vulnerability",
                        affected_asset=target_str, source_agent_id=self.agent_id
                    ))

        # nikto - web server vulnerabilities
        logger.info("  Running nikto...")
        r = KaliDockerExecutor.run(
            f"nikto -h {url} -maxtime 60s -Format txt -nointeractive -Tuning x6",
            timeout=120
        )
        nikto_findings = []
        if r["status"] == "success":
            for line in r["stdout"].split("\n"):
                line = line.strip()
                if line.startswith("+") and len(line) > 5 and "Target" not in line and "Start Time" not in line:
                    nikto_findings.append(line)
                    result.findings.append(Finding(
                        title=f"Nikto: {line[2:100]}",
                        description=line,
                        severity=FindingSeverity.MEDIUM, confidence=0.75,
                        status=FindingStatus.CANDIDATE, category="web_server",
                        affected_asset=url, source_agent_id=self.agent_id
                    ))

        # sslscan for SSL/TLS issues
        logger.info("  Running sslscan...")
        r = KaliDockerExecutor.run(f"sslscan --no-colour {domain}", timeout=60)
        ssl_issues = []
        ssl_raw = ""
        if r["status"] == "success":
            ssl_raw = r["stdout"][:3000]
            weak_indicators = {
                "SSLv2": FindingSeverity.HIGH,
                "SSLv3": FindingSeverity.HIGH,
                "TLSv1.0": FindingSeverity.MEDIUM,
                "TLSv1.1": FindingSeverity.MEDIUM,
                "RC4": FindingSeverity.HIGH,
                "MD5": FindingSeverity.MEDIUM,
                "DES-": FindingSeverity.HIGH,
                "NULL": FindingSeverity.CRITICAL,
                "EXPORT": FindingSeverity.HIGH,
            }
            for indicator, sev in weak_indicators.items():
                if re.search(rf'\b{re.escape(indicator)}.*?(?:enabled|accepted)', r["stdout"], re.IGNORECASE):
                    ssl_issues.append(f"Weak: {indicator}")
                    result.findings.append(Finding(
                        title=f"Weak SSL/TLS: {indicator}",
                        description=f"Server supports weak/deprecated {indicator}. Disable to prevent downgrade attacks.",
                        severity=sev, confidence=0.95,
                        status=FindingStatus.CANDIDATE, category="ssl_tls",
                        affected_asset=domain, source_agent_id=self.agent_id
                    ))

        # Security headers via curl
        logger.info("  Checking security headers...")
        r = KaliDockerExecutor.run(f"curl -sI --max-time 10 -k {url}", timeout=15)
        header_issues = []
        if r["status"] == "success":
            headers = r["stdout"].lower()
            checks = {
                "x-frame-options": ("Missing X-Frame-Options", "Clickjacking protection missing"),
                "content-security-policy": ("Missing Content-Security-Policy", "No CSP header for XSS defense"),
                "strict-transport-security": ("Missing Strict-Transport-Security", "HSTS not enabled"),
                "x-content-type-options": ("Missing X-Content-Type-Options", "MIME sniffing not prevented"),
            }
            for h, (title, desc) in checks.items():
                if h not in headers:
                    header_issues.append(title)
                    result.findings.append(Finding(
                        title=title, description=desc,
                        severity=FindingSeverity.MEDIUM, confidence=0.95,
                        status=FindingStatus.CANDIDATE, category="web_security",
                        affected_asset=url, source_agent_id=self.agent_id
                    ))

        result.discoveries.append({
            "type": "vulnerability_scan",
            "target": url,
            "nuclei_findings": nuclei_findings,
            "nikto_findings": nikto_findings[:20],
            "ssl_issues": ssl_issues,
            "ssl_info": ssl_raw[:1500],
            "header_issues": header_issues,
            "total_findings": len(result.findings),
            "tools": ["nuclei", "nikto", "sslscan", "curl"]
        })
        logger.info(f"VulnerabilityDetectionAgent: {len(result.findings)} findings "
                    f"(nuclei:{len(nuclei_findings)}, nikto:{len(nikto_findings)}, "
                    f"ssl:{len(ssl_issues)}, headers:{len(header_issues)})")
        return result


# ============================================================================
# MASTER ORCHESTRATOR
# ============================================================================

class ComprehensiveReconAgent(BaseAgent):
    def __init__(self, agent_id: str, context: Any):
        super().__init__(agent_id, "Comprehensive Reconnaissance Master", "comprehensive_recon", context)
        self.sub_agents = [
            SubdomainDiscoveryAgent(f"{agent_id}-sub", context),
            PortScanAgent(f"{agent_id}-port", context),
            DirectoryBruteforceAgent(f"{agent_id}-dir", context),
            TechStackAgent(f"{agent_id}-tech", context),
            VulnerabilityDetectionAgent(f"{agent_id}-vuln", context),
        ]

    async def perform_work(self) -> AgentResult:
        result = AgentResult(summary="Comprehensive reconnaissance complete")
        logger.info("=" * 60)
        logger.info("ComprehensiveReconAgent: Starting FULL Kali scan")
        logger.info("=" * 60)

        tasks = [a.perform_work() for a in self.sub_agents]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, AgentResult):
                result.discoveries.extend(r.discoveries)
                result.findings.extend(r.findings)
            elif isinstance(r, Exception):
                logger.error(f"Sub-agent failed: {r}")

        logger.info("=" * 60)
        logger.info(f"ComprehensiveReconAgent COMPLETE: "
                    f"{len(result.discoveries)} discoveries, {len(result.findings)} findings")
        logger.info("=" * 60)
        return result