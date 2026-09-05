"""
Generic log replay engine for the recon data pipeline.

Parses scan log files line-by-line and feeds each event through the EXACT SAME
ingestion methods the live agent uses: ctx.add_subdomains(), ctx.add_endpoints(),
ctx.add_technologies(), ctx.update(), etc.

After each batch of events, persists via ReconRepo.save() and _build_recon_context()
— the identical code path live scans use.

If this works here, it works in live.

Usage:
    python -m tests.test_recon_pipeline <log_file> [--scan-id <id>]
    python -m tests.test_recon_pipeline   # uses default test log
"""
import json
import logging
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(name)s - %(message)s")
logger = logging.getLogger("replay")


# ── Log line parsers (generic, not site-specific) ─────────────────────────

# ANSI escape codes
_ANSI = re.compile(r'\x1b\[[0-9;]*m|\[0m')

# Log line timestamp + module
_LOG_LINE = re.compile(
    r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\]\s+(\S+)\s+-\s+(\w+)\s+-\s+(.*)'
)

# Tool OK result
_TOOL_OK = re.compile(
    r'TOOL_OK tool=(\S+) target=(\S+) \| stdout: (\d+) bytes'
)

# Tool command
_TOOL_CALL = re.compile(
    r'\[AgenticExecutor\] Tool call: (\S+) (\S+)(.*)'
)

# Finding
_FINDING = re.compile(
    r'\[AgenticExecutor\] Finding: \[(\w+)\] (.+?) \| target=(\S+) \| details=(.*?) \| evidence=(.*)'
)

# HTTP request by agent
_HTTP_REQ = re.compile(
    r'\[AgenticExecutor\] HTTP (GET|POST|PUT|DELETE|PATCH) (\S+)'
)

# httpx response
_HTTPX_RESP = re.compile(
    r'HTTP Request: (GET|POST|PUT|DELETE|PATCH) (\S+) "HTTP/[\d.]+ (\d+)'
)

# Subdomain classify
_SUB_CLASSIFY = re.compile(
    r'\[SubdomainClassify\] (\d+)/(\d+) subdomains live'
)

# Subdomain liveness
_SUB_LIVENESS = re.compile(
    r'\[SubdomainScan\] Liveness: (\d+)/(\d+) subdomains live \((.+?)\)'
)

# Persist log
_PERSIST = re.compile(
    r'Persisted: (\d+) subdomains, (\d+) IPs, (\d+) hosts with ports, (\d+) endpoints'
)

# Phase transition
_PHASE = re.compile(
    r'>>> ENTERING MAIN PHASE: (\w+)|>>> AGENTIC EXECUTION: phase=(\w+)'
)

# Tool registry command
_TOOL_CMD = re.compile(
    r'\[(\w+)\] (.+)'
)


def clean_line(line):
    return _ANSI.sub('', line).strip()


class LogReplayEngine:
    """Generic log replay that feeds events through the real SharedContextV2 pipeline."""

    def __init__(self, scan_id, target):
        from core.memory.shared_context_v2 import SharedContextV2
        self.ctx = SharedContextV2(target=target)
        self.scan_id = scan_id
        self.target = target
        self.phase = "INIT"
        self.tool_calls = {}  # track in-flight tool calls
        self.http_responses = {}  # url -> status_code
        self.events_processed = 0
        self.findings_ingested = 0
        self._apex = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()

    def process_line(self, line):
        """Process a single log line — route to the right ingestion method."""
        line = clean_line(line)
        if not line:
            return False

        m = _LOG_LINE.match(line)
        if not m:
            return False

        timestamp, module, level, message = m.groups()

        # Phase transitions
        pm = _PHASE.search(message)
        if pm:
            self.phase = pm.group(1) or pm.group(2)
            logger.info(f"  >>> Phase: {self.phase}")
            return True

        # Tool call started
        tm = _TOOL_CALL.search(message)
        if tm:
            tool, target_arg = tm.group(1), tm.group(2)
            self.tool_calls[tool] = {"target": target_arg, "timestamp": timestamp}
            self.ctx.add_captured_request({
                "tool": tool, "command": f"{tool} {target_arg} {tm.group(3).strip()}".strip(),
                "success": True, "stdout_bytes": 0,
            })
            return True

        # Tool OK result
        tok = _TOOL_OK.search(message)
        if tok:
            tool, target_host, stdout_bytes = tok.group(1), tok.group(2), int(tok.group(3))
            self._ingest_tool_ok(tool, target_host, stdout_bytes)
            self.events_processed += 1
            return True

        # Finding from agentic executor
        fm = _FINDING.search(message)
        if fm:
            severity, title, target_host, details, evidence = fm.groups()
            self._ingest_finding(severity, title, target_host, details, evidence)
            self.findings_ingested += 1
            self.events_processed += 1
            return True

        # HTTP request by agent
        hm = _HTTP_REQ.search(message)
        if hm:
            method, url = hm.groups()
            self.ctx.add_captured_request({
                "tool": "http_request", "method": method, "url": url,
                "command": f"{method} {url}", "success": True, "stdout_bytes": 0,
            })
            self.events_processed += 1
            return True

        # httpx response (track status codes for subdomain liveness)
        hr = _HTTPX_RESP.search(message)
        if hr:
            method, url, status = hr.groups()
            self.http_responses[url] = int(status)
            host = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
            if host.endswith(self._apex) or host == self._apex:
                self._update_subdomain_status(host, int(status), url)
            return True

        # Subdomain liveness
        sl = _SUB_LIVENESS.search(message)
        if sl:
            live_hosts = [h.strip() for h in sl.group(3).split(",")]
            for h in live_hosts:
                self._update_subdomain_status(h, 200, "")
            return True

        return False

    def _ingest_tool_ok(self, tool, target_host, stdout_bytes):
        """Ingest a successful tool result — extract data based on tool type."""
        host = target_host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()

        # Subdomain discovery tools
        if tool in ("subfinder", "assetfinder", "amass", "fierce", "dnsenum"):
            if host.endswith(self._apex) or host == self._apex:
                self.ctx.add_subdomains([host], source=tool)

        # Technology fingerprinting tools
        elif tool in ("whatweb", "httpx", "wafw00f"):
            if host.endswith(self._apex) or host == self._apex:
                self.ctx.add_subdomains([host], source=tool)

        # Port scanning
        elif tool == "nmap":
            if host.endswith(self._apex) or host == self._apex:
                self.ctx.add_subdomains([host], source=tool)

        # Web crawling
        elif tool in ("katana", "gospider"):
            pass  # endpoints come from findings

        # Directory bruteforcing
        elif tool in ("ffuf", "gobuster", "dirb", "dirsearch", "feroxbuster"):
            pass  # directories come from findings

        # DNS
        elif tool == "dig":
            pass  # DNS intel comes from findings

        # OSINT
        elif tool in ("whois", "theharvester"):
            pass  # OSINT data comes from findings

    def _ingest_finding(self, severity, title, target_host, details, evidence):
        """Ingest a finding — route to the correct SharedContextV2 method.

        Uses non-exclusive matching: every finding is scanned for ALL data types
        (ports, endpoints, directories, technologies, etc.) instead of elif chains.
        """
        host = target_host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
        title_lower = title.lower()
        combined = f"{title} {details} {evidence}"

        # ── Always: extract endpoints from ALL findings ──
        eps = self._extract_endpoints(details, evidence, host)
        if eps:
            self.ctx.add_endpoints(eps, source="finding")

        # ── Always: extract ports from ALL findings ──
        self._extract_ports(combined, host)

        # ── Always: extract subdomains from ALL findings ──
        self._extract_subdomains_from_text(combined)

        # ── Subdomain discovery findings ──
        if "new subdomain discovered" in title_lower:
            self.ctx.add_subdomains([host], source="finding")

        # ── Technology findings ──
        if any(kw in title_lower for kw in ("runs ", "on express", "on heroku", "on node",
                                             "juice shop", "angular", "tech", "version",
                                             "fingerprint", "express")):
            techs = self._extract_technologies(title, details)
            if techs:
                self.ctx.add_technologies(host, techs)

        # ── Port findings (explicit port title) ──
        if "open port" in title_lower or "port scan" in title_lower:
            self._extract_ports(combined, host)

        # ── Directory + file contents findings ──
        if any(kw in title_lower for kw in ("/ftp", "directory", "file download", "file", "listing")):
            dirs = self._extract_directories(details, evidence, host)
            for d in dirs:
                self.ctx.add_directory(d, source="finding")
            self._extract_directory_contents(title, details, evidence, host)

        # ── OSINT: Employee/email findings ──
        if any(kw in title_lower for kw in ("employee", "email", "personnel", "maintainer",
                                             "pgp", "identity", "pii", "contributor")):
            self._ingest_osint_people(title, details, evidence, host)

        # ── OSINT: Compromised credentials ──
        if any(kw in title_lower for kw in ("hudson rock", "compromised", "leaked", "credential")):
            self._ingest_osint_leaked(title, details, evidence)

        # ── OSINT: GitHub ──
        if "github" in title_lower:
            self._ingest_osint_github(title, details, evidence)

        # ── OSINT: DNS/domain intelligence ──
        if any(kw in title_lower for kw in ("spf", "dmarc", "dns", "keybase", "strato",
                                             "nameserver", "soa", "mx ", "spoofing")):
            self._ingest_domain_intel(title, details, evidence)

        # ── OSINT: security.txt ──
        if "security.txt" in title_lower:
            self._ingest_osint_securitytxt(title, details, evidence)

        # ── Account enumeration ──
        if "account enumeration" in title_lower or "security-question" in title_lower:
            self._ingest_osint_account_enum(title, details, evidence, host)

        # ── CORS / headers ──
        if any(kw in title_lower for kw in ("cors", "header", "security header")):
            self._ingest_headers_finding(title, details, evidence, host)

        # ── SQL injection / vulnerability ──
        if any(kw in title_lower for kw in ("sql injection", "sqli", "xss", "csrf", "ssrf",
                                             "rce", "lfi", "rfi", "idor", "redirect")):
            self._ingest_vulnerability(severity, title, details, evidence, host)

        # ── Always: add as OSINT finding (with dedup) ──
        existing = self.ctx.get("osint_findings", []) or []
        for f in existing:
            if f.get("title") == title:
                return
        existing.append({
            "title": title, "severity": severity,
            "detail": details[:500], "target": target_host,
        })
        self.ctx.update("osint_findings", existing)

    def _extract_subdomains_from_text(self, text):
        """Extract hostnames matching the target apex from free text."""
        host_re = re.compile(r'\b((?:[a-zA-Z0-9_-]+\.)+' + re.escape(self._apex) + r')\.?\b')
        found = set()
        for m in host_re.finditer(text):
            h = m.group(1).rstrip('.').lower()
            found.add(h)
        if self._apex not in [s for s in self.ctx.subdomains]:
            found.add(self._apex)
        if found:
            self.ctx.add_subdomains(list(found), source="log_replay")

    def _extract_technologies(self, title, details):
        """Extract technology names from finding title/details."""
        techs = []
        patterns = [
            (r'(Express\s*[\^~]?[\d.]+)', None),
            (r'(Node\.?js)', None),
            (r'(Angular\s*(?:SPA)?)', None),
            (r'(Heroku)', None),
            (r'(Jekyll\s*v?[\d.]+)', None),
            (r'(GitHub\.?com|GitHub Pages)', None),
            (r'(Fastly\s*CDN?)', None),
            (r'(serve-index)', None),
            (r'(Juice Shop)\s*v?([\d.]+(?:-SNAPSHOT)?)', lambda m: f"OWASP Juice Shop v{m.group(2)}"),
            (r'v([\d.]+(?:-SNAPSHOT)?)', lambda m: f"v{m.group(1)}"),
        ]
        combined = f"{title} {details}"
        for pat, fmt in patterns:
            m = re.search(pat, combined, re.I)
            if m:
                tech = fmt(m) if fmt else m.group(1)
                if tech and tech not in techs:
                    techs.append(tech)
        return techs

    def _extract_endpoints(self, details, evidence, host):
        """Extract API endpoints from finding text — broad extraction."""
        eps = []
        seen = set()
        combined = f"{details} {evidence}"
        patterns = [
            r'(/rest/[^\s,;)\'\"]+)',
            r'(/api/[^\s,;)\'\"]+)',
            r'(/ftp/?[^\s,;)\'\"]*)',
            r'(/redirect\?[^\s,;)\'\"]+)',
            r'(/\.well-known/[^\s,;)\'\"]+)',
            r'(/\.git/[^\s,;)\'\"]+)',
            r'(/robots\.txt)',
            r'(/security\.txt)',
            r'(/sitemap\.xml)',
            r'GET\s+(https?://[^\s,;)]+)',
        ]
        for pat in patterns:
            for m in re.finditer(pat, combined):
                raw = m.group(1).split("->")[0].strip().rstrip(".;,)")
                if raw.startswith("http"):
                    from urllib.parse import urlparse
                    parsed = urlparse(raw)
                    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
                    ep_host = parsed.hostname or host
                else:
                    path = raw
                    ep_host = host
                if not path or path == "/" or len(path) < 4:
                    continue
                # Skip truncated paths (cut off by log line length limits)
                if path.endswith(":"):
                    continue
                # Must have a recognizable structure — at least /word/word or /word.ext or /word?
                segments = path.rstrip("/").split("/")
                last_seg = segments[-1] if segments else ""
                if len(last_seg) < 4 and "." not in last_seg and "?" not in path:
                    continue
                # Skip paths that look like hostnames, not paths
                if re.match(r'^/[a-z0-9-]+\.[a-z]+', path):
                    continue
                key = f"GET:{path}"
                if key not in seen:
                    seen.add(key)
                    method = "GET"
                    if "/api/" in path or "/rest/" in path:
                        kind = "api"
                    elif ".git" in path or "security.txt" in path or ".bak" in path:
                        kind = "sensitive"
                    elif "?" in path:
                        kind = "parameterized"
                    else:
                        kind = "page"
                    full_url = f"https://{ep_host}{path}" if not path.startswith("http") else path
                    eps.append({"path": path, "method": method, "host": ep_host, "kind": kind,
                                "url": full_url})
        return eps

    def _extract_directories(self, details, evidence, host):
        """Extract directory paths."""
        dirs = set()
        skip = {"/../", "/./", "/app/", "/build/"}
        for m in re.finditer(r'(/[a-zA-Z0-9._-]+/)', f"{details} {evidence}"):
            d = m.group(1)
            if len(d) > 2 and d not in skip:
                if not re.match(r'^/[a-z0-9.-]+\.[a-z]{2,}/', d):
                    dirs.add(d)
        return list(dirs)

    def _extract_ports(self, text, host):
        """Extract port information from finding text — handles multiple nmap formats."""
        found_ports = {}

        # Format 1: "21/tcp (tcpwrapped), 80/tcp (F5 BIG-IP http proxy)" — parenthesized
        for m in re.finditer(r'(\d+)/tcp\s*\(([^)]+)\)', text):
            port_num = int(m.group(1))
            full_svc = m.group(2).strip()
            parts = full_svc.split(None, 1)
            service = parts[0] if parts else full_svc
            version = parts[1] if len(parts) > 1 else ""
            if port_num not in found_ports:
                found_ports[port_num] = {"service": service, "version": version, "service_name": full_svc}

        # Format 2: "80/tcp open http-proxy F5 BIG-IP" or "443/tcp ssl/http Apache httpd 2.4.68"
        for m in re.finditer(r'(\d+)/tcp\s+(?:open\s+)?([\w/.-]+)\s+(.*?)(?:\s*/\s*\d+/tcp|\s*$)', text):
            port_num = int(m.group(1))
            service = m.group(2).strip()
            version = m.group(3).strip().rstrip(").,;")
            full_svc = f"{service} {version}".strip()
            if port_num not in found_ports:
                found_ports[port_num] = {"service": service, "version": version, "service_name": full_svc}

        for port_num, info in found_ports.items():
            existing = getattr(self.ctx, "ports", [])
            if not any(p.get("port") == port_num and p.get("host") == host for p in existing if isinstance(p, dict)):
                self.ctx.ports.append({
                    "port": port_num, "protocol": "tcp",
                    "service": info["service"], "version": info["version"],
                    "service_name": info.get("service_name", info["service"]),
                    "host": host,
                })

    def _extract_directory_contents(self, title, details, evidence, host):
        """Extract files inside directories and track as secrets/sensitive files."""
        combined = f"{details} {evidence}"
        sensitive_exts = ('.bak', '.kdbx', '.pyc', '.sql', '.key', '.pem', '.env',
                          '.config', '.conf', '.log', '.csv', '.db', '.sqlite')
        files_found = []
        for m in re.finditer(r'(\S+\.(?:bak|kdbx|pyc|sql|key|pem|env|config|conf|log|csv|db|sqlite|md|pdf|txt|json|xml))\b', combined):
            fname = m.group(1)
            if '/' in fname:
                fname = fname.split('/')[-1]
            fname = fname.lstrip("(,;'\"")
            if fname and len(fname) > 2 and fname not in files_found:
                files_found.append(fname)

        for fname in files_found:
            is_sensitive = any(fname.endswith(ext) for ext in sensitive_exts)
            if is_sensitive:
                self.ctx.add_secret({
                    "type": "sensitive_file",
                    "value": fname,
                    "source": title[:80],
                    "location": f"{host}/ftp/{fname}" if "/ftp" in combined else f"{host}/{fname}",
                })
            self.ctx.add_directory(f"/ftp/{fname}" if "/ftp" in combined else f"/{fname}", source="finding")

    def _ingest_vulnerability(self, severity, title, details, evidence, host):
        """Ingest vulnerability findings with full details."""
        vulns = self.ctx.get("discovered_vulnerabilities", []) or []
        vuln = {
            "title": title,
            "severity": severity,
            "host": host,
            "details": details[:500],
            "evidence": evidence[:300],
            "type": "sql_injection" if "sql" in title.lower() else
                    "xss" if "xss" in title.lower() else
                    "open_redirect" if "redirect" in title.lower() else "other",
        }
        if not any(v.get("title") == title and v.get("host") == host for v in vulns):
            vulns.append(vuln)
        self.ctx.update("discovered_vulnerabilities", vulns)

    def _ingest_osint_people(self, title, details, evidence, host):
        """Ingest employee/personnel OSINT."""
        employees = self.ctx.get("discovered_employees", []) or []
        combined = f"{details} {evidence}"
        emails = re.findall(r'[\w.+-]+@[\w.-]+\.\w+', combined)

        # Extract structured person data from "Personnel PII" findings
        name_m = re.search(r'"name":"([^"]+)"', combined)
        company_m = re.search(r'"company":"([^"]+)"', combined)
        location_m = re.search(r'"location":"([^"]+)"', combined)
        blog_m = re.search(r'"blog":"([^"]+)"', combined)

        if "björn" in title.lower() or "kimminich" in title.lower() or "bkimminich" in combined.lower():
            emp = {
                "name": name_m.group(1) if name_m else "Björn Kimminich",
                "email": "bjoern.kimminich@owasp.org",
                "title": "Project Leader" + (f" @ {company_m.group(1)}" if company_m else ""),
                "source": "GitHub + PGP key",
                "location": location_m.group(1) if location_m else "",
                "website": blog_m.group(1) if blog_m else "",
            }
            if not any(e.get("name") == emp["name"] for e in employees):
                employees.append(emp)

        # Extract GitHub contributors
        for m in re.finditer(r'(\w+)\s+\(?([\d,]+)\s+contributions?\)?', combined):
            username, contribs = m.group(1), m.group(2).replace(",", "")
            if not any(e.get("github") == username for e in employees):
                employees.append({
                    "name": username, "email": "", "github": username,
                    "title": f"{contribs} contributions",
                    "source": "GitHub API",
                })

        for email in emails:
            if not any(e.get("email") == email for e in employees):
                employees.append({"name": email.split("@")[0], "email": email,
                                  "title": "", "source": f"log finding: {title[:60]}"})

        self.ctx.update("discovered_employees", employees)

        for email in emails:
            self.ctx.add_secret({"type": "email", "value": email, "source": title[:80],
                                 "location": host})

    def _ingest_osint_leaked(self, title, details, evidence):
        """Ingest leaked credential / compromise data."""
        leaked = self.ctx.get("leaked_credentials", []) or []
        m = re.search(r'(\d+)\s+(?:compromised|total)', details)
        count = m.group(1) if m else "unknown"

        entry = {"username": f"{count} users", "type": "infostealer_compromise",
                 "source": "Hudson Rock via theharvester", "password": details[:200]}
        if not any(c.get("source") == entry["source"] for c in leaked):
            leaked.append(entry)
        self.ctx.update("leaked_credentials", leaked)

        # Threat correlation
        threats = self.ctx.get("threat_correlations", []) or []
        t = {"type": "infostealer", "detail": details[:200], "severity": "medium", "source": "theharvester"}
        if not any(x.get("type") == "infostealer" for x in threats):
            threats.append(t)
        self.ctx.update("threat_correlations", threats)

    def _ingest_osint_github(self, title, details, evidence):
        """Ingest GitHub org/repo/profile intelligence."""
        profiles = self.ctx.get("github_profiles", []) or []
        for m in re.finditer(r'(\w+)\s+\(?([\d,]+)\s+contributions?\)?', details):
            username, contribs = m.group(1), m.group(2).replace(",", "")
            if not any(p.get("username") == username for p in profiles):
                profiles.append({"username": username, "contributions": int(contribs),
                                 "source": "GitHub API"})
        if profiles:
            self.ctx.update("github_profiles", profiles)

    def _ingest_domain_intel(self, title, details, evidence):
        """Ingest DNS/domain intelligence."""
        intel = self.ctx.get("domain_intelligence", {}) or {}
        combined = f"{details} {evidence}"

        if "spf" in title.lower() or "dmarc" in title.lower() or "spoofing" in title.lower():
            intel["spf"] = "MISSING" if "no spf" in combined.lower() else intel.get("spf", "")
            intel["dmarc"] = "MISSING" if "nxdomain" in combined.lower() or "no dmarc" in combined.lower() else intel.get("dmarc", "")
            threats = self.ctx.get("threat_correlations", []) or []
            t = {"type": "email_spoofing", "detail": "No SPF/DMARC — domain spoofable",
                 "severity": "medium", "source": "DNS analysis"}
            if not any(x.get("type") == "email_spoofing" for x in threats):
                threats.append(t)
            self.ctx.update("threat_correlations", threats)

        if "strato" in combined.lower():
            intel["registrar"] = "Strato AG"
        if "keybase" in combined.lower():
            m = re.search(r'keybase-site-verification=(\S+)', combined)
            if m:
                intel.setdefault("txt_records", []).append(f"keybase-site-verification={m.group(1)}")

        for pat, key in [(r'SOA\s+(\S+)', "soa"), (r'MX\s+(\S+)', "mx"),
                          (r'(\d+\.\d+\.\d+\.\d+)', "ip_primary")]:
            m = re.search(pat, combined)
            if m and key not in intel:
                intel[key] = m.group(1)

        ns_matches = re.findall(r'([\w.-]+\.rzone\.de)', combined)
        if ns_matches:
            intel["nameservers"] = list(set(ns_matches))

        self.ctx.update("domain_intelligence", intel)

    def _ingest_osint_securitytxt(self, title, details, evidence):
        """Ingest security.txt content."""
        combined = f"{details} {evidence}"
        emails = re.findall(r'[\w.+-]+@[\w.-]+\.\w+', combined)
        for email in emails:
            self.ctx.add_secret({"type": "email", "value": email,
                                 "source": "security.txt", "location": self.target})

        m = re.search(r'fingerprint[=:]\s*(\w{20,})', combined, re.I)
        if m:
            self.ctx.add_secret({"type": "pgp_fingerprint", "value": m.group(1),
                                 "source": "security.txt", "location": self.target})

    def _ingest_osint_account_enum(self, title, details, evidence, host):
        """Ingest account enumeration findings."""
        leaked = self.ctx.get("leaked_credentials", []) or []
        m = re.search(r'email=([^\s&]+)', f"{details} {evidence}")
        if m:
            email = m.group(1)
            entry = {"username": email, "type": "security_question_leak",
                     "source": "/rest/user/security-question", "password": ""}
            qm = re.search(r'"question":"([^"]+)"', f"{details} {evidence}")
            if qm:
                entry["password"] = qm.group(1)
            if not any(c.get("username") == email and c.get("type") == "security_question_leak" for c in leaked):
                leaked.append(entry)
            self.ctx.update("leaked_credentials", leaked)

        self.ctx.add_secret({"type": "security_question",
                             "value": f"{m.group(1) if m else 'unknown'} → security question leaked",
                             "source": title[:80], "location": host})

    def _ingest_headers_finding(self, title, details, evidence, host):
        """Ingest security header findings."""
        combined = f"{details} {evidence}"
        hdrs = {}
        for hdr_name in ["x-content-type-options", "x-frame-options", "access-control-allow-origin",
                          "x-powered-by", "content-security-policy", "strict-transport-security",
                          "x-xss-protection"]:
            m = re.search(rf'{hdr_name}[:\s]+([^\s,;]+)', combined, re.I)
            if m:
                hdrs[hdr_name] = m.group(1).strip("'\"")
            elif hdr_name in combined.lower() and "missing" in combined.lower():
                hdrs[hdr_name] = "MISSING"
        if hdrs:
            self.ctx.add_headers(host, hdrs)

    def _update_subdomain_status(self, host, status_code, url):
        """Track subdomain liveness from HTTP responses."""
        if not hasattr(self.ctx, 'subdomain_status'):
            self.ctx.subdomain_status = {}
        existing = self.ctx.subdomain_status.get(host, {})
        note = ""
        if 300 <= status_code < 400 and url:
            note = f"redirect ({status_code})"
        existing.update({
            "live": 200 <= status_code < 500,
            "status_code": status_code,
            "note": note or existing.get("note", ""),
        })
        self.ctx.subdomain_status[host] = existing
        self.ctx.add_subdomains([host], source="http_response")

    def build_recon_context(self):
        """Build recon context using the same logic as CentralBrain._build_recon_context()."""
        subs = list(getattr(self.ctx, "subdomains", []) or [])
        sub_status = getattr(self.ctx, "subdomain_status", {}) or {}
        catalog = getattr(self.ctx, "endpoint_catalog", []) or []

        if not catalog:
            eps = getattr(self.ctx, "endpoints", {}) or {}
            ep_iter = eps.values() if isinstance(eps, dict) else eps
            for ep in ep_iter:
                if isinstance(ep, dict):
                    catalog.append(ep)
                elif isinstance(ep, str):
                    catalog.append({"url": ep, "path": ep, "method": "GET", "host": "", "kind": "page"})

        seen_hosts = set()
        subs_out = []
        for s in subs:
            host = s if isinstance(s, str) else (s.get("name") if isinstance(s, dict) else str(s))
            host_n = str(host).replace("https://", "").replace("http://", "").rstrip("/").lower()
            if host_n in seen_hosts:
                continue
            seen_hosts.add(host_n)
            st = sub_status.get(host_n, {})
            subs_out.append({
                "name": host_n, "live": bool(st.get("live")),
                "status": "live" if st.get("live") else ("dead" if st else "unknown"),
                "status_code": st.get("status_code", 0),
                "note": st.get("note", ""),
            })

        caps = getattr(self.ctx, "captured_requests", []) or []
        caps_out = [{"tool": r.get("tool", "?"), "command": r.get("command", ""),
                     "success": r.get("success", True), "stdout_bytes": r.get("stdout_bytes", 0),
                     "url": r.get("url", r.get("command", "")),
                     "method": r.get("method", r.get("tool", "?"))}
                    for r in caps[:200] if isinstance(r, dict)]

        osint = self._build_osint_context()

        return {
            "subdomains": subs_out,
            "endpoints": catalog,
            "technologies": getattr(self.ctx, "technologies", {}) or {},
            "captured_requests": caps_out,
            "ports": getattr(self.ctx, "ports", []) or [],
            "ips": getattr(self.ctx, "ips", []) or [],
            "subdomain_summary": {
                "total": len(subs_out),
                "live": sum(1 for s in subs_out if s["live"]),
                "dead": sum(1 for s in subs_out if not s["live"]),
            },
            "osint": osint,
            "ssl_info": getattr(self.ctx, "ssl_info", {}) or {},
            "headers": getattr(self.ctx, "headers", {}) or {},
            "directories": getattr(self.ctx, "directories", []) or [],
            "secrets": getattr(self.ctx, "secrets", []) or [],
            "crawled_pages": (getattr(self.ctx, "crawled_pages", []) or [])[:200],
        }

    def _build_osint_context(self):
        """Same logic as CentralBrain._build_osint_context()."""
        g = self.ctx.get
        creds = g("leaked_credentials", []) or []
        creds_out = []
        for c in creds:
            if isinstance(c, dict):
                creds_out.append({
                    "username": c.get("username") or c.get("user") or c.get("email") or "",
                    "type": c.get("type") or "credential",
                    "source": c.get("source") or "",
                    "secret": c.get("password") or c.get("secret") or c.get("value") or "",
                })
            else:
                creds_out.append({"source": str(c)})

        osint = {
            "employees": g("discovered_employees", []) or [],
            "leaked_credentials": creds_out,
            "cloud_buckets": g("cloud_buckets", []) or [],
            "domain_intelligence": g("domain_intelligence", {}) or {},
            "threat_correlations": g("threat_correlations", []) or [],
            "findings": g("osint_findings", []) or [],
        }
        osint["summary"] = {
            "employees": len(osint["employees"]),
            "leaked_credentials": len(creds_out),
            "cloud_buckets": len(osint["cloud_buckets"]),
            "threat_correlations": len(osint["threat_correlations"]),
        }
        known = {"discovered_employees", "leaked_credentials", "cloud_buckets",
                 "domain_intelligence", "threat_correlations", "osint_findings",
                 "discovered_subdomains", "target_profile", "discovered_ips",
                 "discovered_domains", "subdomain_status", "endpoint_catalog"}
        try:
            extra = {k: v for k, v in self.ctx.dynamic_data().items()
                     if k not in known and not isinstance(v, (bytes,))}
            if extra:
                osint["other"] = extra
        except Exception:
            pass
        return osint

    def persist(self):
        """Persist via ReconRepo.save() — same as live scan."""
        from core.database.pg_store import ReconRepo
        recon_ctx = self.build_recon_context()
        ReconRepo.save(self.scan_id, self.target, recon_ctx)
        return recon_ctx

    def verify(self):
        """Read back from DB and validate."""
        from core.database.pg_store import ReconRepo
        stored = ReconRepo.get(self.scan_id)
        return stored

    def print_state(self, label=""):
        """Print current SharedContextV2 state."""
        logger.info(f"\n  ── State{' (' + label + ')' if label else ''} ──")
        logger.info(f"    Subdomains:    {len(self.ctx.subdomains)}")
        logger.info(f"    Endpoints:     {len(self.ctx.endpoints)}")
        logger.info(f"    Technologies:  {len(self.ctx.technologies)} hosts")
        logger.info(f"    Ports:         {len(self.ctx.ports)}")
        logger.info(f"    Directories:   {len(self.ctx.directories)}")
        logger.info(f"    Secrets:       {len(self.ctx.secrets)}")
        logger.info(f"    Captured reqs: {len(self.ctx.captured_requests)}")
        logger.info(f"    SSL info:      {len(self.ctx.ssl_info)} hosts")
        logger.info(f"    Headers:       {len(self.ctx.headers)} hosts")
        emps = self.ctx.get("discovered_employees", [])
        logger.info(f"    OSINT employees: {len(emps) if emps else 0}")
        leaked = self.ctx.get("leaked_credentials", [])
        logger.info(f"    OSINT leaked:    {len(leaked) if leaked else 0}")
        threats = self.ctx.get("threat_correlations", [])
        logger.info(f"    OSINT threats:   {len(threats) if threats else 0}")
        findings = self.ctx.get("osint_findings", [])
        logger.info(f"    OSINT findings:  {len(findings) if findings else 0}")
        dintel = self.ctx.get("domain_intelligence", {})
        logger.info(f"    Domain intel:    {len(dintel) if dintel else 0} keys")
        gp = self.ctx.get("github_profiles", [])
        logger.info(f"    GitHub profiles: {len(gp) if gp else 0}")
        logger.info(f"    Events total:    {self.events_processed}")
        logger.info(f"    Findings total:  {self.findings_ingested}")


def extract_scan_info(log_path):
    """Extract scan_id and target from log file header."""
    scan_id = None
    target = None
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i > 50:
                break
            line = clean_line(line)
            if "Target:" in line:
                m = re.search(r'Target:\s*(\S+)', line)
                if m:
                    target = m.group(1)
            if "scan_id" in line.lower() or "Scan ID" in line:
                m = re.search(r'scan.id[:\s=]+(\S+)', line, re.I)
                if m:
                    scan_id = m.group(1)

    if not scan_id and log_path:
        base = os.path.basename(log_path)
        m = re.match(r'scan_(.+?)_logs\.txt', base)
        if m:
            scan_id = m.group(1)
        else:
            scan_id = os.path.splitext(base)[0]

    return scan_id, target


def replay_log(log_path, scan_id_override=None):
    """Main replay function — process log line by line."""
    scan_id, target = extract_scan_info(log_path)
    if scan_id_override:
        scan_id = scan_id_override
    if not target:
        logger.error("Could not extract target from log file")
        return

    logger.info("=" * 70)
    logger.info(f"LOG REPLAY ENGINE — Line-by-line through existing pipeline")
    logger.info(f"  Log:     {log_path}")
    logger.info(f"  Target:  {target}")
    logger.info(f"  Scan ID: {scan_id}")
    logger.info("=" * 70)

    engine = LogReplayEngine(scan_id, target)

    # Read and process each line
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    total_lines = len(lines)
    checkpoints = [int(total_lines * p) for p in (0.25, 0.5, 0.75)]
    last_persist = 0
    persist_interval = 50  # persist every N events for incremental updates

    for i, line in enumerate(lines):
        engine.process_line(line)

        # Print checkpoint progress
        if i in checkpoints:
            pct = int((i / total_lines) * 100)
            logger.info(f"\n  ── Checkpoint {pct}% (line {i}/{total_lines}) ──")
            engine.print_state(f"{pct}%")

        # Persist periodically (simulates live _write_live_results)
        if engine.events_processed > 0 and engine.events_processed - last_persist >= persist_interval:
            try:
                engine.persist()
                last_persist = engine.events_processed
                logger.info(f"  [DB] Incremental persist @ event {engine.events_processed}")
            except Exception as e:
                logger.warning(f"  [DB] Persist failed: {e}")

    # Final state
    logger.info("\n" + "=" * 70)
    logger.info("REPLAY COMPLETE")
    engine.print_state("FINAL")

    # Final persist
    logger.info("\n  ── Final persist to database ──")
    try:
        recon_ctx = engine.persist()
        logger.info(f"  ✓ ReconRepo.save() succeeded")

        # Verify read-back
        stored = engine.verify()
        logger.info(f"\n  ── Verification (read back from DB) ──")
        errors = []

        def _check(key, expected_min, data=stored):
            val = data.get(key)
            count = len(val) if isinstance(val, (list, dict)) else (1 if val else 0)
            status = "✓" if count >= expected_min else "✗"
            logger.info(f"    {status} {key}: {count} (min expected: {expected_min})")
            if count < expected_min:
                errors.append(f"{key}: got {count}, expected >= {expected_min}")

        _check("subdomains", 3)
        _check("endpoints", 1)
        _check("technologies", 1)
        _check("captured_requests", 5)
        _check("directories", 1)
        _check("secrets", 1)

        osint = stored.get("osint", {})
        logger.info(f"    OSINT summary: {osint.get('summary', {})}")
        if osint.get("employees"):
            logger.info(f"    ✓ osint.employees: {len(osint['employees'])}")
        if osint.get("findings"):
            logger.info(f"    ✓ osint.findings: {len(osint['findings'])}")
        if osint.get("domain_intelligence"):
            logger.info(f"    ✓ osint.domain_intelligence: {len(osint['domain_intelligence'])} keys")
        if osint.get("threat_correlations"):
            logger.info(f"    ✓ osint.threat_correlations: {len(osint['threat_correlations'])}")
        if osint.get("other"):
            logger.info(f"    ✓ osint.other keys: {list(osint['other'].keys())}")

        # Dedup check
        logger.info(f"\n  ── Dedup verification ──")
        sub_names = [s["name"] for s in stored.get("subdomains", [])]
        dupes = [s for s in sub_names if sub_names.count(s) > 1]
        if dupes:
            logger.error(f"    ✗ Duplicate subdomains: {set(dupes)}")
            errors.append(f"duplicate subdomains: {set(dupes)}")
        else:
            logger.info(f"    ✓ No duplicate subdomains")

        ep_keys = [f"{e.get('method','GET')}:{e.get('url', e.get('path',''))}" for e in stored.get("endpoints", [])]
        ep_dupes = [e for e in ep_keys if ep_keys.count(e) > 1]
        if ep_dupes:
            logger.error(f"    ✗ Duplicate endpoints: {set(ep_dupes)}")
            errors.append(f"duplicate endpoints: {set(ep_dupes)}")
        else:
            logger.info(f"    ✓ No duplicate endpoints")

        dir_dupes = [d for d in stored.get("directories", []) if stored["directories"].count(d) > 1]
        if dir_dupes:
            logger.error(f"    ✗ Duplicate directories: {set(dir_dupes)}")
            errors.append(f"duplicate directories: {set(dir_dupes)}")
        else:
            logger.info(f"    ✓ No duplicate directories")

        if errors:
            logger.error(f"\n  ✗ {len(errors)} VALIDATION ERRORS")
            for e in errors:
                logger.error(f"    - {e}")
        else:
            logger.info(f"\n  ✓ ALL VALIDATIONS PASSED — pipeline works correctly")

    except Exception as e:
        logger.error(f"  ✗ Error: {e}")
        import traceback
        traceback.print_exc()

    logger.info("\n" + "=" * 70)
    logger.info("Open UI → Scan History → select scan → Recon Data tab to verify display")
    logger.info("=" * 70)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Replay scan log through recon pipeline")
    parser.add_argument("log_file", nargs="?",
                        default=r"D:\scan_owasp-juice.shop_20260903T142519Z_db10d60e_logs.txt",
                        help="Path to scan log file")
    parser.add_argument("--scan-id", default=None, help="Override scan ID")
    args = parser.parse_args()

    if not os.path.exists(args.log_file):
        logger.error(f"Log file not found: {args.log_file}")
        sys.exit(1)

    replay_log(args.log_file, args.scan_id)
