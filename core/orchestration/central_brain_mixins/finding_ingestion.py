"""FindingIngestionMixin — extracted from central_brain.py.

Turns raw executor / tool-runner output into `SharedContextV2` vulnerability
records. Held as a mixin so `CentralBrain` composes it via MRO without any
public-API change.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class FindingIngestionMixin:
    def _ingest_executor_findings(self, test_id: str, target: str, evidence: dict) -> None:
        """Convert V2 executor evidence into SharedContext vulnerability records."""
        SEVERITY_MAP = {
            "jwt": "HIGH", "nosqli": "CRITICAL", "upload": "HIGH",
            "proto_pollution": "MEDIUM", "ssrf": "HIGH", "xxe": "HIGH",
            "csrf": "MEDIUM", "idor": "HIGH", "mass_assignment": "HIGH",
            "bizlogic": "MEDIUM", "race_condition": "MEDIUM",
            # Tier 1
            "ssti": "CRITICAL", "cmdi": "CRITICAL", "redirect": "MEDIUM",
            "oauth": "HIGH", "captcha": "MEDIUM", "password": "MEDIUM",
            "ratelimit": "MEDIUM", "log": "MEDIUM", "backup": "HIGH",
            "hidden": "HIGH", "git": "CRITICAL", "env": "CRITICAL",
            # Tier 2 prefixes
            "sqli": "CRITICAL", "xss": "HIGH", "lfi": "HIGH",
            # Tier 3
            "sca": "HIGH", "waf": "MEDIUM",
            # Tier 5
            "mfa": "CRITICAL", "crypto": "HIGH", "content": "MEDIUM",
            # Tier 6
            "stego": "MEDIUM", "video": "MEDIUM", "subtitle": "MEDIUM",
            "nested": "MEDIUM", "web3": "CRITICAL", "race": "HIGH",
            "hidden": "MEDIUM", "gdpr": "HIGH", "error": "MEDIUM",
            "encoding": "HIGH",
            # Tier 7
            "smuggling": "CRITICAL", "deser": "CRITICAL", "cloud": "HIGH",
            "subdomain": "HIGH", "ldap": "HIGH", "csp": "MEDIUM",
            "cache": "HIGH", "dom": "MEDIUM", "saml": "CRITICAL",
            "prompt": "HIGH", "cicd": "HIGH", "basic": "HIGH",
            "rate": "MEDIUM",
            # Tier 8
            "aws": "CRITICAL", "azure": "CRITICAL", "gcp": "CRITICAL",
            "k8s": "CRITICAL", "ci": "CRITICAL",
            "jenkins": "CRITICAL", "gitlab": "HIGH",
            "reflected": "HIGH", "postmessage": "HIGH",
            "clickjacking": "MEDIUM",
        }
        test_prefix = test_id.split("_")[0] if "_" in test_id else test_id
        default_sev = SEVERITY_MAP.get(test_prefix, "MEDIUM")

        findings_keys = [k for k in evidence if k.endswith("_findings") or k == "logic_findings"]
        for fk in findings_keys:
            items = evidence.get(fk, [])
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                test_name = item.get("test", test_id)
                vuln = {
                    "type": test_id.upper(),
                    "title": f"Deterministic test: {test_name} on {item.get('path', item.get('endpoint', target))}",
                    "severity": default_sev,
                    "status": "CONFIRMED" if item.get("status") in (200, 201) else "UNCONFIRMED",
                    "target": target,
                    "location": item.get("path", item.get("endpoint", "")),
                    "evidence": item.get("body_snippet", ""),
                    "source": "deterministic_executor",
                    "test_id": test_id,
                }
                self.ctx.add_vulnerability(vuln)

        # Also check for direct boolean indicators
        for bool_key in ["vulnerable", "introspection_enabled", "directory_listing", "traversal_detected"]:
            if evidence.get(bool_key):
                vuln = {
                    "type": test_id.upper(),
                    "title": f"Deterministic test: {bool_key} detected ({test_id})",
                    "severity": default_sev,
                    "status": "CONFIRMED",
                    "target": target,
                    "source": "deterministic_executor",
                    "test_id": test_id,
                }
                self.ctx.add_vulnerability(vuln)

    def _ingest_approach_a_result(self, capability: str, target: str, result: Any) -> None:
        """Parse and ingest tool results into SharedContext and knowledge stores."""
        if not result or not result.success:
            return
        
        stdout = getattr(result, "stdout", "") or ""
        data = getattr(result, "data", {}) or {}
        
        # 1. Ingest Subdomains
        # FIX: extract hostnames from ANY output format (dnsenum/fierce/assetfinder emit
        # column-formatted reports, not bare-domain-per-line). Scope matches to the apex.
        discovered_subs = set(data.get("subdomains", []) or data.get("domains", []))
        apex = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
        apex = apex[4:] if apex.startswith("www.") else apex
        if stdout and apex:
            host_re = re.compile(r'\b((?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,})\.?\b')
            for match in host_re.findall(stdout):
                host = match.rstrip('.').lower()
                if host == apex or host.endswith('.' + apex):
                    discovered_subs.add(host)
        
        if discovered_subs:
            self.ctx.add_subdomains(list(discovered_subs), source=getattr(result, "tool", capability))
            if hasattr(self, "persistent_knowledge_store") and self.persistent_knowledge_store:
                for sub in discovered_subs:
                    try:
                        self.persistent_knowledge_store.add_asset(self.target_id, "subdomain", sub)
                    except Exception:
                        pass
        
        # 2. Ingest Technologies & HTTP status
        techs = data.get("technologies") or data.get("tech") or []
        target_host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if techs:
            self.ctx.add_technologies(target_host, techs if isinstance(techs, list) else [str(techs)])
        elif stdout and ("[" in stdout or "http" in stdout):
            for line in stdout.splitlines()[:5]:
                if "[" in line and "]" in line:
                    parts = re.findall(r'\[(.*?)\]', line)
                    if parts:
                        self.ctx.add_technologies(target_host, parts[:4])
                        break
        
        # 3. Ingest Open Ports
        ports = data.get("ports") or data.get("open_ports") or []
        if not ports and stdout:
            for line in stdout.splitlines():
                match = re.search(r'(\d+)/tcp\s+open\s+(\S+)', line)
                if match:
                    ports.append({"port": int(match.group(1)), "service": match.group(2)})
        if ports:
            self.ctx.add_ports(target_host, ports)

        # 4. Ingest Endpoints from ANY tool that discovers URLs
        _ep_caps = ("endpoint_discovery", "web_crawling", "directory_bruteforce",
                     "api_enumeration", "vulnerability_scanning", "technology_fingerprinting")
        if stdout and capability in _ep_caps:
            endpoints = []
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                # ffuf CSV-style: URL  [Status: 200, Size: 1234, ...]
                m = re.search(r'(https?://\S+)\s+\[Status:\s*(\d+)', line)
                if m:
                    endpoints.append({"url": m.group(1), "status": int(m.group(2))})
                    continue
                # gobuster/feroxbuster: STATUS  SIZE  URL
                m = re.search(r'^(\d{3})\s+\S+\s+(https?://\S+)', line)
                if m:
                    endpoints.append({"url": m.group(2), "status": int(m.group(1))})
                    continue
                # bare URL lines (katana output)
                m = re.match(r'^(https?://\S+)$', line)
                if m:
                    url = m.group(1)
                    # skip static assets
                    if not re.search(r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map)(\?|$)', url, re.I):
                        endpoints.append({"url": url, "status": 0})
            if endpoints:
                self.ctx.add_endpoints(endpoints, source=getattr(result, "tool", capability))
                logger.info(f"Ingested {len(endpoints)} endpoints from {getattr(result, 'tool', capability)}")

        # 4b. Ingest directories from ffuf/gobuster/dirb/feroxbuster
        if stdout and capability in ("directory_bruteforce", "endpoint_discovery", "web_crawling"):
            tool_name = getattr(result, "tool", "")
            for line in stdout.splitlines():
                line = line.strip()
                # directory paths (ending with /)
                m = re.search(r'(https?://\S+/)\s', line)
                if m:
                    self.ctx.add_directory(m.group(1))
                # /ftp/ style directory listings
                m = re.search(r'(/[a-zA-Z0-9._-]+/)\s', line)
                if m and len(m.group(1)) > 2:
                    self.ctx.add_directory(f"{target.rstrip('/')}{m.group(1)}")

        # 5. Ingest Vulnerability findings from nikto/nuclei output
        if capability == "vulnerability_scanning" and stdout:
            vulns = []
            tool_name = getattr(result, "tool", "unknown")
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                # nuclei JSONL output (preferred — machine-parseable)
                if line.startswith("{") and '"template-id"' in line or '"template_id"' in line:
                    try:
                        import json as _json
                        ndata = _json.loads(line)
                        info = ndata.get("info", {})
                        tid = ndata.get("template-id") or ndata.get("template_id") or "unknown"
                        title = info.get("name") or tid
                        sev = (info.get("severity") or "medium").upper()
                        matched_at = ndata.get("matched-at") or ndata.get("matched") or target
                        classification = info.get("classification", {})
                        cve_ids = classification.get("cve-id") or classification.get("cve_id") or []
                        if isinstance(cve_ids, str):
                            cve_ids = [cve_ids]
                        vulns.append({
                            "type": "NUCLEI_MATCH",
                            "title": f"Nuclei: {title}",
                            "severity": sev,
                            "target": target,
                            "location": matched_at,
                            "template_id": tid,
                            "cve": ", ".join(cve_ids) if cve_ids else "",
                            "proof": f"Nuclei template '{tid}' matched at {matched_at}",
                            "details": info.get("description", f"Template {tid} matched"),
                            "tool": "nuclei",
                        })
                        continue
                    except Exception:
                        pass
                # nikto: + OSVDB-XXXX: description  OR  + description
                m = re.match(r'^\+\s+(OSVDB-\d+:\s*)?(.+)', line)
                _nikto_noise = (
                    "+ Target", "+ Start", "+ End", "+ Server:",
                    "+ SSL Info:", "+ Platform:", "+ No CGI Dir",
                    "+ Scan terminated", "+ host(s) tested",
                    "+ Multiple IPs", "+ Hostname:",
                )
                if m and not any(line.startswith(p) for p in _nikto_noise):
                    osvdb = (m.group(1) or "").strip().rstrip(":")
                    desc = m.group(2).strip()
                    if len(desc) > 10 and not re.match(r'^\d+\s+host\(s\)\s+tested', desc):
                        sev = "MEDIUM"
                        if any(k in desc.lower() for k in ("xss", "inject", "rce", "remote code", "execution")):
                            sev = "HIGH"
                        elif any(k in desc.lower() for k in ("missing", "header", "cookie", "info", "uncommon")):
                            sev = "LOW"
                        vulns.append({
                            "type": "NIKTO_FINDING",
                            "title": desc[:120],
                            "severity": sev,
                            "target": target,
                            "location": target,
                            "proof": f"nikto: {line.strip()}",
                            "details": desc,
                            "tool": tool_name,
                            "osvdb": osvdb,
                        })
                        continue
                # nuclei plaintext: [template-id] [severity] [protocol] URL
                m = re.match(r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)', line)
                if m:
                    vulns.append({
                        "type": "NUCLEI_MATCH",
                        "title": f"Nuclei: {m.group(1)}",
                        "severity": m.group(2).upper(),
                        "target": target,
                        "location": m.group(4),
                        "template_id": m.group(1),
                        "proof": line,
                        "details": f"Template {m.group(1)} matched at {m.group(4)}",
                        "tool": "nuclei",
                    })
            if vulns:
                for v in vulns:
                    if hasattr(self.ctx, 'add_vulnerability'):
                        self.ctx.add_vulnerability(v)
                for v in vulns:
                    logger.info(f"  [VULN] [{v.get('severity','?')}] {v.get('title','')} | type={v.get('type','')} | location={v.get('location','')}")
                    self._log_activity("finding",
                        f"[{v.get('severity','?')}] {v.get('title','')}",
                        tool=tool_name, target=v.get('location', target),
                        detail=f"Type: {v.get('type','')} | {v.get('details','')[:200]}",
                        output_data=str(v.get('proof', ''))[:1000])
                logger.info(f"Ingested {len(vulns)} vulnerability findings from {tool_name}")

        # 6. Ingest TLS/SSL findings from sslscan output
        if capability == "tls_analysis" and stdout:
            tls_findings = []
            ssl_data = {"protocols": [], "ciphers": [], "certificate": {}}
            for line in stdout.splitlines():
                # Parse SSL protocol acceptance
                m_proto = re.search(r'((?:SSL|TLS)v[\d.]+)\s+(\d+)\s+bits\s+(\S+)\s+(Accepted|Rejected)', line)
                if m_proto:
                    entry = {"protocol": m_proto.group(1), "bits": int(m_proto.group(2)),
                             "cipher": m_proto.group(3), "status": m_proto.group(4)}
                    ssl_data["ciphers"].append(entry)
                    if m_proto.group(4) == "Accepted":
                        proto = m_proto.group(1)
                        if proto not in ssl_data["protocols"]:
                            ssl_data["protocols"].append(proto)
                        if proto in ("SSLv2", "SSLv3"):
                            tls_findings.append({
                                "type": "TLS_WEAKNESS",
                                "title": f"Deprecated SSL protocol accepted: {line.strip()[:80]}",
                                "severity": "HIGH", "target": target, "location": target,
                                "proof": line.strip(),
                                "details": "Server accepts deprecated SSL protocol version",
                                "tool": "sslscan",
                            })
                # Parse certificate info
                m_subj = re.search(r'Subject:\s+(.+)', line)
                if m_subj:
                    ssl_data["certificate"]["subject"] = m_subj.group(1).strip()
                m_issuer = re.search(r'Issuer:\s+(.+)', line)
                if m_issuer:
                    ssl_data["certificate"]["issuer"] = m_issuer.group(1).strip()
                m_exp = re.search(r'Not valid after:\s+(.+)', line)
                if m_exp:
                    ssl_data["certificate"]["expires"] = m_exp.group(1).strip()

            if "Heartbleed" in stdout and "vulnerable" in stdout.lower() and "not vulnerable" not in stdout.lower():
                tls_findings.append({
                    "type": "TLS_WEAKNESS",
                    "title": "Heartbleed vulnerability detected",
                    "severity": "CRITICAL", "target": target, "location": target,
                    "proof": "sslscan Heartbleed test positive",
                    "details": "Server is vulnerable to Heartbleed (CVE-2014-0160)",
                    "tool": "sslscan",
                })
            if tls_findings:
                for v in tls_findings:
                    self.ctx.add_vulnerability(v)
                logger.info(f"Ingested {len(tls_findings)} TLS findings from sslscan")
            if ssl_data["protocols"] or ssl_data["certificate"]:
                self.ctx.add_ssl_info(target_host, ssl_data)
                logger.info(f"Stored SSL info for {target_host}: {len(ssl_data['protocols'])} protocols, {len(ssl_data['ciphers'])} ciphers")

        # 7. Ingest HTTP headers from curl/httpx/whatweb output and flag missing ones
        if capability in ("http_analysis", "technology_fingerprinting") and stdout:
            important_headers = {
                "X-Frame-Options": ("Missing X-Frame-Options header", "Clickjacking protection not enabled"),
                "Content-Security-Policy": ("Missing Content-Security-Policy header", "No CSP policy configured"),
                "Strict-Transport-Security": ("Missing HSTS header", "HSTS not enforced"),
                "X-Content-Type-Options": ("Missing X-Content-Type-Options header", "MIME sniffing protection not enabled"),
            }
            parsed_headers = {}
            for line in stdout.splitlines():
                m_hdr = re.match(r'^([A-Za-z][A-Za-z0-9-]+):\s+(.+)', line)
                if m_hdr:
                    parsed_headers[m_hdr.group(1)] = m_hdr.group(2).strip()
            if parsed_headers:
                self.ctx.add_headers(target_host, parsed_headers)
                logger.info(f"Stored {len(parsed_headers)} HTTP headers for {target_host}")
            response_headers = set()
            for line in stdout.splitlines():
                for hdr in important_headers:
                    if hdr.lower() in line.lower():
                        response_headers.add(hdr)

        # 8. Ingest secrets/sensitive files from tool output
        if stdout:
            _secret_patterns = [
                (r'(\.git/config|\.git/HEAD)\b', "Git repository exposed", "HIGH"),
                (r'(/\.env|\.env\.bak|\.env\.local)\b', "Environment file exposed", "HIGH"),
                (r'(\.kdbx|\.key|\.pem|\.p12|\.pfx)\b', "Sensitive key/credential file", "MEDIUM"),
                (r'(password|secret|api[_-]?key|token|credential)\s*[:=]\s*\S+', "Hardcoded secret", "HIGH"),
                (r'(/ftp/[^\s]+\.(?:md|txt|pdf|bak|sql))', "Sensitive file in FTP directory", "MEDIUM"),
            ]
            for pattern, desc, severity in _secret_patterns:
                for m in re.finditer(pattern, stdout, re.IGNORECASE):
                    self.ctx.add_secret({
                        "type": desc, "value": m.group(0)[:200], "location": target,
                        "severity": severity, "tool": getattr(result, "tool", capability),
                    })

        # 9. Ingest directory listings from tool output
        if stdout and capability in ("directory_bruteforce", "endpoint_discovery", "web_crawling",
                                     "vulnerability_scanning", "technology_fingerprinting"):
            _dir_re = re.compile(r'(?:Directory|Index of|listing)\s+(?:of\s+)?(https?://\S+|/\S+)', re.IGNORECASE)
            for m in _dir_re.finditer(stdout):
                self.ctx.add_directory(m.group(1))

        # 10. Ingest OSINT data (emails, employees, GitHub info) from theHarvester/whois
        if capability in ("employee_enumeration", "osint", "whois_lookup") and stdout:
            tool_name = getattr(result, "tool", capability)
            # Extract emails
            emails = set()
            email_re = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
            for m in email_re.finditer(stdout):
                email = m.group(0).lower()
                if apex in email or not email.endswith(('.png', '.jpg', '.gif')):
                    emails.add(email)
            if emails:
                existing = self.ctx.get("discovered_employees", []) or []
                existing_emails = {e.get("email", "").lower() for e in existing if isinstance(e, dict)}
                for email in emails:
                    if email.lower() not in existing_emails:
                        name_part = email.split("@")[0].replace(".", " ").replace("_", " ").replace("-", " ")
                        existing.append({"email": email, "name": name_part.title(), "source": tool_name})
                self.ctx.update("discovered_employees", existing)
                logger.info(f"Ingested {len(emails)} emails from {tool_name}")

            # Extract GitHub users/orgs
            gh_re = re.compile(r'github\.com/([a-zA-Z0-9_-]+)')
            gh_users = set()
            for m in gh_re.finditer(stdout):
                gh_users.add(m.group(1))
            if gh_users:
                existing_gh = self.ctx.get("github_profiles", []) or []
                existing_names = {g.get("username", "") for g in existing_gh if isinstance(g, dict)}
                for user in gh_users:
                    if user not in existing_names:
                        existing_gh.append({"username": user, "source": tool_name})
                self.ctx.update("github_profiles", existing_gh)

            # Extract leaked credential indicators
            cred_patterns = [
                r'(\d+)\s+(?:compromised|leaked|breached)\s+(?:user|credential|account)',
                r'(?:compromised|leaked|breached)\s+(?:user|credential|account)s?[:]\s*(\d+)',
            ]
            for pat in cred_patterns:
                m = re.search(pat, stdout, re.IGNORECASE)
                if m:
                    count = int(m.group(1))
                    existing_creds = self.ctx.get("leaked_credentials", []) or []
                    existing_creds.append({
                        "type": "breach_indicator", "source": tool_name,
                        "count": count, "note": f"{count} compromised credentials reported",
                    })
                    self.ctx.update("leaked_credentials", existing_creds)

        # 11. Record tool invocation in tool_executions (not captured_requests)
        tool_name = getattr(result, "tool", capability)
        command = getattr(result, "command", "") or ""
        if command:
            exec_record = {
                "tool": tool_name, "command": command[:500], "target": target,
                "capability": capability, "success": bool(result.success),
                "stdout_bytes": len(stdout),
            }
            self.ctx.add_tool_execution(exec_record)
            try:
                from core.database.pg_store import ToolExecutionRepo
                ToolExecutionRepo.save(
                    scan_id=self.scan_id, tool=tool_name,
                    command=command[:500], target=target,
                    capability=capability, success=bool(result.success),
                    stdout_bytes=len(stdout))
            except Exception:
                pass

        self._write_progress({"status": "running"})

