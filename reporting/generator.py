"""
Report Generator - FIXED
- No duplicate scanning (extracts from existing discoveries)
- UTF-8 encoding (no charmap errors)
- Strips ANSI escape codes
- Optional LLM enrichment (Ollama by default)
- Includes ALL findings (main + finalization)
"""

import json
import logging
import re
import asyncio
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from urllib.parse import urlparse

from core.models import Finding
from reporting.recon_report import ReconnaissanceReportGenerator
from agents.report_intelligence import ReportIntelligence

logger = logging.getLogger(__name__)

# ANSI escape sequence cleaner
ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def clean_ansi(text: str) -> str:
    """Remove ANSI escape codes from tool output"""
    if not isinstance(text, str):
        return text
    return ANSI_ESCAPE.sub('', text)


def clean_data(obj):
    """Recursively clean ANSI codes from strings"""
    if isinstance(obj, str):
        return clean_ansi(obj)
    if isinstance(obj, list):
        return [clean_data(x) for x in obj]
    if isinstance(obj, dict):
        return {k: clean_data(v) for k, v in obj.items()}
    return obj


class ReportGenerator:
    """Extracts technical data from existing discoveries. No re-scanning."""

    def __init__(self, context: Any, findings: List[Finding], discoveries: List[Dict[str, Any]]):
        self.context = context
        self.findings = findings
        # Clean ANSI codes from all discoveries once
        self.discoveries = clean_data(discoveries)
        self.report_dir = Path("reports")
        self.recon_generator = ReconnaissanceReportGenerator()
        self.intel = ReportIntelligence()

    async def generate(self):
        self.report_dir.mkdir(exist_ok=True)
        duration = getattr(self.context, 'get_duration_seconds', lambda: 0)()

        # Extract technical data from EXISTING discoveries (no re-scan)
        technical_data = self._extract_technical_data()

        # Format findings once
        findings_formatted = [self._fmt(f) for f in self.findings]

        # LLM enrichment (optional, works without it)
        llm_available = await self.intel.is_available()
        logger.info(f"LLM enrichment: {'AVAILABLE' if llm_available else 'UNAVAILABLE (using fallback)'}")

        exec_summary_text = ""
        prioritized = findings_formatted
        endpoint_analysis = {}

        if llm_available:
            logger.info("Generating LLM-powered executive summary...")
            exec_summary_text = await self.intel.generate_executive_summary(
                self.context.target, findings_formatted, self.discoveries
            )

            logger.info("Prioritizing findings via LLM...")
            prioritized = await self.intel.prioritize_findings(findings_formatted)

            # Analyze discovered endpoints
            all_endpoints = []
            for d in self.discoveries:
                if d.get("type") == "js_endpoint_analysis":
                    all_endpoints.extend(d.get("endpoints_discovered", []))
            if all_endpoints:
                logger.info(f"Analyzing {len(all_endpoints)} endpoints via LLM...")
                endpoint_analysis = await self.intel.analyze_endpoints(
                    all_endpoints, self.context.target
                )
        else:
            exec_summary_text = self.intel._fallback_summary(
                self.context.target, findings_formatted
            )

        # Recon report
        recon_report = self.recon_generator.generate_report(
            target=self.context.target, mode=self.context.mode,
            discoveries=self.discoveries, findings=self.findings, duration=duration
        )
        if "appendix" in recon_report:
            recon_report["appendix"]["technical_data"] = technical_data

        # Build final JSON report
        json_report = self._build_json_report(prioritized, exec_summary_text)
        json_report["discoveries"] = self.discoveries
        json_report["technical_data"] = technical_data
        json_report["reconnaissance"] = recon_report
        json_report["methodology"] = recon_report.get("methodology", "Autonomous multi-agent assessment")
        json_report["recommendations"] = recon_report.get("recommendations", self._recommendations())
        if endpoint_analysis:
            json_report["endpoint_intelligence"] = endpoint_analysis

        await self._save_json(json_report)
        await self._save_markdown(self._build_markdown(
            technical_data, exec_summary_text, prioritized, endpoint_analysis
        ))
        logger.info(f"Reports generated in {self.report_dir}/")

    def _extract_technical_data(self) -> Dict[str, Any]:
        """Pull technical data from existing discoveries - NO NEW SCANS"""
        td = {
            "subdomains": [], "ips": [], "ports_found": {},
            "technologies": [], "directories": [], "security_headers": {},
            "ssl_info": {}, "cookies": [], "whois": "",
            "js_endpoints": [], "secrets_found": [],
        }

        for d in self.discoveries:
            dtype = d.get("type", "")

            # From SubdomainDiscoveryAgent
            if dtype in ("subdomain_discovery", "live_dns"):
                td["subdomains"].extend(d.get("subdomains", []))
                td["ips"].extend(d.get("ips", []))
                if d.get("whois"):
                    td["whois"] = d["whois"]

            # From PortScanAgent
            elif dtype in ("port_scan", "live_ports"):
                ports = d.get("open_ports") or d.get("ports", {})
                if isinstance(ports, dict):
                    td["ports_found"].update({int(k): v for k, v in ports.items()})
                elif isinstance(ports, list):
                    services = d.get("services", [])
                    for i, p in enumerate(ports):
                        td["ports_found"][int(p)] = services[i] if i < len(services) else "unknown"

            # From TechStackAgent
            elif dtype in ("technology_stack", "live_tech"):
                techs = d.get("technologies", [])
                td["technologies"].extend([t for t in techs if isinstance(t, str)])
                if d.get("headers"):
                    hdrs = d["headers"] if isinstance(d["headers"], dict) else {}
                    for h in ["x-frame-options", "x-content-type-options", "content-security-policy",
                               "strict-transport-security", "x-xss-protection", "referrer-policy"]:
                        if h in hdrs:
                            td["security_headers"][h] = hdrs[h]
                        elif h not in td["security_headers"]:
                            td["security_headers"][h] = "MISSING"

            # From DirectoryBruteforceAgent
            elif dtype in ("directory_discovery", "live_dirs"):
                dirs = d.get("found_directories") or d.get("directories", [])
                td["directories"].extend(dirs)

            # From vuln scan
            elif dtype in ("vulnerability_scan",):
                for h in d.get("header_issues", []):
                    # These are titles like "Missing X-Frame-Options"
                    if "x-frame-options" in h.lower():
                        td["security_headers"]["x-frame-options"] = "MISSING"

            # From SSL scan
            elif dtype in ("live_ssl",):
                td["ssl_info"] = d.get("info", {})

            # From JS endpoint agent
            elif dtype == "js_endpoint_analysis":
                td["js_endpoints"] = d.get("endpoints_discovered", [])
                td["secrets_found"] = d.get("secrets_found", [])

        # Dedupe
        td["subdomains"] = sorted(set(td["subdomains"]))
        td["ips"] = sorted(set(td["ips"]))
        td["technologies"] = sorted(set(td["technologies"]))
        td["js_endpoints"] = sorted(set(td["js_endpoints"]))

        return td

    def _build_json_report(self, findings: List[Dict], exec_summary: str) -> Dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO")
            if sev in counts:
                counts[sev] += 1

        return {
            "metadata": {
                "title": f"Security Assessment Report - {self.context.target}",
                "assessor": "AutonomousSecurityAgent",
                "version": "2.1.0",
                "target": self.context.target,
                "mode": self.context.mode,
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": getattr(self.context, 'get_duration_seconds', lambda: 0)(),
                "llm_enriched": bool(exec_summary and len(exec_summary) > 100),
            },
            "executive_summary": {
                "narrative": exec_summary,
                "total_findings": len(findings),
                **counts,
                "total_discoveries": len(self.discoveries),
            },
            "scope": {
                "target": self.context.target,
                "mode": self.context.mode,
                "objectives": ["Security assessment"],
            },
            "findings": findings,
        }

    def _fmt(self, f: Finding) -> dict:
        return {
            "title": clean_ansi(getattr(f, 'title', '')),
            "description": clean_ansi(getattr(f, 'description', '')),
            "severity": f.severity.name if hasattr(f.severity, 'name') else str(f.severity),
            "confidence": getattr(f, 'confidence', 0.5),
            "category": getattr(f, 'category', ''),
            "affected_asset": getattr(f, 'affected_asset', ''),
            "status": f.status.name if hasattr(f.status, 'name') else 'CANDIDATE',
        }

    def _build_markdown(self, td: Dict, exec_summary: str,
                          findings: List[Dict], endpoint_analysis: Dict) -> str:
        # ASCII only - no unicode arrows or special chars
        lines = []
        lines.append(f"# Security Assessment Report\n\n")
        lines.append(f"**Target:** {self.context.target}\n")
        lines.append(f"**Mode:** {self.context.mode}\n")
        lines.append(f"**Date:** {datetime.now().isoformat()}\n\n")

        if exec_summary:
            lines.append(f"## Executive Summary\n\n{exec_summary}\n\n")

        lines.append(f"## Findings ({len(findings)} total)\n\n")
        for i, f in enumerate(findings, 1):
            sev = f.get('severity', 'INFO')
            prio = f.get('llm_priority', '')
            prio_str = f" [priority: {prio}]" if prio else ""
            lines.append(f"### {i}. [{sev}]{prio_str} {f.get('title', '')}\n\n")
            lines.append(f"{f.get('description', '')}\n\n")
            if f.get('llm_reason'):
                lines.append(f"*LLM reasoning: {f['llm_reason']}*\n\n")
            lines.append(f"- Category: {f.get('category', '')}\n")
            lines.append(f"- Affected: {f.get('affected_asset', '')}\n")
            lines.append(f"- Confidence: {f.get('confidence', 0):.0%}\n\n")

        if td.get("ips"):
            lines.append("## Resolved IPs\n\n")
            for ip in td["ips"]:
                lines.append(f"- {ip}\n")
            lines.append("\n")

        if td.get("subdomains"):
            lines.append("## Subdomains\n\n")
            for s in td["subdomains"][:50]:
                lines.append(f"- {s}\n")
            lines.append("\n")

        if td.get("ports_found"):
            lines.append("## Open Ports\n\n| Port | Service |\n|------|---------|\n")
            for p, s in td["ports_found"].items():
                lines.append(f"| {p} | {s} |\n")
            lines.append("\n")

        if td.get("technologies"):
            lines.append("## Technologies\n\n")
            for t in td["technologies"]:
                lines.append(f"- {t}\n")
            lines.append("\n")

        if td.get("security_headers"):
            lines.append("## Security Headers\n\n| Header | Status |\n|--------|--------|\n")
            for h, v in td["security_headers"].items():
                lines.append(f"| {h} | {v} |\n")
            lines.append("\n")

        if td.get("directories"):
            lines.append("## Discovered Paths\n\n| Path | Status |\n|------|--------|\n")
            for d in td["directories"]:
                path = d.get('path', '')
                status = d.get('status') or d.get('status_code', '')
                lines.append(f"| {path} | {status} |\n")
            lines.append("\n")

        if td.get("js_endpoints"):
            lines.append(f"## JavaScript-Discovered Endpoints ({len(td['js_endpoints'])})\n\n")
            for ep in td["js_endpoints"][:40]:
                lines.append(f"- `{ep}`\n")
            lines.append("\n")

        if td.get("secrets_found"):
            lines.append(f"## Secrets Found in JS ({len(td['secrets_found'])})\n\n")
            for s in td["secrets_found"]:
                lines.append(f"- **{s.get('type')}** in {s.get('source', '')}: `{s.get('redacted_value', '')}`\n")
            lines.append("\n")

        if endpoint_analysis.get("interesting"):
            lines.append("## LLM-Flagged Interesting Endpoints\n\n")
            for e in endpoint_analysis["interesting"]:
                lines.append(f"- `{e.get('endpoint', '')}` ({e.get('risk', 'unknown')} risk): {e.get('reason', '')}\n")
            lines.append("\n")

        if td.get("ssl_info"):
            si = td["ssl_info"]
            lines.append("## SSL Certificate\n\n")
            lines.append(f"- **Subject:** {si.get('subject', 'N/A')}\n")
            lines.append(f"- **Issuer:** {si.get('issuer', 'N/A')}\n")
            lines.append(f"- **Valid until:** {si.get('notAfter', 'N/A')}\n")
            if si.get('san'):
                lines.append(f"- **SANs:** {', '.join(si['san'][:10])}\n")
            lines.append("\n")

        lines.append("## Recommendations\n\n")
        for rec in self._recommendations():
            if isinstance(rec, dict):
                lines.append(f"- **{rec.get('priority', '')}**: {rec.get('action', '')}\n")
            else:
                lines.append(f"- {rec}\n")

        return "".join(lines)

    def _recommendations(self) -> List:
        recs = []
        crit = sum(1 for f in self.findings if f.severity.name == 'CRITICAL')
        high = sum(1 for f in self.findings if f.severity.name == 'HIGH')
        med = sum(1 for f in self.findings if f.severity.name == 'MEDIUM')
        if crit:
            recs.append(f"Address {crit} critical findings within 24-48 hours")
        if high:
            recs.append(f"Address {high} high-severity findings within 1 week")
        if med:
            recs.append(f"Address {med} medium-severity findings within 30 days")
        recs.extend([
            "Implement security monitoring and alerting",
            "Conduct regular security assessments",
            "Apply security patches monthly",
            "Establish incident response procedures",
        ])
        return recs

    async def _save_json(self, report: Dict):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = self.report_dir / f"report_{ts}.json"
        # UTF-8 encoding + ensure_ascii=False for proper unicode
        with open(fn, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)
        logger.info(f"JSON report saved: {fn}")

    async def _save_markdown(self, content: str):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = self.report_dir / f"report_{ts}.md"
        # UTF-8 encoding fixes the charmap error
        with open(fn, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"Markdown report saved: {fn}")