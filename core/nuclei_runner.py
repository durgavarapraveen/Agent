"""
Technology-Matched Nuclei Vulnerability Runner.
Maps detected technologies to official Nuclei template tags and executes non-blocking scans.
"""

import asyncio
import json
import logging
import os
import shutil
import urllib.parse
from typing import Dict, List, Optional, Any, Union

logger = logging.getLogger(__name__)

# Mapping from common technology keywords to official Nuclei template tags
TECH_TAG_MAP = {
    "nginx": "nginx",
    "apache": "apache",
    "wordpress": "wordpress,wp",
    "drupal": "drupal",
    "joomla": "joomla",
    "django": "django",
    "laravel": "laravel",
    "rails": "rails,ruby",
    "express": "express,nodejs",
    "react": "react",
    "vue": "vue",
    "angular": "angular",
    "php": "php",
    "tomcat": "tomcat",
    "iis": "iis",
    "spring": "spring,boot",
    "flask": "flask,python",
    "grafana": "grafana",
    "jenkins": "jenkins",
    "kubernetes": "k8s,kubernetes",
    "docker": "docker",
}


class NucleiRunner:
    """Asynchronous Nuclei vulnerability scanner with technology-based tag filtering."""

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = binary_path or shutil.which("nuclei") or "nuclei"

    def find_templates_for(self, tech: str) -> str:
        """
        Map a detected technology name to official Nuclei template tags.
        """
        tech_clean = (tech or "").strip().lower()
        for key, tags in TECH_TAG_MAP.items():
            if key in tech_clean:
                return tags
        return tech_clean

    async def execute_template(
        self,
        target: str,
        tech_tags: Union[List[str], str],
        timeout: int = 60
    ) -> List[Dict[str, Any]]:
        """
        Execute nuclei non-blockingly using asyncio.create_subprocess_exec.
        CLI flags: -u <target> -tags <tags> -jsonl -silent -severity low,medium,high,critical
        """
        if isinstance(tech_tags, list):
            tags_str = ",".join(tech_tags)
        else:
            tags_str = str(tech_tags)

        # Ensure general/fallback tags map to standard Nuclei template categories if needed
        if not tags_str or tags_str == "general":
            tags_str = "cve,misconfig,exposure,tech"

        cmd = [
            self.binary_path,
            "-u", target,
            "-tags", tags_str,
            "-jsonl",
            "-silent",
            "-severity", "low,medium,high,critical"
        ]

        logger.info(f"NUCLEI_EXECUTE: cmd='{' '.join(cmd)}' timeout={timeout}s")
        findings: List[Dict[str, Any]] = []

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=float(timeout))
            process_returncode = process.returncode
        except FileNotFoundError:
            # Fallback to KaliDockerExecutor if local nuclei binary is missing
            try:
                from agents.kali_executor import KaliDockerExecutor
                if KaliDockerExecutor.get_container():
                    full_cmd = f"nuclei -u {target} -tags {tags_str} -jsonl -silent -severity low,medium,high,critical"
                    logger.info(f"NUCLEI_EXECUTE_DOCKER: running via KaliDockerExecutor: '{full_cmd}'")
                    res = KaliDockerExecutor.run(full_cmd, timeout=timeout)
                    stdout_bytes = res.get("stdout", "").encode("utf-8")
                    stderr_bytes = res.get("stderr", "").encode("utf-8")
                    process_returncode = res.get("returncode", res.get("exit_code", 0))
                else:
                    logger.error(f"NUCLEI_BINARY_MISSING: binary '{self.binary_path}' not found in PATH")
                    return []
            except Exception as e:
                logger.error(f"NUCLEI_BINARY_MISSING: binary '{self.binary_path}' not found in PATH ({e})")
                return []
        except asyncio.TimeoutError:
            logger.warning(f"NUCLEI_TIMEOUT: scan timed out after {timeout}s for target={target}")
            return []
        except Exception as e:
            logger.error(f"NUCLEI_START_FAILED: failed to spawn process: {e}")
            return []

        if process_returncode != 0 and stderr_bytes:
            err_msg = stderr_bytes.decode("utf-8", errors="ignore").strip()
            logger.warning(f"NUCLEI_STDERR: returncode={process_returncode} msg='{err_msg[:200]}'")

        stdout_text = stdout_bytes.decode("utf-8", errors="ignore")
        for line in stdout_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                finding = self._parse_json_finding(target, data)
                if finding:
                    findings.append(finding)
            except json.JSONDecodeError:
                logger.debug(f"NUCLEI_PARSE_SKIP: non-JSON line: {line[:100]}")

        logger.info(f"NUCLEI_COMPLETE: target={target} matches={len(findings)}")
        return findings

    def _parse_json_finding(self, target: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Map raw nuclei JSON output line into a standardized Finding dictionary."""
        info = data.get("info", {})
        template_id = data.get("template-id") or data.get("template_id") or info.get("name") or "generic"
        title = info.get("name") or template_id
        severity = (info.get("severity") or "medium").upper()

        # Extract CVE IDs
        classification = info.get("classification", {})
        cve_ids = classification.get("cve-id") or classification.get("cve_id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        cve_str = ", ".join(cve_ids) if cve_ids else ""

        matched_at = data.get("matched-at") or data.get("matched") or target
        extracted_results = data.get("extracted-results") or []
        curl_cmd = data.get("curl-command") or ""

        proof = f"Nuclei match template '{template_id}' at {matched_at}"
        if cve_str:
            proof += f" (CVE: {cve_str})"
        if extracted_results:
            proof += f" Extracted: {', '.join(str(x) for x in extracted_results[:3])}"

        return {
            "type": "NUCLEI_MATCH",
            "title": f"Nuclei Match: {title}",
            "severity": severity,
            "target": target,
            "location": matched_at,
            "template_id": template_id,
            "cve": cve_str,
            "proof": proof,
            "details": f"Template '{template_id}' matched target {matched_at}. Description: {info.get('description', 'N/A')}",
            "curl_command": curl_cmd,
            "tool": "nuclei"
        }

    async def scan_context_technologies(self, ctx: Any, timeout: int = 60) -> List[Dict[str, Any]]:
        """
        Inspect technologies in SharedContext and run technology-matched scans.
        Registers all parsed findings into SharedContext.
        """
        all_findings = []
        tech_dict = getattr(ctx, "technologies", {}) or {}

        if not tech_dict and hasattr(ctx, "target"):
            tech_dict = {ctx.target: ["general"]}

        for host, techs in tech_dict.items():
            tags = [self.find_templates_for(t) for t in techs if t]
            if not tags:
                tags = ["cve", "default"]

            findings = await self.execute_template(host, tags, timeout=timeout)
            for f in findings:
                all_findings.append(f)
                if hasattr(ctx, "add_vulnerability"):
                    ctx.add_vulnerability(f)

        return all_findings
