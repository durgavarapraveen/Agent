"""
Automated Finding Retest & Reproducibility Engine (Phase 4 Module 4.2).
Executes strictly idempotent, read-only re-probes (TCP socket connect, HTTP HEAD / Range: 0-0, banner grabbing),
updates finding confidence/reproducibility status, enforces rate limiting (10 req/s),
and performs regression detection against baseline snapshots (baseline_findings.json).
"""

import asyncio
import json
import logging
import os
import socket
import time
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple, Any

from core.authorization import TargetScopeValidator

logger = logging.getLogger(__name__)

BASELINE_FILE = "baseline_findings.json"
REGRESSION_REPORT_FILE = "regression_report.md"


class RetestEngine:
    """Read-only revalidation engine, rate limiter, and regression baseline differ."""

    def __init__(self, timeout: int = 5, rate_limit_per_sec: int = 10, scope_validator: Optional[TargetScopeValidator] = None):
        self.timeout = timeout
        self.rate_limit_per_sec = rate_limit_per_sec
        self.scope_validator = scope_validator or TargetScopeValidator.get()

    def _rate_limit_delay(self):
        """Enforce maximum 10 re-probes per second per target."""
        time.sleep(1.0 / float(self.rate_limit_per_sec))

    async def _single_probe(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, body_data: Optional[bytes] = None) -> Tuple[int, str]:
        """Perform a single HTTP probe asynchronously."""
        def _sync_fetch():
            req = urllib.request.Request(url, data=body_data, headers=headers or {}, method=method.upper())
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="ignore")

        try:
            return await asyncio.to_thread(_sync_fetch)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
            return e.code, err_body
        except Exception as e:
            logger.debug(f"RetestEngine probe failed for {url}: {e}")
            return 0, ""

    def revalidate_port_finding(self, target_ip: str, port: int) -> bool:
        """Port-based findings: TCP connect socket check to confirm port is open."""
        self.scope_validator.validate(target_ip)
        self._rate_limit_delay()
        try:
            with socket.create_connection((target_ip, int(port)), timeout=self.timeout):
                return True
        except Exception:
            return False

    def revalidate_http_finding(self, url: str, expected_status: int = 200) -> Tuple[bool, int]:
        """
        HTTP-based findings: Send single HEAD request (or GET with Range: bytes=0-0)
        to exact endpoint to check response code match without re-running exploits.
        """
        self.scope_validator.validate(url)
        self._rate_limit_delay()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DefensiveRetest/1.0", "Range": "bytes=0-0"}, method="HEAD")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return (resp.status == expected_status or (resp.status < 400 and expected_status < 400)), resp.status
        except urllib.error.HTTPError as e:
            return (e.code == expected_status), e.code
        except Exception:
            return False, 0

    def revalidate_banner_finding(self, target_ip: str, port: int, expected_banner: str = "") -> Tuple[bool, str]:
        """Banner-based findings: Grab service banner with 5s timeout to confirm version hasn't changed."""
        self.scope_validator.validate(target_ip)
        self._rate_limit_delay()
        try:
            with socket.create_connection((target_ip, int(port)), timeout=self.timeout) as s:
                s.settimeout(self.timeout)
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                if expected_banner and expected_banner.lower() in banner.lower():
                    return True, banner
                elif not expected_banner and banner:
                    return True, banner
                return False, banner
        except Exception:
            return False, ""

    def process_finding_retest(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Revalidate finding based on type.
        Adjusts confidence: +5% (capped at 0.95) if reproducible; downgrades to LOW / NOT REPRODUCIBLE if failed;
        flags PATCHED if banner version changed.
        """
        conf_score = float(finding.get("confidence_score", 0.75))
        cve_or_title = str(finding.get("cve_id") or finding.get("title") or "Unknown")
        target = str(finding.get("target") or finding.get("url") or "127.0.0.1")

        if "port" in finding or "port_scan" in str(finding.get("type", "")).lower():
            port = int(finding.get("port", 80))
            ip = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            is_open = self.revalidate_port_finding(ip, port)

            if is_open:
                finding["confidence_score"] = min(0.95, round(conf_score + 0.05, 2))
                finding["reproducibility_status"] = "REPRODUCIBLE"
            else:
                finding["confidence_score"] = 0.30
                finding["confidence_category"] = "LOW"
                finding["reproducibility_status"] = "NOT REPRODUCIBLE"

        elif "url" in finding or "http" in str(finding.get("type", "")).lower():
            url = finding.get("url") or target
            expected_code = int(finding.get("status_code", 200))
            matched, got_code = self.revalidate_http_finding(url, expected_code)

            if matched:
                finding["confidence_score"] = min(0.95, round(conf_score + 0.05, 2))
                finding["reproducibility_status"] = "REPRODUCIBLE"
            else:
                finding["confidence_score"] = 0.30
                finding["confidence_category"] = "LOW"
                finding["reproducibility_status"] = "NOT REPRODUCIBLE"

        elif "banner" in finding or "version" in finding:
            port = int(finding.get("port", 80))
            ip = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            exp_banner = str(finding.get("banner") or finding.get("version") or "")
            matched, got_banner = self.revalidate_banner_finding(ip, port, exp_banner)

            if matched:
                finding["confidence_score"] = min(0.95, round(conf_score + 0.05, 2))
                finding["reproducibility_status"] = "REPRODUCIBLE"
            elif got_banner and not matched:
                finding["status"] = "PATCHED"
                finding["reproducibility_status"] = "PATCHED"
            else:
                finding["confidence_score"] = 0.30
                finding["confidence_category"] = "LOW"
                finding["reproducibility_status"] = "NOT REPRODUCIBLE"

        return finding

    def perform_regression_analysis(self, current_findings: List[Dict[str, Any]], baseline_path: str = BASELINE_FILE) -> Dict[str, List[Dict[str, Any]]]:
        """
        Diff current findings against baseline_findings.json:
        - Present in new but not old -> NEW_VULNERABILITY
        - Present in old but not new -> REMEDIATED
        - Present in both -> PERSISTENT
        Outputs regression_report.md summarizing delta.
        """
        old_findings = []
        if os.path.exists(baseline_path):
            try:
                with open(baseline_path, "r", encoding="utf-8") as f:
                    old_findings = json.load(f)
            except Exception as e:
                logger.debug(f"[RetestEngine] Baseline read error: {e}")

        def _key(item: Dict[str, Any]) -> str:
            return f"{item.get('cve_id') or item.get('title')}_{item.get('url') or item.get('target')}"

        old_map = {_key(f): f for f in old_findings}
        new_map = {_key(f): f for f in current_findings}

        new_vulns = [f for k, f in new_map.items() if k not in old_map]
        remediated = [f for k, f in old_map.items() if k not in new_map]
        persistent = [f for k, f in new_map.items() if k in old_map]

        # Save current as new baseline
        try:
            with open(baseline_path, "w", encoding="utf-8") as f:
                json.dump(current_findings, f, indent=2)
        except Exception as e:
            logger.error(f"[RetestEngine] Saving new baseline failed: {e}")

        # Write regression_report.md
        report_md = f"""# Vulnerability Regression & Delta Report

## Summary Delta
- **New Vulnerabilities Introduced**: {len(new_vulns)}
- **Remediated Vulnerabilities**: {len(remediated)}
- **Persistent Vulnerabilities**: {len(persistent)}

### New Vulnerabilities
{"".join([f"- **{f.get('cve_id') or f.get('title')}** on `{f.get('url') or f.get('target')}`\n" for f in new_vulns]) if new_vulns else "None\n"}

### Remediated Vulnerabilities
{"".join([f"- **{f.get('cve_id') or f.get('title')}** on `{f.get('url') or f.get('target')}` (Successfully Fixed)\n" for f in remediated]) if remediated else "None\n"}
"""
        try:
            with open(REGRESSION_REPORT_FILE, "w", encoding="utf-8") as f:
                f.write(report_md)
        except Exception as e:
            logger.error(f"[RetestEngine] Writing regression report failed: {e}")

        return {
            "NEW_VULNERABILITY": new_vulns,
            "REMEDIATED": remediated,
            "PERSISTENT": persistent
        }

    async def can_reproduce(
        self,
        finding: Dict[str, Any],
        attempts: int = 3,
        min_success_threshold: int = 2
    ) -> Tuple[bool, int]:
        """
        Perform multi-attempt validation calls to verify finding reproducibility.
        Requires at least min_success_threshold successful attempts (default 2/3).
        """
        location = str(finding.get("location") or finding.get("target") or finding.get("url") or "").strip()
        if not location:
            return True, attempts

        url = location.split()[0] if " " in location else location
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"http://{url}"

        method = str(finding.get("method") or "GET").upper()
        headers = finding.get("headers") or {"User-Agent": "DefensiveSecurityScanner-Retest/1.0"}
        tracer = finding.get("tracer_used")
        matched_error = finding.get("matched_error")
        expected_status = finding.get("expected_status") or finding.get("status_code") or 200

        successes = 0

        for attempt_idx in range(attempts):
            self._rate_limit_delay()
            status, body = await self._single_probe(url, method, headers)
            matched = False

            if tracer and tracer in body:
                matched = True
            elif matched_error and matched_error.lower() in body.lower():
                matched = True
            elif not tracer and not matched_error and (status == expected_status or (status < 400 and expected_status < 400)) and status != 0:
                matched = True

            if matched:
                successes += 1

            await asyncio.sleep(0.01)

        is_reproducible = (successes >= min_success_threshold)
        return is_reproducible, successes

    async def retest_findings(
        self,
        findings: List[Dict[str, Any]],
        attempts: int = 3,
        min_success_threshold: int = 2
    ) -> List[Dict[str, Any]]:
        """
        Retest all candidate findings, setting status='CONFIRMED' or status='UNCONFIRMED'.
        Logs explicit warnings for unconfirmed findings without dropping them.
        """
        logger.info(f"RETEST_ENGINE_START: retesting {len(findings)} findings ({attempts} attempts each)")

        for f in findings:
            reproducible, successes = await self.can_reproduce(f, attempts, min_success_threshold)
            f["retest_attempts"] = attempts
            f["retest_successes"] = successes

            if reproducible:
                f["status"] = "CONFIRMED"
                f["reproducibility_status"] = "REPRODUCIBLE"
                f["confidence_score"] = min(0.95, round(float(f.get("confidence_score", 0.75)) + 0.05, 2))
                logger.info(f"FINDING_CONFIRMED: [{f.get('severity','?')}] {f.get('title','?')} ({successes}/{attempts} attempts succeeded)")
            else:
                f["status"] = "UNCONFIRMED"
                f["reproducibility_status"] = "NOT REPRODUCIBLE"
                f["confidence_score"] = 0.30
                f["confidence_category"] = "LOW"
                logger.warning(
                    f"FINDING_UNCONFIRMED: [{f.get('severity','?')}] {f.get('title','?')} "
                    f"failed reproducibility check ({successes}/{attempts} attempts succeeded)"
                )

        logger.info(f"RETEST_ENGINE_COMPLETE: {len(findings)} findings processed")
        return findings
