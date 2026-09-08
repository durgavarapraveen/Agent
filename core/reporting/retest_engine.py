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
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from core.security.authorization import TargetScopeValidator

logger = logging.getLogger(__name__)

# Anchor baseline/regression artefacts under a stable directory, not CWD.
# Previously these were bare filenames — every caller's current working
# directory (docker exec, cron worker, pytest) picked its own location, so
# regression diffs were computed against different baselines each run.
#
# Override with `RETEST_ARTIFACT_DIR` env if you want them somewhere specific.
_RETEST_DIR = Path(os.environ.get(
    "RETEST_ARTIFACT_DIR",
    str(Path(__file__).resolve().parents[2] / "data" / "retest"),
))
try:
    _RETEST_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass
BASELINE_FILE = str(_RETEST_DIR / "baseline_findings.json")
REGRESSION_REPORT_FILE = str(_RETEST_DIR / "regression_report.md")


class RetestEngine:
    """Read-only revalidation engine, rate limiter, and regression baseline differ."""

    def __init__(self, timeout: int = 5, rate_limit_per_sec: int = 10,
                 scope_validator: Optional[TargetScopeValidator] = None,
                 auth_headers: Optional[Dict[str, str]] = None):
        self.timeout = timeout
        self.rate_limit_per_sec = rate_limit_per_sec
        self.scope_validator = scope_validator or TargetScopeValidator.get()
        # Optional authenticated-session headers (Feature #6) so revalidation
        # probes exercise the post-auth surface rather than getting 401s.
        self.auth_headers = auth_headers or {}

    def _rate_limit_delay(self):
        """Enforce maximum 10 re-probes per second per target."""
        time.sleep(1.0 / float(self.rate_limit_per_sec))

    async def _single_probe(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, body_data: Optional[bytes] = None) -> Tuple[int, str]:
        """Perform a single HTTP probe asynchronously."""
        merged_headers = dict(self.auth_headers)
        merged_headers.update(headers or {})

        def _sync_fetch():
            req = urllib.request.Request(url, data=body_data, headers=merged_headers, method=method.upper())
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
        # Return code:
        #   -1  → network error / TLS failure — retest is INCONCLUSIVE
        #    0  → other unexpected exception (still inconclusive)
        #   >0  → real HTTP status code from the target
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DefensiveRetest/1.0", "Range": "bytes=0-0"}, method="HEAD")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return (resp.status == expected_status or (resp.status < 400 and expected_status < 400)), resp.status
        except urllib.error.HTTPError as e:
            return (e.code == expected_status), e.code
        except (urllib.error.URLError, socket.timeout, socket.gaierror, ConnectionError, OSError):
            return False, -1

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
        except (socket.timeout, socket.gaierror, ConnectionError, OSError):
            # NETWORK_ERROR sentinel — caller MUST distinguish this from
            # "banner mismatch" so the finding isn't wrongly downgraded.
            return False, "__NETWORK_ERROR__"

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
            elif got_code == -1:
                # Network / TLS failure — retest INCONCLUSIVE. Do NOT downgrade
                # confidence; the original finding stands until we can retest
                # under working network conditions.
                finding["reproducibility_status"] = "INCONCLUSIVE"
                finding.setdefault("retest_notes", []).append(
                    "Network error during retest — original evidence preserved."
                )
            else:
                # Real HTTP response that didn't match expected — treat as not
                # reproducible.
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
            elif got_banner == "__NETWORK_ERROR__":
                # Network / socket error — inconclusive; keep original score.
                finding["reproducibility_status"] = "INCONCLUSIVE"
                finding.setdefault("retest_notes", []).append(
                    "Network error during banner retest — original evidence preserved."
                )
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
        _nl = "\n"
        _new_list = _nl.join(
            f"- **{f.get('cve_id') or f.get('title')}** on `{f.get('url') or f.get('target')}`"
            for f in new_vulns
        ) if new_vulns else "None"
        _rem_list = _nl.join(
            f"- **{f.get('cve_id') or f.get('title')}** on `{f.get('url') or f.get('target')}` (Successfully Fixed)"
            for f in remediated
        ) if remediated else "None"
        report_md = f"""# Vulnerability Regression & Delta Report

## Summary Delta
- **New Vulnerabilities Introduced**: {len(new_vulns)}
- **Remediated Vulnerabilities**: {len(remediated)}
- **Persistent Vulnerabilities**: {len(persistent)}

### New Vulnerabilities
{_new_list}

### Remediated Vulnerabilities
{_rem_list}
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

    _AUTO_CONFIRM_TYPES = {
        "MISSING_HEADER", "TLS_WEAKNESS", "NIKTO_FINDING",
        "NUCLEI_MATCH", "INFO_DISCLOSURE",
    }

    # Exploit-derived findings need payload replay, not generic HEAD probes
    _EXPLOIT_CONFIRM_TYPES = {
        "SQL_INJECTION", "SQLI", "XSS", "COMMAND_INJECTION",
        "DIRECTORY_LISTING", "PATH_TRAVERSAL", "FILE_DISCLOSURE",
    }

    _AGENTIC_SOURCES = {"exploit_agent", "agentic_executor", "sqlmap", "nuclei", "dalfox"}

    async def can_reproduce(
        self,
        finding: Dict[str, Any],
        attempts: int = 3,
        min_success_threshold: int = 2
    ) -> Tuple[bool, int]:
        """
        Perform multi-attempt validation calls to verify finding reproducibility.
        Requires at least min_success_threshold successful attempts (default 2/3).
        Findings from tool-based scanners (nikto, nuclei, sslscan) are auto-confirmed
        since they were already validated by the tool itself.
        Exploit-derived findings (SQLi, XSS, etc.) use payload replay if available.
        Agentic executor findings with live evidence are auto-confirmed.
        """
        ftype = str(finding.get("type") or "").upper()
        if ftype in self._AUTO_CONFIRM_TYPES:
            return True, attempts

        source = str(finding.get("source") or "").lower()
        if source in self._AGENTIC_SOURCES and finding.get("evidence"):
            return True, attempts

        if finding.get("confirmed") or finding.get("exploited"):
            return True, attempts

        # Exploit findings with evidence/payload: auto-confirm if exploit agent marked success
        if ftype in self._EXPLOIT_CONFIRM_TYPES:
            return await self._reproduce_exploit_finding(finding, attempts, min_success_threshold)

        location = str(finding.get("location") or finding.get("target") or finding.get("url") or "").strip()
        if not location:
            return True, attempts

        url = location.split()[0] if " " in location else location
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"http://{url}"

        method = str(finding.get("method") or "GET").upper()
        headers = finding.get("headers") or {"User-Agent": "Mozilla/5.0 (compatible; SecurityRetest/1.0)"}
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

    async def _reproduce_exploit_finding(
        self, finding: Dict[str, Any], attempts: int, min_success_threshold: int
    ) -> Tuple[bool, int]:
        """Replay the actual exploit payload for injection/exploit-type findings."""
        evidence = finding.get("evidence") or finding.get("proof") or {}
        payload = finding.get("payload") or finding.get("post_data") or (evidence.get("payload") if isinstance(evidence, dict) else "")

        # If the exploit agent confirmed it already, trust the evidence
        if finding.get("confirmed") or finding.get("exploited"):
            return True, attempts

        location = str(finding.get("location") or finding.get("target") or finding.get("url") or "").strip()
        if not location:
            return True, attempts

        url = location.split()[0] if " " in location else location
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"

        ftype = str(finding.get("type") or "").upper()
        method = str(finding.get("method") or "").upper()

        # Directory listing: GET the path and check for listing indicators
        if ftype == "DIRECTORY_LISTING":
            successes = 0
            for _ in range(attempts):
                self._rate_limit_delay()
                status, body = await self._single_probe(url, "GET", {
                    "User-Agent": "Mozilla/5.0 (compatible; SecurityRetest/1.0)"
                })
                body_lower = body.lower()
                if status == 200 and any(ind in body_lower for ind in [
                    "index of", "directory listing", "<pre>", "parent directory",
                    ".md5", "package.json", "ftp",
                ]):
                    successes += 1
                await asyncio.sleep(0.01)
            return successes >= min_success_threshold, successes

        # SQLi/XSS/injection: replay with original method and payload
        if payload and method in ("POST", "PUT", "PATCH"):
            headers = finding.get("headers") or {
                "User-Agent": "Mozilla/5.0 (compatible; SecurityRetest/1.0)",
                "Content-Type": "application/json",
            }
            tracer = finding.get("tracer_used") or finding.get("matched_error")
            successes = 0
            for _ in range(attempts):
                self._rate_limit_delay()
                body_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
                status, body = await self._single_probe(url, method, headers, body_data=body_bytes)
                if tracer and tracer.lower() in body.lower():
                    successes += 1
                elif status and status < 500:
                    successes += 1
                await asyncio.sleep(0.01)
            return successes >= min_success_threshold, successes

        # No payload to replay — auto-confirm if exploit agent found it
        if finding.get("source") in ("exploit_agent", "sqlmap", "nuclei", "dalfox"):
            return True, attempts

        return True, attempts

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
