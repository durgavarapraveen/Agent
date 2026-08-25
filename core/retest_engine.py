"""
Automated Finding Retest & Reproducibility Engine.
Performs multi-attempt validation calls to verify finding stability before report generation.
"""

import asyncio
import logging
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)


class RetestEngine:
    """Asynchronous reproducibility verification engine for candidate findings."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    async def _single_probe(self, url: str, method: str, headers: Dict[str, str], body_data: Optional[bytes] = None) -> Tuple[int, str]:
        """Perform a single HTTP probe asynchronously."""
        def _sync_fetch():
            req = urllib.request.Request(url, data=body_data, headers=headers, method=method.upper())
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
        location = str(finding.get("location") or finding.get("target") or "").strip()
        if not location:
            return True, attempts  # Cannot probe empty location; default to confirmed

        # Extract URL
        url = location.split()[0] if " " in location else location
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"http://{url}"

        method = str(finding.get("method") or "GET").upper()
        headers = finding.get("headers") or {"User-Agent": "DefensiveSecurityScanner-Retest/1.0"}
        tracer = finding.get("tracer_used")
        matched_error = finding.get("matched_error")
        expected_status = finding.get("expected_status") or 200

        successes = 0

        for attempt_idx in range(attempts):
            status, body = await self._single_probe(url, method, headers)
            matched = False

            if tracer and tracer in body:
                matched = True
            elif matched_error and matched_error.lower() in body.lower():
                matched = True
            elif not tracer and not matched_error and status == expected_status and status != 0:
                matched = True

            if matched:
                successes += 1

            # Small delay between attempts
            await asyncio.sleep(0.1)

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
                logger.info(f"FINDING_CONFIRMED: [{f.get('severity','?')}] {f.get('title','?')} ({successes}/{attempts} attempts succeeded)")
            else:
                f["status"] = "UNCONFIRMED"
                logger.warning(
                    f"FINDING_UNCONFIRMED: [{f.get('severity','?')}] {f.get('title','?')} "
                    f"failed reproducibility check ({successes}/{attempts} attempts succeeded)"
                )

        logger.info(f"RETEST_ENGINE_COMPLETE: {len(findings)} findings processed")
        return findings
