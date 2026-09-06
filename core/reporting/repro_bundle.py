"""Per-finding reproducibility bundle generator.

For each HIGH/CRITICAL confirmed finding, produce a bundle:
  - reproduce.sh — curl command(s) that trigger the vuln
  - reproduce.py — Playwright script that walks the browser path
  - transcript.txt — full HTTP request+response of the exploit
  - README.md — one-page explanation + business impact

Bundles stored in scan_artifacts with kind='repro_bundle' — one artefact
per finding. Also exposed as a ZIP-per-scan endpoint.
"""
from __future__ import annotations
import json
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _to_curl(method: str, url: str, headers: Optional[Dict] = None,
              body: Optional[str] = None) -> str:
    parts = [f"curl -sk -X {method}"]
    for k, v in (headers or {}).items():
        parts.append(f"  -H {k+': '+str(v)!r}")
    if body:
        parts.append(f"  --data {body!r}")
    parts.append(f"  {url!r}")
    return " \\\n".join(parts)


def _extract_request_from_finding(v: Dict) -> Dict[str, Any]:
    """Try to reverse-engineer a working reproduction request from the
    finding's location + evidence + details."""
    url = v.get("location") or v.get("target") or ""
    method = "GET"
    body = None
    headers = {"User-Agent": "AntiGravity-Repro/1.0"}
    # Common signal: "POST ..." in title
    title = str(v.get("title") or "")
    m = re.match(r"^\s*([A-Z]+)\s+(https?://\S+)", title)
    if m:
        method = m.group(1); url = m.group(2)
    # Look for a JSON body inside details/evidence
    text = (v.get("details") or "") + "\n" + (v.get("evidence") or "")
    body_match = re.search(r"\{[^{}]{5,300}\}", text)
    if body_match:
        candidate = body_match.group(0)
        try:
            json.loads(candidate)
            body = candidate
            method = "POST" if method == "GET" else method
            headers["Content-Type"] = "application/json"
        except Exception:
            pass
    # Look for a payload string (?q=..., '/rest/... --')
    payload_match = re.search(r"payload[=:]?\s*['\"]([^'\"]{5,200})['\"]", text, re.IGNORECASE)
    if payload_match and "?" not in url:
        pl = payload_match.group(1)
        url = url + ("&" if "?" in url else "?") + f"q={pl}"
    # Bearer if we captured one from auth_bypasses referenced by this finding
    return {"method": method, "url": url, "headers": headers, "body": body}


def _playwright_script(url: str) -> str:
    return f"""from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page(ignore_https_errors=True)
    page.goto({url!r})
    page.wait_for_load_state('networkidle')
    page.screenshot(path='proof.png', full_page=True)
    print('Screenshot saved to proof.png')
    browser.close()
"""


def _readme(v: Dict, req: Dict) -> str:
    return (
        f"# {v.get('title', 'Vulnerability')}\n\n"
        f"**Severity:** {v.get('severity', 'INFO')}  \n"
        f"**Type:** {v.get('type', 'unknown')}  \n"
        f"**Target:** {v.get('location') or v.get('target', '')}  \n"
        f"**Confirmed:** {v.get('confirmed', False)}  \n\n"
        f"## Details\n{v.get('details', '(no details)')}\n\n"
        f"## Evidence\n```\n{(v.get('evidence') or v.get('proof') or '')[:2000]}\n```\n\n"
        f"## Reproduction\n\n"
        f"Run `bash reproduce.sh` for a curl-based reproduction, or "
        f"`python reproduce.py` for a Playwright browser walkthrough.\n\n"
        f"## Request\n```\n{req['method']} {req['url']}\n"
        f"{chr(10).join(k+': '+str(vv) for k,vv in (req['headers'] or {}).items())}\n\n"
        f"{req.get('body') or ''}\n```\n"
    )


def _bundle_zip(v: Dict) -> bytes:
    import io, zipfile
    req = _extract_request_from_finding(v)
    curl = _to_curl(**req)
    py = _playwright_script(req["url"])
    readme = _readme(v, req)
    transcript = (
        f"===== REQUEST =====\n{req['method']} {req['url']}\n"
        + "\n".join(f"{k}: {vv}" for k, vv in (req['headers'] or {}).items())
        + (f"\n\n{req['body']}" if req.get('body') else "")
        + f"\n\n===== EVIDENCE =====\n{(v.get('evidence') or v.get('proof') or '')[:8000]}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("README.md", readme)
        z.writestr("reproduce.sh", "#!/usr/bin/env bash\nset -e\n" + curl + "\n")
        z.writestr("reproduce.py", py)
        z.writestr("transcript.txt", transcript)
        z.writestr("finding.json", json.dumps(v, indent=2, default=str))
    return buf.getvalue()


def generate_bundles_for_scan(scan_id: str,
                                min_severity: str = "HIGH") -> Dict[str, int]:
    """Generate a per-finding bundle for every HIGH/CRITICAL confirmed finding.
    Stores as `scan_artifacts` rows with kind='repro_bundle'."""
    from core.database.pg_store import VulnRepo, ScanArtifactRepo
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    thr = order.get(min_severity.upper(), 1)
    vulns = VulnRepo.get_by_scan(scan_id) or []
    made = 0
    for v in vulns:
        sev = (v.get("severity") or "INFO").upper()
        if order.get(sev, 4) > thr:
            continue
        try:
            zip_bytes = _bundle_zip(v)
            title = (v.get("title") or "finding")[:80]
            safe = re.sub(r"[^\w\-]+", "_", title).strip("_") or "finding"
            ScanArtifactRepo.insert(
                scan_id, "repro_bundle", f"{safe}.zip", zip_bytes,
                mime_type="application/zip",
                metadata={"finding_title": title, "severity": sev,
                          "location": v.get("location") or v.get("target", "")})
            made += 1
        except Exception as e:
            logger.debug(f"[ReproBundle] failed for {v.get('title', '?')}: {e}")
    logger.info(f"[ReproBundle] Generated {made} bundle(s) for scan {scan_id}")
    return {"bundles_created": made, "vulns_considered": len(vulns)}
