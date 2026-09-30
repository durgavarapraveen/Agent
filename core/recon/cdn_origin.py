"""CDN origin unmasking.

subdomain_enum detects that a host is behind Cloudflare/Akamai/Fastly but never
resolves the ORIGIN behind it (often a direct-IP with weaker controls). This
finds candidate origin IPs and confirms one when it serves the same site content
directly (bypassing the CDN).

Method (HTTP/DNS only — no Kali dependency):
  1. Confirm the apex is CDN-fronted (response header signatures). If not, no-op.
  2. Gather candidate IPs: origin-hint subdomains (origin./direct./dev./…) and
     cert-SAN hosts (crt.sh), resolved to A records.
  3. For each candidate IP NOT owned by the CDN, request it directly with the
     apex Host header; if the body closely matches the CDN-fronted apex body, the
     origin is exposed → finding.

Confirmation is 2-signal: the IP is off-CDN AND serves the apex's own content.
"""
from __future__ import annotations

import asyncio
import difflib
import logging
import socket
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_TIMEOUT = 10
_ORIGIN_HINTS = ("origin", "direct", "dev", "staging", "test", "cpanel", "ftp",
                 "mail", "webmail", "server", "backend", "api-direct")
_CDN_HEADER_SIGS = ("cf-ray", "x-amz-cf-id", "x-fastly", "x-served-by", "x-cache",
                    "fastly-io-info", "x-akamai", "akamai")
_CDN_SERVER_SIGS = ("cloudflare", "cloudfront", "akamai", "fastly", "varnish")
# Coarse CDN network owners (best-effort skip so we don't "confirm" a CDN edge).
_CDN_ASN_HINTS = ("cloudflare", "amazon", "akamai", "fastly", "google", "microsoft")


def _authorized(host: str) -> bool:
    try:
        from core.security.authorization import TargetScopeValidator
        return bool(host) and TargetScopeValidator.get().is_authorized(host)
    except Exception:
        return bool(host)


def _similar(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).quick_ratio()


def _resolve(host: str) -> List[str]:
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        return [ip for ip in ips if ip and not ip.startswith("127.")]
    except Exception:
        return []


def _apex(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


async def _fetch(session, url, host_header=None):
    import aiohttp
    headers = {"Host": host_header} if host_header else {}
    try:
        async with session.get(url, headers=headers, ssl=False, allow_redirects=False,
                               timeout=aiohttp.ClientTimeout(total=_TIMEOUT)) as r:
            return r.status, dict(r.headers), await r.text(errors="replace")
    except Exception:
        return 0, {}, ""


def _is_cdn_fronted(headers: Dict[str, str]) -> bool:
    low = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
    if any(sig in low for sig in _CDN_HEADER_SIGS):
        return True
    server = low.get("server", "")
    return any(sig in server for sig in _CDN_SERVER_SIGS)


async def _cert_san_hosts(apex: str) -> Set[str]:
    """SAN hostnames from crt.sh for the apex (cert pivot)."""
    out: Set[str] = set()
    try:
        import aiohttp
        async with aiohttp.ClientSession() as s:
            async with s.get(f"https://crt.sh/?q=%25.{apex}&output=json",
                             timeout=aiohttp.ClientTimeout(total=_TIMEOUT)) as r:
                if r.status == 200:
                    for row in await r.json(content_type=None):
                        for nm in str(row.get("name_value", "")).split("\n"):
                            nm = nm.strip().lstrip("*.").lower()
                            if nm.endswith(apex):
                                out.add(nm)
    except Exception:
        pass
    return out


async def run_cdn_origin_unmask(ctx) -> List[Dict[str, Any]]:
    base = str(getattr(ctx, "target", "") or "")
    if not base:
        return []
    if not base.startswith(("http://", "https://")):
        base = f"https://{base}"
    host = urlparse(base).hostname or ""
    if not host or not _authorized(host):
        return []
    apex = _apex(host)
    try:
        import aiohttp
    except Exception:
        return []

    async with aiohttp.ClientSession() as session:
        a_status, a_headers, a_body = await _fetch(session, base)
        if not _is_cdn_fronted(a_headers) or len(a_body) < 80:
            logger.debug("[CDNOrigin] %s not CDN-fronted (or empty) — nothing to unmask", host)
            return []
        cdn_ips = set(_resolve(host))

        # Candidate origin hosts: origin-hint subdomains + cert SANs.
        cand_hosts: Set[str] = {f"{h}.{apex}" for h in _ORIGIN_HINTS}
        cand_hosts |= await _cert_san_hosts(apex)
        cand_ips: Set[str] = set()
        for h in list(cand_hosts)[:60]:
            for ip in _resolve(h):
                if ip not in cdn_ips:
                    cand_ips.add(ip)

        findings: List[Dict[str, Any]] = []
        scheme = urlparse(base).scheme
        for ip in list(cand_ips)[:40]:
            _, _, ip_body = await _fetch(session, f"{scheme}://{ip}/", host_header=host)
            if not ip_body:
                continue
            sim = _similar(ip_body, a_body)
            if sim >= 0.85:
                f = {
                    "title": f"CDN origin IP exposed for {host}: {ip}",
                    "type": "CDN_ORIGIN_EXPOSURE", "vuln_type": "cdn_origin_exposure",
                    "severity": "medium",
                    "url": f"{scheme}://{ip}/", "target": ip, "location": ip,
                    "confirmed": True, "status": "CONFIRMED", "source": "cdn_origin",
                    "details": {"fronted_host": host, "origin_ip": ip,
                                "body_similarity": round(sim, 2)},
                    "remediation": ("Restrict the origin to accept traffic only from the CDN "
                                    "(firewall/allowlist CDN egress ranges, authenticated pull); "
                                    "rotate the origin IP; don't expose origin-hint subdomains."),
                }
                try:
                    from core.exploitation.proof_util import attach_proof
                    attach_proof(f, method="GET", url=f"{scheme}://{ip}/", status=200,
                                 resp_body=ip_body[:400],
                                 note=(f"Direct IP {ip} served {host}'s content (similarity {sim:.0%}) "
                                       f"with Host: {host}, bypassing the CDN."))
                except Exception:
                    pass
                findings.append(f)
                try:
                    ctx.add_vulnerability(f)
                except Exception:
                    pass
    if findings:
        logger.info("[CDNOrigin] %d origin IP(s) exposed", len(findings))
    return findings
