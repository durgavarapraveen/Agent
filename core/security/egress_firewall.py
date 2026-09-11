from __future__ import annotations

import contextlib
import contextvars
import ipaddress
import logging
import os
import socket
from typing import Iterable, List, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class EgressBlocked(Exception):
    pass

# When set, outbound requests on the current async task/thread are user-initiated
# RAG knowledge ingestion of an arbitrary PUBLIC URL — legitimately outside scan
# scope. We still block internal/private/reserved destinations so the bypass
# can't be turned into an SSRF primitive.
_RAG_INGEST_BYPASS: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "egress_rag_ingest_bypass", default=False)


@contextlib.contextmanager
def rag_ingest_egress():
    token = _RAG_INGEST_BYPASS.set(True)
    try:
        yield
    finally:
        _RAG_INGEST_BYPASS.reset(token)


def _is_internal_address(host: str) -> bool:
    h = (host or "").strip().lower().strip("[]")
    if not h:
        return True
    candidates: List[str] = []
    try:
        ipaddress.ip_address(h)
        candidates.append(h)
    except ValueError:
        try:
            infos = socket.getaddrinfo(h, None)
            candidates = [ai[4][0] for ai in infos]
        except Exception:
            # Cannot resolve — treat as internal (fail closed).
            return True
    for ip in candidates:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return True
    return False


# Loopback + link-local + RFC-1918 + carrier-grade NAT — never authoritative
# even if scope somehow ends up empty. We ALLOW loopback (tools talk to their
# own MCP servers) but NEVER let a request leave the box unless the target
# is in the scope validator.
_LOOPBACK_PREFIXES = ("127.", "0.", "::1", "localhost")


# Infrastructure allowlist — hosts the AGENT ITSELF needs to reach to
# function, independent of whichever target it's scanning:
#   - LLM providers (planner + reasoning calls)
#   - Threat-intel / OSINT feeds
#   - IP-lookup helpers (AnonGate)
#   - Package registries (rare, but nuclei-templates auto-update etc.)
# These are NOT scan targets; SSRF finding them wouldn't matter because
# they don't accept anonymous auth from the scan. Extend via env var
_INFRA_ALLOWLIST = {
    # LLM providers
    "api.deepseek.com", "api.groq.com", "api.openai.com",
    "api.anthropic.com", "api.together.xyz", "api.mistral.ai",
    "api.cohere.ai", "generativelanguage.googleapis.com",
    "openrouter.ai", "api.openrouter.ai",
    # Embedding providers (RAG)
    "api.voyageai.com",
    # OSINT / threat-intel feeds
    "api.shodan.io", "api.censys.io", "search.censys.io",
    "otx.alienvault.com", "urlscan.io", "www.virustotal.com",
    "crt.sh", "www.hackerone.com", "hackertarget.com",
    "api.hackertarget.com", "index.commoncrawl.org",
    "web.archive.org", "cve.mitre.org", "services.nvd.nist.gov",
    # IP lookup (AnonGate + WAN detection)
    "api.ipify.org", "ifconfig.me", "ipinfo.io", "icanhazip.com",
    # Nuclei / template updates
    "raw.githubusercontent.com", "github.com", "api.github.com",
    "codeload.github.com", "objects.githubusercontent.com",
    # Model hub — RAG local embedder (sentence-transformers) validates and
    # downloads all-MiniLM-L6-v2 from HuggingFace. CDN subdomains are covered
    # by the suffix match in _is_infra().
    "huggingface.co", "hf.co", "cdn-lfs.huggingface.co",
    # Public DNS (dig / OSINT resolvers)
    "dns.google", "cloudflare-dns.com", "1.1.1.1", "8.8.8.8",
    # DuckDuckGo search fallback in ingestion
    "duckduckgo.com", "lite.duckduckgo.com",
}


def _is_loopback(host: str) -> bool:
    h = (host or "").strip().lower().strip("[]")
    return any(h.startswith(p) for p in _LOOPBACK_PREFIXES) or h in ("localhost",)


# Trusted infra domain suffixes — cover rotating CDN subdomains we can't
# enumerate (e.g. HuggingFace model/LFS CDNs).
_INFRA_SUFFIXES = (".huggingface.co", ".hf.co", ".duckduckgo.com")


def _is_infra(host: str) -> bool:
    h = (host or "").strip().lower().strip("[]")
    if h in _INFRA_ALLOWLIST:
        return True
    if any(h == s.lstrip(".") or h.endswith(s) for s in _INFRA_SUFFIXES):
        return True
    # Env-var extension
    extra = (os.getenv("EGRESS_INFRA_ALLOWLIST") or "").strip()
    if extra:
        for entry in extra.split(","):
            entry = entry.strip().lower()
            if entry and (h == entry or h.endswith("." + entry)):
                return True
    return False


def _extract_host(url_or_host: str) -> Optional[str]:
    if not url_or_host:
        return None
    s = url_or_host.strip()
    if "://" in s:
        try:
            return (urlparse(s).hostname or "").strip("[]").lower()
        except Exception:
            return None
    # Bare host or host:port.
    return s.split(":", 1)[0].strip("[]").lower()


def assert_egress_allowed(url_or_host: str, purpose: str = "http") -> None:
    host = _extract_host(url_or_host)
    if not host:
        raise EgressBlocked(f"egress denied: no host in {url_or_host!r}")
    # User-initiated RAG ingestion may reach arbitrary PUBLIC URLs (outside scan
    # scope), but NEVER internal/private/reserved/loopback destinations — that
    # keeps the bypass from becoming an SSRF primitive against local services.
    if _RAG_INGEST_BYPASS.get():
        if _is_internal_address(host):
            logger.error(f"[EgressFirewall] BLOCKED rag-ingest egress to internal {host}")
            raise EgressBlocked(f"egress denied (rag ingest): {host} is an internal address")
        return
    if _is_loopback(host):
        return
    if _is_infra(host):
        return
    try:
        from core.security.authorization import TargetScopeValidator
        scope = TargetScopeValidator.get()
        if scope.is_authorized(host):
            return
    except Exception as e:
        logger.error(f"[EgressFirewall] scope check failed: {e} — DENYING {host}")
        raise EgressBlocked(f"egress denied ({purpose}): scope check failed for {host}")
    logger.error(f"[EgressFirewall] BLOCKED egress to {host} (purpose={purpose})")
    raise EgressBlocked(f"egress denied ({purpose}): {host} not in authorised scope")


def resolve_target_ips(hosts: Iterable[str]) -> Set[str]:
    ips: Set[str] = set()
    for h in hosts or []:
        h = (h or "").strip()
        if not h:
            continue
        try:
            for ai in socket.getaddrinfo(h, None):
                ip = ai[4][0]
                if ip and not ip.startswith("::"):
                    ips.add(ip)
        except Exception as e:
            logger.debug(f"[EgressFirewall] resolve {h} failed: {e}")
    return ips


def render_docker_network_policy(target_hosts: List[str],
                                 network_name: str = "antigravity_scan") -> str:
    ips = sorted(resolve_target_ips(target_hosts))
    allowed = " ".join(sorted(set(ips + ["8.8.8.8", "1.1.1.1"])))  # DNS
    hosts_joined = " ".join(target_hosts)
    lines = [
        f"# Phase 6.4 egress firewall for scan targets: {hosts_joined}",
        f"# Resolved authorised IPs: {allowed}",
        f"set -euo pipefail",
        f"docker network rm {network_name} 2>/dev/null || true",
        f"docker network create --driver bridge --subnet 172.31.0.0/24 \\",
        f"    -o com.docker.network.bridge.name=br-antigrav-scan {network_name}",
        f"# Default DROP for anything leaving br-antigrav-scan",
        f"iptables -I DOCKER-USER 1 -i br-antigrav-scan -j DROP",
        f"# Loopback + Docker-internal always OK",
        f"iptables -I DOCKER-USER 1 -i br-antigrav-scan -d 127.0.0.0/8 -j RETURN",
        f"iptables -I DOCKER-USER 1 -i br-antigrav-scan -d 172.16.0.0/12 -j RETURN",
    ]
    for ip in sorted(set(ips + ["8.8.8.8", "1.1.1.1"])):
        lines.append(f"iptables -I DOCKER-USER 1 -i br-antigrav-scan -d {ip} -j RETURN")
    lines.append(f"# Attach the Kali container to the restricted network:")
    lines.append(f"#   docker network connect {network_name} kali-pentesting")
    lines.append(f"#   docker network disconnect bridge kali-pentesting")
    return "\n".join(lines) + "\n"


def install_httpx_guard() -> None:
    try:
        import httpx
    except Exception:
        return
    if getattr(httpx, "_antigravity_egress_guard_installed", False):
        return
    original_async_send = httpx.AsyncClient.send
    original_sync_send = httpx.Client.send

    async def _guarded_async_send(self, request, *args, **kwargs):
        assert_egress_allowed(str(request.url), purpose="httpx.async")
        return await original_async_send(self, request, *args, **kwargs)

    def _guarded_sync_send(self, request, *args, **kwargs):
        assert_egress_allowed(str(request.url), purpose="httpx.sync")
        return original_sync_send(self, request, *args, **kwargs)

    httpx.AsyncClient.send = _guarded_async_send
    httpx.Client.send = _guarded_sync_send
    httpx._antigravity_egress_guard_installed = True
    logger.info("[EgressFirewall] httpx egress guard installed")
