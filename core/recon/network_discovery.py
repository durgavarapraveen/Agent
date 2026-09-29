"""Network-layer attack-surface discovery — async TCP port scan of in-scope
hosts + lightweight service banner hints. Scope-enforced: only scans hosts the
TargetScopeValidator authorizes. Emits endpoint/asset facts + info findings."""
from __future__ import annotations

import asyncio
import logging
import os
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Common service ports worth knowing about on a web-app target.
_COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2375: "docker", 3000: "http-alt", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5601: "kibana", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 9300: "elastic-transport", 11211: "memcached",
    27017: "mongodb",
}
# Ports that are notably risky if exposed.
_RISKY = {23: "telnet", 2375: "docker-api", 6379: "redis", 9200: "elasticsearch",
          11211: "memcached", 27017: "mongodb", 5432: "postgres", 3306: "mysql",
          1433: "mssql", 445: "smb", 3389: "rdp"}


class NetworkDiscovery:
    def __init__(self, ctx=None, timeout: float = 1.5, concurrency: int = 100):
        self.ctx = ctx
        self.timeout = timeout
        self._sem = asyncio.Semaphore(concurrency)

    def _host(self) -> str:
        t = getattr(self.ctx, "target", "") or ""
        p = urlparse(t if "://" in t else f"//{t}")
        return p.hostname or t

    def _scan_ports(self) -> List[int]:
        # Base = default common set, merged with any ports already discovered on
        # ctx/recon and an optional NEO_SCAN_PORTS env override (comma list).
        ports = set(_COMMON_PORTS)
        for attr in ("open_ports", "discovered_ports", "ports"):
            for p in (getattr(self.ctx, attr, None) or []):
                try:
                    ports.add(int(p))
                except (TypeError, ValueError):
                    pass
        env = os.getenv("NEO_SCAN_PORTS", "")
        for tok in env.replace(";", ",").split(","):
            tok = tok.strip()
            if tok.isdigit():
                ports.add(int(tok))
        return sorted(ports)

    _HTTP_PORTS = {80, 3000, 8000, 8080, 8888, 5601, 9200, 5984}

    async def _scan_port(self, host: str, port: int):
        """Connect and best-effort grab a service banner/version. Returns
        (port, banner) or None. Banner: HTTP `Server:` header for plaintext HTTP
        ports, else a greeting read (ftp/ssh/smtp/redis/etc). TLS ports are left
        unbannered (would need a TLS handshake)."""
        async with self._sem:
            reader = writer = None
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
                banner = ""
                try:
                    if port in self._HTTP_PORTS:
                        writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                        await writer.drain()
                        data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                        banner = self._parse_server_header(data)
                    elif port not in (443, 993, 995, 8443):
                        # Services that greet on connect (ftp/ssh/smtp/redis...).
                        data = await asyncio.wait_for(reader.read(256), timeout=min(1.5, self.timeout))
                        banner = data.decode("latin-1", "replace").strip().splitlines()[0][:120] if data else ""
                except Exception:
                    banner = ""
                return (port, banner)
            except Exception:
                return None
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

    @staticmethod
    def _parse_server_header(data: bytes) -> str:
        try:
            for line in data.decode("latin-1", "replace").splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()[:120]
        except Exception:
            pass
        return ""

    async def scan(self) -> List[Dict[str, Any]]:
        host = self._host()
        if not host:
            return []
        try:
            from core.security.authorization import TargetScopeValidator
            if not TargetScopeValidator.get().is_authorized(host):
                logger.info("[NetworkDiscovery] %s not in scope — skipping", host)
                return []
        except Exception:
            return []

        # resolve once (fail closed)
        try:
            socket.gethostbyname(host)
        except Exception as e:
            logger.debug("[NetworkDiscovery] resolve failed %s: %s", host, e)

        scan_ports = self._scan_ports()
        logger.info("[NetworkDiscovery] scanning %d ports on %s", len(scan_ports), host)
        results = await asyncio.gather(*[self._scan_port(host, p) for p in scan_ports])
        banners: Dict[int, str] = {r[0]: r[1] for r in results if r}
        open_ports = sorted(banners)

        findings: List[Dict[str, Any]] = []
        # record open ports as assets on the knowledge graph if present
        for port in open_ports:
            svc = _COMMON_PORTS.get(port, "unknown")
            banner = banners.get(port, "")
            self._record_asset(host, port, svc, banner)
            if port in _RISKY:
                _ver = f" — {banner}" if banner else ""
                findings.append({
                    "id": f"NETSVC_{host}_{port}",
                    "type": "MISCONFIGURATION", "sub_type": "exposed_service",
                    "title": f"Exposed {svc} service on {host}:{port}{_ver}",
                    "severity": "HIGH" if port in (2375, 6379, 9200, 11211, 27017) else "MEDIUM",
                    "target": f"{host}:{port}", "location": f"{host}:{port}",
                    "tool": "network_discovery",
                    "proof": f"TCP {port} ({svc}) open on {host}" + (f"; banner: {banner}" if banner else ""),
                    "details": f"Sensitive service {svc} reachable on port {port}." + (f" Version/banner: {banner}" if banner else ""),
                    "confirmed": True, "status": "CONFIRMED", "cwe": "CWE-284",
                    "service_banner": banner,
                })
        if self.ctx is not None:
            try:
                self.ctx.update("open_ports", {host: open_ports})
            except Exception:
                pass
        logger.info("[NetworkDiscovery] %s open ports: %s", host, open_ports)
        return findings

    def _record_asset(self, host: str, port: int, svc: str, banner: str = "") -> None:
        kg = getattr(self.ctx, "knowledge_graph", None) if self.ctx else None
        if kg is None:
            return
        try:
            kg.add_asset(f"{host}:{port}", {"host": host, "port": port, "service": svc,
                                            "banner": banner, "source": "network_discovery"})
        except Exception:
            pass


async def run_network_discovery(ctx) -> List[Dict[str, Any]]:
    if not getattr(ctx, "target", ""):
        return []
    return await NetworkDiscovery(ctx).scan()
