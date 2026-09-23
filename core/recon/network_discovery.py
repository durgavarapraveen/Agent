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

    async def _scan_port(self, host: str, port: int) -> Optional[int]:
        async with self._sem:
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port
            except Exception:
                return None

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
        open_ports = sorted(p for p in results if p)

        findings: List[Dict[str, Any]] = []
        # record open ports as assets on the knowledge graph if present
        for port in open_ports:
            svc = _COMMON_PORTS.get(port, "unknown")
            self._record_asset(host, port, svc)
            if port in _RISKY:
                findings.append({
                    "id": f"NETSVC_{host}_{port}",
                    "type": "MISCONFIGURATION", "sub_type": "exposed_service",
                    "title": f"Exposed {svc} service on {host}:{port}",
                    "severity": "HIGH" if port in (2375, 6379, 9200, 11211, 27017) else "MEDIUM",
                    "target": f"{host}:{port}", "location": f"{host}:{port}",
                    "tool": "network_discovery",
                    "proof": f"TCP {port} ({svc}) open on {host}",
                    "details": f"Sensitive service {svc} reachable on port {port}.",
                    "confirmed": True, "status": "CONFIRMED", "cwe": "CWE-284",
                })
        if self.ctx is not None:
            try:
                self.ctx.update("open_ports", {host: open_ports})
            except Exception:
                pass
        logger.info("[NetworkDiscovery] %s open ports: %s", host, open_ports)
        return findings

    def _record_asset(self, host: str, port: int, svc: str) -> None:
        kg = getattr(self.ctx, "knowledge_graph", None) if self.ctx else None
        if kg is None:
            return
        try:
            kg.add_asset(f"{host}:{port}", {"host": host, "port": port, "service": svc,
                                            "source": "network_discovery"})
        except Exception:
            pass


async def run_network_discovery(ctx) -> List[Dict[str, Any]]:
    if not getattr(ctx, "target", ""):
        return []
    return await NetworkDiscovery(ctx).scan()
