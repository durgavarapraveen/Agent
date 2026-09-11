"""Phase 3.2 — Deterministic connection pinning and egress telemetry.

Guarantees the actual connection destination matches the authorized DNS resolution.
Records per-request egress evidence: DNS answer set, chosen IP, port, protocol,
policy decision, and redirect chain.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EgressRecord:
    timestamp: float
    target_host: str
    resolved_ips: tuple
    chosen_ip: str
    port: int
    protocol: str
    policy_decision: str
    redirect_chain: tuple = ()
    sni_host: str = ""
    request_id: str = ""
    correlation_id: str = ""


class ConnectionPinning:
    """Pin resolved IPs for a hostname so subsequent connections use the same address."""

    _instance: Optional["ConnectionPinning"] = None
    _lock = threading.RLock()

    @classmethod
    def get(cls) -> "ConnectionPinning":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self._pins: Dict[str, str] = {}
        self._dns_cache: Dict[str, List[str]] = {}
        self._lock_internal = threading.RLock()

    def resolve_and_pin(self, hostname: str, port: int = 443) -> Optional[str]:
        hostname = hostname.strip().lower()
        with self._lock_internal:
            if hostname in self._pins:
                return self._pins[hostname]
        try:
            results = socket.getaddrinfo(hostname, port)
            ips = list(dict.fromkeys(ai[4][0] for ai in results))
        except Exception as e:
            logger.error(f"[ConnectionPinning] DNS resolution failed for {hostname}: {e}")
            return None
        if not ips:
            return None
        chosen = ips[0]
        with self._lock_internal:
            self._dns_cache[hostname] = ips
            self._pins[hostname] = chosen
        return chosen

    def get_pinned_ip(self, hostname: str) -> Optional[str]:
        with self._lock_internal:
            return self._pins.get(hostname.strip().lower())

    def verify_connection(self, hostname: str, actual_ip: str) -> bool:
        pinned = self.get_pinned_ip(hostname)
        if pinned is None:
            return False
        return actual_ip == pinned

    def clear_pin(self, hostname: str) -> None:
        with self._lock_internal:
            self._pins.pop(hostname.strip().lower(), None)
            self._dns_cache.pop(hostname.strip().lower(), None)

    def detect_rebinding(self, hostname: str, port: int = 443) -> bool:
        hostname = hostname.strip().lower()
        with self._lock_internal:
            old_ips = set(self._dns_cache.get(hostname, []))
        if not old_ips:
            return False
        try:
            results = socket.getaddrinfo(hostname, port)
            new_ips = {ai[4][0] for ai in results}
        except Exception:
            return True
        new_only = new_ips - old_ips
        for ip in new_only:
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                    logger.critical(f"[ConnectionPinning] DNS rebinding detected: {hostname} "
                                    f"resolved to private {ip}")
                    return True
            except ValueError:
                continue
        return False


class EgressTelemetry:
    """Append-only egress log for audit and evidence reconstruction."""

    _instance: Optional["EgressTelemetry"] = None
    _lock = threading.RLock()

    @classmethod
    def get(cls) -> "EgressTelemetry":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self, max_records: int = 50_000):
        self._records: List[EgressRecord] = []
        self._max = max_records
        self._lock_internal = threading.RLock()

    def record(self, target_host: str, resolved_ips: list, chosen_ip: str,
               port: int, protocol: str, policy_decision: str,
               redirect_chain: list = None, sni_host: str = "",
               request_id: str = "") -> EgressRecord:
        try:
            from core.observability.correlation import get_correlation_id
            cid = get_correlation_id()
        except ImportError:
            cid = ""
        rec = EgressRecord(
            timestamp=time.time(),
            target_host=target_host,
            resolved_ips=tuple(resolved_ips),
            chosen_ip=chosen_ip,
            port=port,
            protocol=protocol,
            policy_decision=policy_decision,
            redirect_chain=tuple(redirect_chain or []),
            sni_host=sni_host or target_host,
            request_id=request_id,
            correlation_id=cid,
        )
        with self._lock_internal:
            if len(self._records) < self._max:
                self._records.append(rec)
        return rec

    def get_records(self, host: str = "", limit: int = 100) -> List[EgressRecord]:
        with self._lock_internal:
            if host:
                filtered = [r for r in self._records if r.target_host == host.lower()]
            else:
                filtered = list(self._records)
        return filtered[-limit:]

    def export(self) -> List[Dict[str, Any]]:
        with self._lock_internal:
            return [
                {
                    "timestamp": r.timestamp,
                    "target_host": r.target_host,
                    "resolved_ips": list(r.resolved_ips),
                    "chosen_ip": r.chosen_ip,
                    "port": r.port,
                    "protocol": r.protocol,
                    "policy_decision": r.policy_decision,
                    "redirect_chain": list(r.redirect_chain),
                    "sni_host": r.sni_host,
                    "request_id": r.request_id,
                }
                for r in self._records
            ]
