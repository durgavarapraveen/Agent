from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_LOCALHOST_NAMES = frozenset({
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "lvh.me", "0.0.0.0", "[::]", "::1",
})

_MAX_REDIRECTS = 10
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_REQUEST_BUDGET = 10_000

@dataclass(frozen=True)
class EgressEvidence:
    url: str
    dns_answers: List[str]
    chosen_ip: str
    port: int
    protocol: str
    policy_decision: str
    redirect_chain: List[str]
    timestamp: float = field(default_factory=time.time)
    
    def log(self):
        logger.info(f"[EgressTelemetry] {self.policy_decision} | URL={self.url} IP={self.chosen_ip} PORT={self.port} PROTO={self.protocol} DNS={self.dns_answers} CHAIN={self.redirect_chain}")

# ── Data models ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ResolvedTarget:
    hostname: str
    canonical: str
    ips: Tuple[str, ...]
    resolved_at: float = field(default_factory=time.monotonic)

    @property
    def is_safe(self) -> bool:
        return len(self.ips) > 0 and all(
            not _is_dangerous_ip(ip) for ip in self.ips
        )


@dataclass(frozen=True)
class NetworkDecision:
    allowed: bool
    url: str
    reason: str
    resolved: Optional[ResolvedTarget] = None
    reason_code: Optional[str] = None


# ── IP classification ────────────────────────────────────────────────────

def _is_dangerous_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # fail closed

    if (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
        return True

    # Carrier-grade NAT (100.64.0.0/10) — is_private covers this in 3.11+
    # but not all Python versions, so check explicitly
    if isinstance(addr, ipaddress.IPv4Address):
        if addr in ipaddress.IPv4Network("100.64.0.0/10"):
            return True

    # IPv4-mapped IPv6 (::ffff:x.x.x.x) — check the embedded v4
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return _is_dangerous_ip(str(addr.ipv4_mapped))

    # 6to4 addresses (2002::/16) can embed arbitrary IPv4
    if isinstance(addr, ipaddress.IPv6Address):
        if addr in ipaddress.IPv6Network("2002::/16"):
            try:
                packed = addr.packed
                embedded_v4 = ipaddress.IPv4Address(packed[2:6])
                return _is_dangerous_ip(str(embedded_v4))
            except Exception:
                return True

    return False


def _is_localhost_name(hostname: str) -> bool:
    h = hostname.lower().strip().strip("[]")
    if h in _LOCALHOST_NAMES:
        return True
    if h.startswith("127.") or h == "::1":
        return True
    # Decimal/octal/hex IP encoding tricks: 2130706433 = 127.0.0.1
    if re.match(r"^0[xX][0-9a-fA-F]+$", h) or re.match(r"^\d{8,}$", h):
        try:
            n = int(h, 0)
            if 0 <= n <= 0xFFFFFFFF:
                addr = ipaddress.IPv4Address(n)
                return _is_dangerous_ip(str(addr))
        except (ValueError, OverflowError):
            pass
    return False


# ── Hostname canonicalization ────────────────────────────────────────────

def canonicalize_hostname(hostname: str) -> str:
    h = (hostname or "").strip().lower().strip("[]")
    if not h:
        return ""

    # Handle punycode/IDN
    try:
        h = h.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass

    # Strip trailing dot (FQDN)
    h = h.rstrip(".")
    return h


def parse_url_target(url: str) -> Tuple[str, str, int, str]:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "https").lower()
    host = canonicalize_hostname(parsed.hostname or "")
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    return scheme, host, port, path


# ── DNS resolver with rebinding protection ───────────────────────────────

class DNSResolver:

    def __init__(self, cache_ttl: float = 60.0):
        self._cache: Dict[str, ResolvedTarget] = {}
        self._lock = threading.Lock()
        self._cache_ttl = cache_ttl

    def resolve(self, hostname: str) -> ResolvedTarget:
        canonical = canonicalize_hostname(hostname)
        if not canonical:
            return ResolvedTarget(hostname=hostname, canonical="", ips=())

        with self._lock:
            cached = self._cache.get(canonical)
            if cached and (time.monotonic() - cached.resolved_at) < self._cache_ttl:
                return cached

        # Direct IP literal — no DNS needed
        try:
            ipaddress.ip_address(canonical)
            result = ResolvedTarget(
                hostname=hostname, canonical=canonical, ips=(canonical,),
            )
            with self._lock:
                self._cache[canonical] = result
            return result
        except ValueError:
            pass

        # DNS resolution
        ips: List[str] = []
        try:
            infos = socket.getaddrinfo(canonical, None, socket.AF_UNSPEC,
                                       socket.SOCK_STREAM)
            seen: Set[str] = set()
            for family, _, _, _, sockaddr in infos:
                ip = sockaddr[0]
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
        except socket.gaierror:
            pass
        except Exception as e:
            logger.debug("[NetworkBroker] DNS resolution failed for %s: %s",
                         canonical, e)

        result = ResolvedTarget(
            hostname=hostname, canonical=canonical, ips=tuple(ips),
        )
        with self._lock:
            self._cache[canonical] = result
        return result

    def clear(self):
        with self._lock:
            self._cache.clear()

    async def resolve_async(self, hostname: str) -> ResolvedTarget:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.resolve, hostname)


# ── Request budget ───────────────────────────────────────────────────────

class RequestBudget:

    def __init__(self, max_requests: int = _DEFAULT_REQUEST_BUDGET):
        self._max = max_requests
        self._count = 0
        self._lock = threading.Lock()

    def consume(self) -> bool:
        with self._lock:
            if self._count >= self._max:
                return False
            self._count += 1
            return True

    @property
    def remaining(self) -> int:
        with self._lock:
            return max(0, self._max - self._count)

    @property
    def used(self) -> int:
        with self._lock:
            return self._count

    def reset(self):
        with self._lock:
            self._count = 0


# ── Network Broker ───────────────────────────────────────────────────────

class NetworkBroker:

    _instance: Optional["NetworkBroker"] = None
    _lock = threading.RLock()

    @classmethod
    def get(cls) -> "NetworkBroker":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset_for_tests(cls) -> None:
        with cls._lock:
            cls._instance = None

    def __init__(self, budget: Optional[RequestBudget] = None,
                 resolver: Optional[DNSResolver] = None,
                 max_redirects: int = _MAX_REDIRECTS,
                 timeout: float = _DEFAULT_TIMEOUT):
        self._resolver = resolver or DNSResolver()
        self._budget = budget or RequestBudget()
        self._max_redirects = max_redirects
        self._timeout = timeout

    @property
    def resolver(self) -> DNSResolver:
        return self._resolver

    @property
    def budget(self) -> RequestBudget:
        return self._budget

    # ── Core authorization ──────────────────────────────────────────────

    def check_url(self, url: str) -> NetworkDecision:
        if not url or not url.strip():
            return NetworkDecision(
                allowed=False, url=url or "",
                reason="empty URL", reason_code="SCHEMA_INVALID",
            )

        scheme, host, port, path = parse_url_target(url)
        if not host:
            return NetworkDecision(
                allowed=False, url=url,
                reason="no hostname in URL", reason_code="SCHEMA_INVALID",
            )

        # Localhost alias check
        if _is_localhost_name(host):
            return NetworkDecision(
                allowed=False, url=url,
                reason=f"localhost alias blocked: {host}",
                reason_code="PRIVATE_IP_BLOCKED",
            )

        # DNS resolution with pinning
        resolved = self._resolver.resolve(host)
        if not resolved.ips:
            return NetworkDecision(
                allowed=False, url=url, resolved=resolved,
                reason=f"DNS resolution failed for {host}",
                reason_code="DNS_REBIND_BLOCKED",
            )

        # IP safety check — ALL resolved IPs must be safe
        for ip in resolved.ips:
            if _is_dangerous_ip(ip):
                return NetworkDecision(
                    allowed=False, url=url, resolved=resolved,
                    reason=f"resolved IP {ip} is private/reserved",
                    reason_code="PRIVATE_IP_BLOCKED",
                )

        # Egress firewall scope check
        try:
            from core.security.egress_firewall import assert_egress_allowed
            assert_egress_allowed(url, purpose="network_broker")
        except Exception as e:
            ename = type(e).__name__
            if ename == "EgressBlocked" or "egress" in str(e).lower():
                return NetworkDecision(
                    allowed=False, url=url, resolved=resolved,
                    reason=str(e), reason_code="EGRESS_BLOCKED",
                )
            return NetworkDecision(
                allowed=False, url=url, resolved=resolved,
                reason=f"egress check error: {e}",
                reason_code="POLICY_ERROR",
            )

        # Budget check
        if not self._budget.consume():
            return NetworkDecision(
                allowed=False, url=url, resolved=resolved,
                reason="request budget exhausted",
                reason_code="BUDGET_EXCEEDED",
            )

        return NetworkDecision(
            allowed=True, url=url, resolved=resolved,
            reason="authorized",
        )

    async def check_url_async(self, url: str) -> NetworkDecision:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.check_url, url)

    # ── Redirect validation ─────────────────────────────────────────────

    def validate_redirect(self, original_url: str,
                          redirect_url: str,
                          hop: int = 0) -> NetworkDecision:
        if hop >= self._max_redirects:
            return NetworkDecision(
                allowed=False, url=redirect_url,
                reason=f"too many redirects ({hop}/{self._max_redirects})",
                reason_code="REDIRECT_OUT_OF_SCOPE",
            )

        decision = self.check_url(redirect_url)
        if not decision.allowed:
            return NetworkDecision(
                allowed=False, url=redirect_url, resolved=decision.resolved,
                reason=f"redirect hop {hop}: {decision.reason}",
                reason_code=decision.reason_code or "REDIRECT_OUT_OF_SCOPE",
            )

        logger.debug("[NetworkBroker] redirect hop %d: %s -> %s (allowed)",
                     hop, original_url, redirect_url)
        return decision

    # ── DNS rebinding guard ─────────────────────────────────────────────

    def verify_no_rebind(self, hostname: str,
                         previous: ResolvedTarget) -> NetworkDecision:
        fresh = self._resolver.resolve(hostname)

        if set(fresh.ips) != set(previous.ips):
            logger.warning(
                "[NetworkBroker] DNS REBIND DETECTED: %s changed from %s to %s",
                hostname, previous.ips, fresh.ips,
            )
            # Re-check new IPs for safety
            for ip in fresh.ips:
                if _is_dangerous_ip(ip):
                    return NetworkDecision(
                        allowed=False, url=hostname, resolved=fresh,
                        reason=f"DNS rebinding: {hostname} now resolves to dangerous IP {ip}",
                        reason_code="DNS_REBIND_BLOCKED",
                    )

        return NetworkDecision(
            allowed=True, url=hostname, resolved=fresh,
            reason="no rebinding detected",
        )

    # ── Governed HTTP client factory ────────────────────────────────────

    def create_client(self, redirect_chain: Optional[List[str]] = None, **kwargs) -> Any:
        try:
            import httpx
            import httpcore
        except ImportError:
            raise RuntimeError("httpx and httpcore required for NetworkBroker.create_client")

        broker = self
        max_redir = self._max_redirects
        timeout_val = kwargs.pop("timeout", self._timeout)
        current_chain = redirect_chain or []

        class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
            def __init__(self, original: httpcore.AsyncNetworkBackend):
                self._original = original

            async def connect_tcp(self, host: str, port: int, timeout: Optional[float] = None, local_address: Optional[str] = None, **kwargs) -> httpcore.AsyncNetworkStream:
                canonical = canonicalize_hostname(host)
                with broker._resolver._lock:
                    cached = broker._resolver._cache.get(canonical)
                
                if cached and cached.ips:
                    ip = cached.ips[0]
                    logger.debug(f"[NetworkBroker] Pinned TCP connection: {host} -> {ip}")
                    host_to_connect = ip
                else:
                    host_to_connect = host
                    logger.warning(f"[NetworkBroker] Pinned TCP connection failed to find cached IP for {host}, falling back to default resolution")
                    
                return await self._original.connect_tcp(host_to_connect, port, timeout=timeout, local_address=local_address, **kwargs)
                
            async def connect_unix_socket(self, path: str, timeout: Optional[float] = None, **kwargs) -> httpcore.AsyncNetworkStream:
                return await self._original.connect_unix_socket(path, timeout=timeout, **kwargs)
                
            async def sleep(self, seconds: float) -> None:
                return await self._original.sleep(seconds)

        class GovernedTransport(httpx.AsyncBaseTransport):
            def __init__(self, inner: httpx.AsyncBaseTransport):
                self._inner = inner

            async def handle_async_request(self, request):
                url_str = str(request.url)
                decision = broker.check_url(url_str)
                
                scheme, host, port, path = parse_url_target(url_str)
                dns_answers = list(decision.resolved.ips) if decision.resolved else []
                chosen_ip = dns_answers[0] if dns_answers else ""
                
                evidence = EgressEvidence(
                    url=url_str,
                    dns_answers=dns_answers,
                    chosen_ip=chosen_ip,
                    port=port,
                    protocol=scheme,
                    policy_decision=decision.reason_code or ("ALLOWED" if decision.allowed else "DENIED"),
                    redirect_chain=list(current_chain)
                )
                evidence.log()
                
                if not decision.allowed:
                    from core.security.egress_firewall import EgressBlocked
                    raise EgressBlocked(
                        f"NetworkBroker blocked: {decision.reason}"
                    )
                return await self._inner.handle_async_request(request)

        base_transport = httpx.AsyncHTTPTransport(retries=1)
        # Monkeypatch the pool's network backend with our pinning wrapper
        if hasattr(base_transport, "_pool") and hasattr(base_transport._pool, "_network_backend"):
            base_transport._pool._network_backend = PinnedNetworkBackend(base_transport._pool._network_backend)
            
        transport = GovernedTransport(base_transport)

        return httpx.AsyncClient(
            transport=transport,
            verify=False,
            follow_redirects=False,  # we validate each redirect
            timeout=httpx.Timeout(timeout_val),
            **kwargs,
        )

    async def request(self, method: str, url: str,
                      follow_redirects: bool = True,
                      **kwargs) -> Any:

        decision = self.check_url(url)
        if not decision.allowed:
            from core.security.egress_firewall import EgressBlocked
            raise EgressBlocked(f"NetworkBroker: {decision.reason}")

        redirect_chain: List[str] = []
        
        try:
            current_url = url
            for hop in range(self._max_redirects + 1):
                # Create client fresh for each hop so telemetry captures the updated chain
                client = self.create_client(redirect_chain=list(redirect_chain))
                try:
                    resp = await client.request(method, current_url, **kwargs)
                finally:
                    await client.aclose()

                if follow_redirects and resp.is_redirect and resp.has_redirect_location:
                    next_url = str(resp.next_request.url)
                    redirect_chain.append(current_url)
                    redir_decision = self.validate_redirect(
                        current_url, next_url, hop,
                    )
                    if not redir_decision.allowed:
                        from core.security.egress_firewall import EgressBlocked
                        raise EgressBlocked(
                            f"NetworkBroker redirect blocked: {redir_decision.reason}"
                        )
                    current_url = next_url
                    kwargs.pop("content", None)
                    kwargs.pop("data", None)
                    kwargs.pop("json", None)
                    if resp.status_code in (301, 302, 303):
                        method = "GET"
                    continue

                return resp

            from core.security.egress_firewall import EgressBlocked
            raise EgressBlocked(f"NetworkBroker: max redirects exceeded for {url}")
        except Exception:
            raise


# ── Module-level accessor ────────────────────────────────────────────────

def get_network_broker() -> NetworkBroker:
    return NetworkBroker.get()
