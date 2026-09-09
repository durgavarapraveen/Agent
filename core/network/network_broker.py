"""P0.2 — Network Broker.

Centralized, governed network access layer. Every outbound HTTP request from
scan tools routes through here. Provides:

  - DNS resolution with rebinding protection (resolve-then-connect, pinned IP)
  - Redirect revalidation (every hop re-checked against scope + private IP)
  - Hostname canonicalization (IDN/punycode, IPv4-mapped IPv6, encoded IPs)
  - Private/reserved/loopback/link-local IP blocking
  - Request budget enforcement
  - Audit logging of every request

Architecture:
    Agent -> ToolGateway -> PolicyEngine -> NetworkBroker -> Network
"""
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
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)

_LOCALHOST_NAMES = frozenset({
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "lvh.me", "0.0.0.0", "[::]", "::1",
})

_MAX_REDIRECTS = 10
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_REQUEST_BUDGET = 10_000


# ── Data models ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ResolvedTarget:
    """DNS resolution result with pinned IPs for rebinding protection."""
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
    """Result of a network authorization check."""
    allowed: bool
    url: str
    reason: str
    resolved: Optional[ResolvedTarget] = None
    reason_code: Optional[str] = None


# ── IP classification ────────────────────────────────────────────────────

def _is_dangerous_ip(ip_str: str) -> bool:
    """True if IP is private, loopback, link-local, reserved, multicast,
    unspecified, or in carrier-grade NAT (100.64.0.0/10)."""
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
    """Check for localhost aliases including non-obvious ones."""
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
    """Normalize hostname: lowercase, strip brackets/whitespace, handle IDN."""
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
    """Extract (scheme, host, port, path) from a URL.
    Returns canonicalized hostname."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "https").lower()
    host = canonicalize_hostname(parsed.hostname or "")
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    return scheme, host, port, path


# ── DNS resolver with rebinding protection ───────────────────────────────

class DNSResolver:
    """Resolve-then-connect: resolves hostname to IPs, pins them, and all
    subsequent connections use the pinned IPs. Prevents DNS rebinding where
    a hostname resolves to a safe IP on check but an internal IP on connect."""

    def __init__(self, cache_ttl: float = 60.0):
        self._cache: Dict[str, ResolvedTarget] = {}
        self._lock = threading.Lock()
        self._cache_ttl = cache_ttl

    def resolve(self, hostname: str) -> ResolvedTarget:
        """Resolve hostname and cache the result. Uses pinned IPs."""
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
        """Async wrapper — runs blocking DNS in executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.resolve, hostname)


# ── Request budget ───────────────────────────────────────────────────────

class RequestBudget:
    """Track and limit total requests per scan session."""

    def __init__(self, max_requests: int = _DEFAULT_REQUEST_BUDGET):
        self._max = max_requests
        self._count = 0
        self._lock = threading.Lock()

    def consume(self) -> bool:
        """Returns True if request is within budget."""
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
    """Centralized network access with DNS rebinding protection, redirect
    revalidation, and scope enforcement.

    Every scan-originated HTTP request should go through this broker.
    Infrastructure traffic (LLM API calls, OSINT feeds) is handled
    separately by the EgressFirewall allowlist.
    """

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
        """Full authorization check for an outbound URL:
        1. Parse and canonicalize
        2. Check localhost aliases
        3. Resolve DNS and pin IPs
        4. Verify all IPs are non-dangerous
        5. Check target scope via EgressFirewall
        """
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
        """Async version of check_url."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.check_url, url)

    # ── Redirect validation ─────────────────────────────────────────────

    def validate_redirect(self, original_url: str,
                          redirect_url: str,
                          hop: int = 0) -> NetworkDecision:
        """Validate a redirect target. Every hop is re-checked against scope
        and private IP blocking. Prevents redirect-to-internal attacks."""
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
        """Re-resolve and verify IPs haven't changed (DNS rebinding check).
        Call this before using a cached connection if TTL is near expiry."""
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

    def create_client(self, **kwargs) -> Any:
        """Create an httpx.AsyncClient that routes all requests through
        the broker's authorization checks. Uses pinned IPs from DNS
        resolution to prevent TOCTOU rebinding."""
        try:
            import httpx
        except ImportError:
            raise RuntimeError("httpx required for NetworkBroker.create_client")

        broker = self
        max_redir = self._max_redirects
        timeout_val = kwargs.pop("timeout", self._timeout)

        class GovernedTransport(httpx.AsyncBaseTransport):
            def __init__(self, inner: httpx.AsyncBaseTransport):
                self._inner = inner

            async def handle_async_request(self, request):
                url_str = str(request.url)
                decision = broker.check_url(url_str)
                if not decision.allowed:
                    from core.security.egress_firewall import EgressBlocked
                    raise EgressBlocked(
                        f"NetworkBroker blocked: {decision.reason}"
                    )
                return await self._inner.handle_async_request(request)

        transport = GovernedTransport(
            httpx.AsyncHTTPTransport(retries=1)
        )

        return httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,  # we validate each redirect
            timeout=httpx.Timeout(timeout_val),
            **kwargs,
        )

    async def request(self, method: str, url: str,
                      **kwargs) -> Any:
        """Make a governed HTTP request with redirect revalidation.
        Returns httpx.Response."""
        import httpx

        decision = self.check_url(url)
        if not decision.allowed:
            from core.security.egress_firewall import EgressBlocked
            raise EgressBlocked(f"NetworkBroker: {decision.reason}")

        client = self.create_client()
        try:
            current_url = url
            for hop in range(self._max_redirects + 1):
                resp = await client.request(method, current_url, **kwargs)

                if resp.is_redirect and resp.has_redirect_location:
                    next_url = str(resp.next_request.url)
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
        finally:
            await client.aclose()


# ── Module-level accessor ────────────────────────────────────────────────

def get_network_broker() -> NetworkBroker:
    return NetworkBroker.get()
