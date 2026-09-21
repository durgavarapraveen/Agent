from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _private_targets_allowed() -> bool:
    """Opt-in for scanning private/loopback targets (labs: Juice Shop, DVWA,
    internal apps). Default OFF (anti-SSRF hard wall stays). When ON, the
    private-IP/loopback block is lifted ONLY for hosts that are ALSO in the
    authorized scope — scope enforcement is never bypassed."""
    return os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() in ("true", "1", "yes", "on")


def _host_in_scope(host: str) -> bool:
    try:
        from core.security.authorization import TargetScopeValidator
        return bool(TargetScopeValidator.get().is_authorized(host))
    except Exception:
        return False

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
        # Negative cache for repeatedly-failing STATIC assets (.js/.css/.map/…).
        # A dead-LLM planner loop re-queued the same JS fetch 854× (all 503),
        # hammering the target. Once a static GET returns 4xx/5xx, short-circuit
        # identical GETs for a TTL instead of re-fetching. key -> (status, expiry).
        self._neg_cache: dict = {}
        try:
            self._neg_ttl = float(os.getenv("STATIC_NEG_CACHE_TTL", "600"))
        except (TypeError, ValueError):
            self._neg_ttl = 600.0

    _STATIC_EXT = (".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif",
                   ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webp")

    def _static_neg_key(self, method: str, url: str):
        """Return a cache key for a cacheable static GET, else None."""
        if (method or "").upper() != "GET":
            return None
        path = url.split("?", 1)[0].split("#", 1)[0].lower()
        if path.endswith(self._STATIC_EXT):
            return url.split("#", 1)[0]
        return None

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

        # Localhost alias check — hard block unless private targets are
        # explicitly enabled AND this host is in the authorized scope.
        if _is_localhost_name(host):
            if not (_private_targets_allowed() and _host_in_scope(host)):
                return NetworkDecision(
                    allowed=False, url=url,
                    reason=f"localhost alias blocked: {host}",
                    reason_code="PRIVATE_IP_BLOCKED",
                )
            logger.warning("[NetworkBroker] private/loopback target %s allowed "
                           "(ALLOW_PRIVATE_TARGETS + in-scope)", host)

        # DNS resolution with pinning
        resolved = self._resolver.resolve(host)
        if not resolved.ips:
            return NetworkDecision(
                allowed=False, url=url, resolved=resolved,
                reason=f"DNS resolution failed for {host}",
                reason_code="DNS_REBIND_BLOCKED",
            )

        # IP safety check — ALL resolved IPs must be safe, unless private
        # targets are explicitly enabled AND this host is in authorized scope.
        _allow_private = _private_targets_allowed() and _host_in_scope(host)
        for ip in resolved.ips:
            if _is_dangerous_ip(ip) and not _allow_private:
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
                    # Cache miss: do NOT fall back to unpinned transport resolution
                    # (that would let the OS resolve to a rebind/internal IP with no
                    # check). Resolve through the guarded resolver and fail CLOSED.
                    try:
                        fresh = broker._resolver.resolve(canonical)
                    except Exception as e:
                        raise RuntimeError(
                            f"[NetworkBroker] blocked {host}: guarded resolution failed ({e})") from e
                    if not (fresh and fresh.ips):
                        raise RuntimeError(f"[NetworkBroker] blocked {host}: no resolvable IP")
                    ip = fresh.ips[0]
                    if _is_dangerous_ip(ip) and not (_private_targets_allowed() and _host_in_scope(host)):
                        raise RuntimeError(
                            f"[NetworkBroker] blocked {host}: resolves to dangerous IP {ip}")
                    host_to_connect = ip
                    logger.debug(f"[NetworkBroker] Pinned via fresh resolve: {host} -> {ip}")

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

    async def send_request(self, method: str, url: str, **kwargs) -> Any:
        """Back-compat alias: several probes call ``broker.send_request(...)``."""
        return await self.request(method, url, **kwargs)

    async def request(self, method: str, url: str,
                      follow_redirects: bool = True,
                      **kwargs) -> Any:

        # Defense-in-depth: canonicalise the target before scope check + send so a
        # stacked-scheme artifact ("…/#/get:get://https://host/…", "get:https://…")
        # from any probe is repaired here even if it slipped past discovery. Only
        # replace when the cleaner yields a valid URL; otherwise keep the original
        # and let the scope/egress layer reject it.
        try:
            from core.common.url_hygiene import canonical_http_url
            _cu = canonical_http_url(url)
            if _cu:
                url = _cu
        except Exception:
            pass

        # `verify` is a client-construction arg, not a per-request one — httpx's
        # AsyncClient.request() rejects it with TypeError. The scoped client below
        # already sets verify=False, so silently drop any caller-supplied verify
        # (probes commonly pass verify=False) instead of failing the request.
        kwargs.pop("verify", None)

        # Compat: many probes pass `body=` (requests-style). httpx's request()
        # has no `body` kwarg and raises TypeError — which silently killed every
        # POST-based probe (race/chatbot/state-changing). Translate it to the
        # right httpx kwarg by shape: dict → json, str/bytes → content. If the
        # caller already set json/content/data, the explicit one wins.
        if "body" in kwargs:
            _b = kwargs.pop("body")
            if _b is not None and not any(k in kwargs for k in ("json", "content", "data")):
                if isinstance(_b, (dict, list)):
                    kwargs["json"] = _b
                elif isinstance(_b, (bytes, bytearray, str)):
                    kwargs["content"] = _b
                else:
                    kwargs["content"] = str(_b)

        # §26/§39: external watchdog — fail-closed on budget breach / kill switch,
        # independent of the agent/LLM. Metered after the response returns.
        try:
            from core.security.watchdog import get_watchdog
            _wd = get_watchdog()
            _wd.check()
        except Exception as _e:
            if _e.__class__.__name__ == "WatchdogTripped":
                raise
            _wd = None

        decision = self.check_url(url)
        if not decision.allowed:
            from core.security.egress_firewall import EgressBlocked
            raise EgressBlocked(f"NetworkBroker: {decision.reason}")

        # Negative-cache short-circuit: an identical static-asset GET that already
        # failed (4xx/5xx) this scan returns the cached failure without re-hitting
        # the target (caps runaway re-fetch loops like the 854× rolldown-runtime.js).
        _nk = self._static_neg_key(method, url)
        if _nk is not None:
            _hit = self._neg_cache.get(_nk)
            if _hit is not None:
                _status, _exp = _hit
                if time.monotonic() < _exp:
                    import httpx as _httpx
                    logger.debug("[NegCache] short-circuit %s (cached status %s)", _nk, _status)
                    return _httpx.Response(status_code=_status,
                                           request=_httpx.Request(method, url))
                self._neg_cache.pop(_nk, None)

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

                if _wd is not None:
                    try:
                        _wd.record_request(len(getattr(resp, "content", b"") or b""))
                    except Exception:
                        pass

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

                # Record a failing static-asset fetch so identical retries this
                # scan are short-circuited instead of re-hammering the target.
                if _nk is not None and resp.status_code in (404, 500, 502, 503, 504):
                    self._neg_cache[_nk] = (resp.status_code,
                                            time.monotonic() + self._neg_ttl)
                return resp

            from core.security.egress_firewall import EgressBlocked
            raise EgressBlocked(f"NetworkBroker: max redirects exceeded for {url}")
        except Exception:
            raise


# ── Module-level accessor ────────────────────────────────────────────────

def get_network_broker() -> NetworkBroker:
    return NetworkBroker.get()
