
import os
import re
import time
import logging
from typing import List, Optional
from urllib.parse import urlparse
from core.common.exceptions import AuthorizationError

logger = logging.getLogger(__name__)


PASSIVE_OSINT_DOMAINS = frozenset({
    "crt.sh", "api.github.com", "github.com",
    "dns.google", "otx.alienvault.com", "shodan.io", "api.shodan.io",
    "urlscan.io", "web.archive.org", "archive.org",
    "rapiddns.io", "hackertarget.com", "threatcrowd.org",
    "api.certspotter.com", "censys.io", "search.censys.io",
    "securitytrails.com", "api.securitytrails.com",
    "virustotal.com", "www.virustotal.com",
    "api.hunter.io", "hunter.io",
    "haveibeenpwned.com", "api.pwnedpasswords.com",
})


class TargetScopeValidator:

    _instance: Optional['TargetScopeValidator'] = None
    _lock = __import__("threading").RLock()

    @classmethod
    def get(cls) -> 'TargetScopeValidator':
        with cls._lock:
            if cls._instance is None:
                from core.common.config import get_config
                target = get_config().get("TARGET", "example.com")
                cls._instance = cls([target])
            return cls._instance

    @classmethod
    def set(cls, validator: 'TargetScopeValidator') -> None:
        with cls._lock:
            cls._instance = validator

    def __init__(self, authorized_targets: List[str], *, allow_wildcard: Optional[bool] = None,
                 max_impact: str = None, expires_at: float = None):
        self.authorized_scope = [
            self._normalize_target(t) for t in authorized_targets if t
        ]
        # ── IMMUTABLE AUTHORIZATION CONTRACT (§3/§5) ──────────────────────
        # The ORIGINAL authorized targets, frozen at construction. Discovery may
        # add working-set entries via add_target(), but ONLY hosts that still
        # satisfy this baseline — discovery can never grant authority the
        # original contract did not. This is the security boundary; the mutable
        # authorized_scope is only a convenience cache.
        self._baseline_scope: frozenset = frozenset(self.authorized_scope)
        # Wildcard "*" is a LAB-only convenience. In production it must DENY (§4).
        if allow_wildcard is None:
            allow_wildcard = os.getenv("AUTHZ_ALLOW_WILDCARD", "false").lower() in ("true", "1", "yes", "on")
        self._allow_wildcard = bool(allow_wildcard)
        # Contract metadata (impact ceiling + expiry) — enforced by the broker/watchdog.
        self._max_impact = (max_impact or os.getenv("AUTHZ_MAX_IMPACT", "POC")).upper()
        self._expires_at = expires_at  # epoch seconds; None = no expiry
        if not self._allow_wildcard and "*" in self._baseline_scope:
            logger.warning("[TargetScopeValidator] Wildcard '*' in scope but AUTHZ_ALLOW_WILDCARD "
                           "is off — wildcard will DENY (production-safe).")
        # IPs that in-scope hosts (authorized domains and their subdomains) resolve
        # to. Populated automatically as ANY in-scope host is validated, so scanning
        # those IPs later is authorized — globally, without per-call-site wiring.
        # IP → expiry timestamp (TTL). A resolved IP is trusted only for a bounded
        # window, then re-validated — a permanent set let a stale/shared/cloud IP
        # stay authorized after DNS repointed (cross-tenant SSRF risk).
        self._authorized_ips: dict = {}
        self._resolved_hosts: dict = {}      # host → last-resolved timestamp (TTL)
        try:
            self._ip_ttl = float(os.getenv("AUTHZ_IP_TTL_SECONDS", "3600"))
        except (TypeError, ValueError):
            self._ip_ttl = 3600.0
        logger.info(f"[TargetScopeValidator] Initialized with scope: {self.authorized_scope}")

    def _add_ip(self, ip: str) -> None:
        import time
        self._authorized_ips[ip] = time.time() + self._ip_ttl

    def _ip_valid(self, ip: str) -> bool:
        import time
        exp = self._authorized_ips.get(ip)
        if exp is None:
            return False
        if time.time() >= exp:
            self._authorized_ips.pop(ip, None)   # expired → force re-validation
            return False
        return True

    def note_resolution(self, host: str, ip: str = None) -> None:
        try:
            host_norm = self._normalize_target(host)
            if not host_norm or not self._host_in_scope(host_norm):
                return
            ips = []
            if ip and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip.strip()):
                ips = [ip.strip()]
            else:
                last = self._resolved_hosts.get(host_norm)
                if last is not None and (time.time() - last) < self._ip_ttl:
                    return  # resolved recently — within TTL, skip re-resolve
                self._resolved_hosts[host_norm] = time.time()
                import socket
                try:
                    ips = list({ai[4][0] for ai in socket.getaddrinfo(host_norm, None)})
                except Exception:
                    ips = []
            for got in ips:
                if not self._ip_valid(got):
                    logger.info(f"[TargetScopeValidator] Authorized IP {got} (resolved from in-scope host {host_norm}, ttl={self._ip_ttl:.0f}s)")
                self._add_ip(got)
        except Exception as e:
            raise SystemError(f"Policy enforcement failed: {e}") from e

    def _host_in_scopes(self, norm: str, scopes) -> bool:
        norm_bare = norm[4:] if norm.startswith("www.") else norm
        for allowed in scopes:
            allowed_norm = self._normalize_target(allowed)
            if allowed == "*":
                # wildcard honored only in explicit lab mode (§4)
                if self._allow_wildcard:
                    return True
                continue
            if norm == allowed_norm or norm_bare == allowed_norm:
                return True
            if allowed_norm.startswith("*."):
                allowed_norm = allowed_norm[2:]
            allowed_bare = allowed_norm[4:] if allowed_norm.startswith("www.") else allowed_norm
            if norm_bare == allowed_bare or norm_bare.endswith("." + allowed_bare):
                return True
        return False

    def _host_in_scope(self, norm: str) -> bool:
        return self._host_in_scopes(norm, self.authorized_scope)

    def _matches_baseline(self, norm: str) -> bool:
        """Does this host satisfy the IMMUTABLE contract (§5)? Discovery is
        checked against this, never against the mutable working set."""
        return self._host_in_scopes(norm, self._baseline_scope)

    def _normalize_target(self, target: str) -> str:
        if not target:
            return ""
        target = target.strip()
        # Strip ALL leading scheme/method artifacts, not just the first. The
        # prompt/plan renderer can prepend a "METHOD:" prefix AND a "get://"
        # pseudo-scheme on top of the real "https://", producing a triple like
        # "GET:get://https://host/…". A single-pass "://" split would leave
        # "https" as the host and wrongly DENY an in-scope endpoint. Loop until
        # no leading scheme (word://) or HTTP-method (WORD:) prefix remains.
        _prev = None
        while target and target != _prev:
            _prev = target
            m = re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', target)
            if m:
                target = target[m.end():]
                continue
            m = re.match(r'^(?:get|post|put|delete|patch|head|options|connect|trace):',
                         target, re.IGNORECASE)
            if m:
                target = target[m.end():]
        # Strip path
        if "/" in target:
            target = target.split("/", 1)[0]
        # Strip userinfo (user:pass@host) — the host is AFTER the last '@'
        if "@" in target:
            target = target.rsplit("@", 1)[1]
        # Strip port
        if ":" in target:
            target = target.split(":", 1)[0]
        # Normalize FQDN trailing dot so "example.com." == "example.com"
        return target.rstrip(".").lower()

    def add_target(self, target: str) -> bool:
        """Add a DISCOVERED host to the working set — ONLY if it independently
        satisfies the immutable contract (§3/§5). Discovery can never expand
        authority beyond the original contract. Returns True if added.

        A discovered host that does NOT match the baseline is rejected and
        recorded as an out-of-scope DiscoveredAsset (visible, not authorized)."""
        norm = self._normalize_target(target)
        if not norm:
            return False
        if not self._matches_baseline(norm):
            self._note_discovered_out_of_scope(norm)
            logger.warning("[TargetScopeValidator] REFUSED to authorize discovered host "
                           "'%s' — outside immutable contract %s", norm, sorted(self._baseline_scope))
            return False
        if norm not in self.authorized_scope:
            self.authorized_scope.append(norm)
            logger.info("[TargetScopeValidator] Discovered host '%s' matches contract → in working set", norm)
        return True

    def _note_discovered_out_of_scope(self, norm: str) -> None:
        try:
            store = getattr(self, "_discovered_out_of_scope", None)
            if store is None:
                store = set()
                self._discovered_out_of_scope = store
            store.add(norm)
        except Exception:
            pass

    def discovered_out_of_scope(self) -> list:
        return sorted(getattr(self, "_discovered_out_of_scope", set()))

    def _related_to_scope(self, norm: str) -> bool:
        """True if `norm` shares a brand label with an in-scope target
        (e.g. api.decibyl.com or decibyl.ai-backup.s3… vs scope decibyl.ai) —
        an out-of-scope asset worth surfacing to the operator. Unrelated
        third-party hosts (fonts.googleapis.com) return False and are ignored.
        Never authorizes anything; used only to record a DiscoveredAsset."""
        try:
            toks = getattr(self, "_brand_toks", None)
            if toks is None:
                toks = set()
                for a in self._baseline_scope:
                    parts = [p for p in str(a).split(".") if p]
                    if len(parts) >= 2 and not re.match(r"^\d+$", parts[-2]):
                        toks.add(parts[-2].lower())
                self._brand_toks = toks
            n = norm.lower()
            return any(t and t in n for t in toks)
        except Exception:
            return False

    def is_authorized(self, target: str) -> bool:
        if not target:
            return False
        # Relative, SAME-ORIGIN reference (path / fragment / query, e.g. "/login",
        # "/#/register", "?q=1") — it resolves against the already-authorized target
        # host, so it is in scope by definition. Without this, _normalize_target
        # collapses "/login" → "" and the host check DENIES the target's OWN routes,
        # blocking the crawler/browser from login/register/cart pages (lost coverage).
        # Excludes protocol-relative URLs ("//host", "/\host") that point at a
        # DIFFERENT host — those fall through to the normal host check — and pseudo
        # schemes (javascript:/data:/file:) which are not same-origin navigations.
        _t = str(target).strip()
        if _t.startswith(("#", "?")) or (
                _t.startswith("/") and not _t.startswith("//") and not _t.startswith("/\\")):
            return True
        norm = self._normalize_target(target)
        if norm in PASSIVE_OSINT_DOMAINS:
            return True
        # Wildcard authorizes everything ONLY in explicit lab mode (§4).
        if self._allow_wildcard and any(a == "*" for a in self.authorized_scope):
            return True

        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', norm))

        # A bare IP that is LITERALLY in the contract (e.g. scope=['172.17.0.2'])
        # is authorized directly — otherwise an IP target authorized itself to
        # nothing and every request to it was silently filtered.
        if is_ip and (norm in self._baseline_scope or norm in self.authorized_scope):
            return True

        # Hostname: if it's an authorized domain or any subdomain thereof, authorize
        # it AND opportunistically cache the IPs it resolves to. Because every tool
        # invocation is validated through here, this makes IP-authorization global:
        # once the agent touches an in-scope host, that host's IPs are authorized for
        # any later scan — no per-discovery-site wiring needed.
        if not is_ip:
            if self._host_in_scope(norm):
                self.note_resolution(norm)
                return True
            # De-dupe denial logging (§10): every request to an out-of-scope host
            # (e.g. fonts.googleapis.com) hit this line, producing 871 identical
            # WARNINGs in scan c12701a6 — ~half of all warnings, burying real
            # signal. Log each unique denied host ONCE at WARNING; repeats go to
            # DEBUG. The deny decision itself is unchanged.
            _seen = getattr(self, "_denied_logged", None)
            if _seen is None:
                _seen = self._denied_logged = set()
            if norm not in _seen:
                _seen.add(norm)
                logger.warning(f"[TargetScopeValidator] DENIED host={norm} scope={self.authorized_scope}")
            else:
                logger.debug(f"[TargetScopeValidator] DENIED host={norm} (repeat)")
            # Surface (do NOT authorize) brand-related out-of-scope assets the
            # scan bumps into — e.g. api.decibyl.com, decibyl.ai-backup.s3… —
            # so the operator sees them in the Coverage panel and can widen scope
            # if they own them. Unrelated third-party hosts are ignored.
            if self._related_to_scope(norm):
                self._note_discovered_out_of_scope(norm)
            return False

        # Check if target is an IP address belonging to an in-scope domain.
        if True:
            # 1. Already recorded as an in-scope host's resolved IP (within TTL).
            if self._ip_valid(norm):
                return True
            # 2. Resolve every authorized domain (ALL A-records, not just the first)
            #    and authorize the IP if it belongs to one. Cache the result.
            import socket
            for allowed in self.authorized_scope:
                allowed_norm = self._normalize_target(allowed)
                if allowed_norm and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', allowed_norm):
                    domains_to_check = [allowed_norm]
                    if allowed_norm.startswith("www."):
                        domains_to_check.append(allowed_norm[4:])
                    for domain in domains_to_check:
                        try:
                            resolved = {ai[4][0] for ai in socket.getaddrinfo(domain, None)}
                        except Exception:
                            resolved = set()
                        if norm in resolved:
                            self._add_ip(norm)
                            logger.info(f"[TargetScopeValidator] Authorized resolved IP {norm} for in-scope domain {domain}")
                            return True
        return False

    def validate(self, target: str) -> None:
        logger.debug(f"[TargetScopeValidator] Validating target: {target}")
        # Phase 6.1 seal: `TargetScopeValidator` MUST NOT be no-op'd, even in
        # benchmark mode. The HF July 2026 incident happened partly because
        # cyber-eval workloads ran without production classifiers. We enforce
        # here that a validator with an empty scope refuses everything —
        # never accidentally-passes because scope was cleared for a test.
        if not self.authorized_scope:
            logger.error("[TargetScopeValidator] AUTHORIZATION_DENIED: scope is EMPTY — "
                         "refusing every target. This is the fail-closed guarantee.")
            raise AuthorizationError(
                "TargetScopeValidator scope is empty. Fail-closed guarantee "
                "denies every target when scope is unset. Load a scope via "
                "load_authorization_document() before any tool call."
            )
        if not self.is_authorized(target):
            logger.error(f"[TargetScopeValidator] AUTHORIZATION_DENIED: '{target}' is out of scope!")
            raise AuthorizationError(
                f"Target '{target}' is not in authorized scope: {self.authorized_scope}"
            )
        logger.info(f"[TargetScopeValidator] AUTHORIZATION_CHECK passed: {target}")

    def extract_and_validate_command(self, command: str) -> None:
        if not command:
            return
            
        logger.debug(f"[TargetScopeValidator] Checking targets in command: {command}")
        
        # 1. Extract URLs — capture the FULL authority (incl. any userinfo) so
        # urlparse resolves the REAL host. A truncated class that stops at '@'
        # lets http://authorized.com@evil.com be read as authorized.com (SSRF
        # scope bypass); use parsed.hostname, never the raw netloc.
        urls = re.findall(r'https?://[^\s"\'<>\\]+', command)
        targets = []
        for url in urls:
            try:
                parsed = urlparse(url)
                host = parsed.hostname  # strips userinfo + port; real target host
                if host:
                    targets.append(host)
                elif parsed.netloc:
                    targets.append(parsed.netloc)
            except Exception as e:
                raise SystemError(f"Policy enforcement failed: {e}") from e
                
        # 2. Extract standalone IPs and domains from tokens
        tokens = command.split()
        for token in tokens:
            token = token.strip("\",';()<>")
            # IP check
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', token):
                targets.append(token)
            # Domain check (has dot, starts/ends with alphanumeric, excludes tools/arguments)
            elif re.match(r'^[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-\.]+$', token):
                # Ignore arguments like -d, output file basenames or tool names
                if token.lower() not in (
                    "httpx", "nmap", "subfinder", "amass", "sslscan", "gobuster", 
                    "feroxbuster", "dirb", "dirsearch", "nikto", "nuclei", "whatweb",
                    "sqlmap", "wpscan", "sslyze", "arjun", "paramspider", "dalfox",
                    "katana", "curl", "theharvester", "example.com"
                ) and not token.startswith("-"):
                    targets.append(token)
                    
        # Validate all extracted targets
        for t in set(targets):
            self.validate(t)

class AuthContext:
    def __init__(self, allowed_tools: Optional[List[str]] = None, 
                 has_elevated_privilege: bool = False, 
                 target_profile=None):
        self.allowed_tools = allowed_tools or []
        self.has_elevated_privilege = has_elevated_privilege
        self.target_profile = target_profile
        self.validator = TargetScopeValidator.get()

    def can_scan_target(self, target: str) -> bool:
        return self.validator.is_authorized(target)

    def log_denial(self, tool_name: str, target: str, reason: str):
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"AuthContext Denial: tool={tool_name} target={target} reason={reason}")
