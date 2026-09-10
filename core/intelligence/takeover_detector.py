from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Fingerprint → CNAME-suffix pairs. A match on the fingerprint alone is NEVER
# enough — the DNS check must also succeed. Suffixes must be leading-dot so
# a host like `evil-heroku-clone.example.com` cannot spoof `.herokuapp.com`.
_TAKEOVER_SIGNATURES: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    # provider, response-body signatures, dangling-CNAME suffixes
    ("heroku", (
        "no such app",
        "herokucdn.com/error-pages/no-such-app.html",
    ), (".herokuapp.com", ".herokudns.com")),
    ("github_pages", (
        "there isn't a github pages site here",
        "there isn't a github pages site here.",
    ), (".github.io",)),
    ("aws_s3", (
        "nosuchbucket",
        "the specified bucket does not exist",
    ), (".s3.amazonaws.com", ".s3-website-", ".s3.")),
    ("azure", (
        "404 web site not found",
    ), (".azurewebsites.net", ".cloudapp.net", ".trafficmanager.net")),
    ("fastly", (
        "fastly error: unknown domain",
    ), (".fastly.net",)),
    ("shopify", (
        "sorry, this shop is currently unavailable",
    ), (".myshopify.com",)),
    ("bitbucket", (
        "repository not found",
    ), (".bitbucket.io",)),
    ("readthedocs", (
        "unknown to read the docs",
    ), (".readthedocs.io", ".readthedocs.org")),
    ("tumblr", (
        "whatever you were looking for doesn't currently exist at this address",
    ), (".tumblr.com", ".domains.tumblr.com")),
    ("unbounce", (
        "the requested url was not found on this server",
    ), (".unbouncepages.com",)),
    ("wordpress", (
        "do you want to register",
    ), (".wordpress.com",)),
    ("netlify", (
        "not found - request id",
    ), (".netlify.app", ".netlify.com")),
    ("surge", (
        "project not found",
    ), (".surge.sh",)),
    ("desk", (
        "please try again or try desk.com free for 14 days",
    ), (".desk.com",)),
)

# Explicit NEGATIVE signatures — these look takeover-shaped but are known
# false positives. Any of these in the body immediately disqualifies the
# fingerprint match, regardless of what else matched.
_FALSE_POSITIVE_SIGNATURES: tuple[str, ...] = (
    # Heroku dyno sleeping / crashed: the app IS claimed, just not running.
    # The response embeds an iframe to herokucdn.com error pages so it looks
    # like an unclaimed app if you only look for herokucdn.com in the body.
    "application error",
    # AWS S3 access denied on a CLAIMED bucket (private ACL, wrong signature)
    "accessdenied",
    "<code>accessdenied</code>",
    # GitHub Pages 404 on a claimed empty repo
    "there isn't a github pages site here yet",  # empty-branch variant
)


@dataclass
class TakeoverVerdict:
    is_takeover: bool
    provider: Optional[str] = None
    reason: str = ""
    cname: Optional[str] = None

    def as_finding_details(self) -> str:
        if self.is_takeover:
            return (
                f"Dangling {self.provider} CNAME: {self.cname}. The fingerprint "
                f"in the response indicates an unclaimed instance; the DNS still "
                f"points at a third-party service anyone can register."
            )
        return self.reason


@lru_cache(maxsize=1024)
def _resolve_cname(hostname: str) -> Optional[str]:
    if not hostname:
        return None
    hostname = hostname.strip(".").lower()
    try:
        import dns.resolver as _r
        resolver = _r.Resolver()
        resolver.lifetime = 5.0
        resolver.timeout = 3.0
        try:
            ans = resolver.resolve(hostname, "CNAME")
            targets = [str(rdata.target).strip(".").lower() for rdata in ans]
            if targets:
                return targets[-1]
        except Exception:
            return None
    except Exception:
        # dnspython not installed. Fall back to socket which does not expose
        # CNAME records — treat as "unknown, no CNAME evidence."
        try:
            _, aliases, _ = socket.gethostbyname_ex(hostname)
            if aliases:
                return aliases[-1].strip(".").lower()
        except Exception:
            return None
    return None


def _matches_any(needles: tuple[str, ...], body_lower: str) -> bool:
    return any(n in body_lower for n in needles)


def evaluate(response_body: str, hostname: str,
             status_code: Optional[int] = None) -> TakeoverVerdict:
    body_lower = (response_body or "").lower()
    if not body_lower:
        return TakeoverVerdict(False, reason="empty response body")

    # Fast-path: explicit false-positive markers override every fingerprint.
    for fp in _FALSE_POSITIVE_SIGNATURES:
        if fp in body_lower:
            return TakeoverVerdict(
                False,
                reason=(f"response contains a known false-positive marker "
                        f"({fp!r}); the service is claimed but returning a "
                        f"stock error (sleeping dyno, private bucket, empty "
                        f"repo, …)."),
            )

    # Find the first fingerprint match.
    matched: Optional[Tuple[str, tuple[str, ...]]] = None
    for provider, sigs, cname_suffixes in _TAKEOVER_SIGNATURES:
        if _matches_any(sigs, body_lower):
            matched = (provider, cname_suffixes)
            break
    if matched is None:
        return TakeoverVerdict(False, reason="no takeover fingerprint in response")

    provider, cname_suffixes = matched

    # DNS clause — a real takeover needs a dangling CNAME into the same
    # provider whose fingerprint matched. An A/AAAA record means nothing
    # is delegated: an attacker cannot hijack it via provider signup.
    cname = _resolve_cname(hostname)
    if cname is None:
        return TakeoverVerdict(
            False, provider=provider,
            reason=(f"fingerprint suggests {provider} but {hostname} has no "
                    f"CNAME (direct A/AAAA record) — nothing to hijack."),
        )
    if not any(cname.endswith(sfx.lstrip(".")) or ("." + cname).endswith(sfx)
               for sfx in cname_suffixes):
        return TakeoverVerdict(
            False, provider=provider, cname=cname,
            reason=(f"fingerprint suggests {provider} but CNAME points at "
                    f"{cname!r}, not any of {list(cname_suffixes)} — the "
                    f"delegation is elsewhere."),
        )

    return TakeoverVerdict(
        True, provider=provider, cname=cname,
        reason=(f"unclaimed {provider} instance: fingerprint present AND "
                f"CNAME {cname!r} dangles into {provider}"),
    )
