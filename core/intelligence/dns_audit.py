"""
Defensive DNS Security Posture Auditor (core/dns_audit.py)

Audits domain SPF and DMARC records to verify strict enforcement
against domain spoofing and email misuse.
"""

import logging
from typing import Dict, Any

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

logger = logging.getLogger(__name__)


class DNSPostureAuditor:
    """Defensive DNS configuration auditor."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def audit_domain_email_security(self, domain: str) -> Dict[str, Any]:
        """
        Check SPF and DMARC records for a domain to evaluate spoofing defense posture.
        """
        if not DNS_AVAILABLE:
            return {
                "domain": domain,
                "error": "dnspython library not installed. Install via `pip install dnspython`."
            }

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        spf_result = self._check_spf(resolver, domain)
        dmarc_result = self._check_dmarc(resolver, domain)

        return {
            "domain": domain,
            "spf": spf_result,
            "dmarc": dmarc_result,
            "is_fully_hardened": spf_result.get("is_secure", False) and dmarc_result.get("is_enforced", False)
        }

    def _check_spf(self, resolver: dns.resolver.Resolver, domain: str) -> Dict[str, Any]:
        result = {
            "record_found": False,
            "raw_record": None,
            "policy": "MISSING",
            "is_secure": False,
            "recommendation": "Configure an SPF TXT record with '-all' enforcement."
        }
        try:
            answers = resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = "".join([b.decode('utf-8', errors='ignore') for b in rdata.strings])
                if txt.startswith("v=spf1"):
                    result["record_found"] = True
                    result["raw_record"] = txt
                    if "-all" in txt:
                        result["policy"] = "HardFail (-all)"
                        result["is_secure"] = True
                        result["recommendation"] = "SPF policy is strictly enforced."
                    elif "~all" in txt:
                        result["policy"] = "SoftFail (~all)"
                        result["recommendation"] = "Consider updating '~all' to '-all' for strict rejection."
                    elif "+all" in txt or "?all" in txt:
                        result["policy"] = "Permissive (+all/?all)"
                        result["recommendation"] = "Remove permissive directives (+all/?all) to prevent spoofing."
                    break
        except Exception as e:
            logger.debug(f"[DNSAuditor] SPF lookup error for {domain}: {e}")

        return result

    def _check_dmarc(self, resolver: dns.resolver.Resolver, domain: str) -> Dict[str, Any]:
        dmarc_target = f"_dmarc.{domain}"
        result = {
            "record_found": False,
            "raw_record": None,
            "policy": "MISSING",
            "is_enforced": False,
            "recommendation": "Publish a DMARC record at _dmarc." + domain
        }
        try:
            answers = resolver.resolve(dmarc_target, 'TXT')
            for rdata in answers:
                txt = "".join([b.decode('utf-8', errors='ignore') for b in rdata.strings])
                if txt.startswith("v=DMARC1"):
                    result["record_found"] = True
                    result["raw_record"] = txt
                    if "p=reject" in txt:
                        result["policy"] = "reject"
                        result["is_enforced"] = True
                        result["recommendation"] = "DMARC is fully enforced in reject mode."
                    elif "p=quarantine" in txt:
                        result["policy"] = "quarantine"
                        result["is_enforced"] = True
                        result["recommendation"] = "DMARC quarantines unauthorized emails."
                    elif "p=none" in txt:
                        result["policy"] = "none"
                        result["recommendation"] = "DMARC is in monitoring mode. Transition to 'quarantine' or 'reject'."
                    break
        except Exception as e:
            logger.debug(f"[DNSAuditor] DMARC lookup error for {dmarc_target}: {e}")

        return result
