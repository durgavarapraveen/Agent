"""
Finding Correlation Engine — chains related findings into attack narratives.
"""

import logging
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class AttackChain:
    chain_id: str
    name: str
    description: str
    severity: str  # Composite severity (highest in chain)
    impact: str
    findings: List[Dict] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)
    likelihood: float = 0.0  # 0.0-1.0
    # P1.5: provenance for the chain — whether every member was CONFIRMED and
    # whether an evidence dependency (not just a type/host coincidence) links
    # the steps. A chain built under strict mode has both True.
    confirmed: bool = False
    evidence_link: bool = False


# Rules defining how finding types can chain together
# Format: (finding_type_A, finding_type_B) -> chain template
CHAIN_RULES: List[Dict] = [
    {
        "requires": [("OPEN_REDIRECT",), ("SSRF",)],
        "name": "Open Redirect → SSRF Chain",
        "description": "Open redirect can be chained with SSRF to access internal services by redirecting requests to internal URLs.",
        "impact": "Internal network access, potential data exfiltration from internal services",
        "severity": "CRITICAL",
        "likelihood_boost": 0.3,
    },
    {
        "requires": [("XSS",), ("CSRF",)],
        "name": "XSS + CSRF → Account Takeover",
        "description": "Cross-site scripting can bypass CSRF protections, enabling unauthorized actions on behalf of authenticated users.",
        "impact": "Full account takeover, unauthorized state-changing actions",
        "severity": "CRITICAL",
        "likelihood_boost": 0.25,
    },
    {
        "requires": [("XSS",), ("MISSING_HEADER",)],
        "name": "XSS + Missing Security Headers",
        "description": "XSS vulnerability is amplified by missing security headers (CSP, X-Frame-Options) that would otherwise mitigate exploitation.",
        "impact": "Unrestricted XSS exploitation, potential session hijacking",
        "severity": "HIGH",
        "likelihood_boost": 0.2,
    },
    {
        "requires": [("INFORMATION_DISCLOSURE", "INFO_DISCLOSURE", "DIRECTORY_LISTING"), ("SQL_INJECTION",)],
        "name": "Info Disclosure → SQL Injection",
        "description": "Information disclosure reveals database structure, table names, or technology stack that aids SQL injection exploitation.",
        "impact": "Targeted database extraction using disclosed schema information",
        "severity": "CRITICAL",
        "likelihood_boost": 0.3,
    },
    {
        "requires": [("INFORMATION_DISCLOSURE", "INFO_DISCLOSURE"), ("AUTHENTICATION_BYPASS",)],
        "name": "Info Disclosure → Auth Bypass → Privilege Escalation",
        "description": "Disclosed credentials, API keys, or session data enables authentication bypass and subsequent privilege escalation.",
        "impact": "Unauthorized access to privileged functionality",
        "severity": "CRITICAL",
        "likelihood_boost": 0.35,
    },
    {
        "requires": [("DEFAULT_CREDENTIALS",), ("PRIVILEGE_ESCALATION",)],
        "name": "Default Creds → Privilege Escalation",
        "description": "Default credentials provide initial access, which is then escalated through privilege escalation vulnerabilities.",
        "impact": "Full system compromise from default credentials",
        "severity": "CRITICAL",
        "likelihood_boost": 0.4,
    },
    {
        "requires": [("CORS_MISCONFIGURATION",), ("INFORMATION_DISCLOSURE", "INFO_DISCLOSURE")],
        "name": "CORS Misconfiguration + Info Disclosure",
        "description": "Permissive CORS policy allows cross-origin reading of disclosed sensitive information.",
        "impact": "Cross-origin data theft of sensitive information",
        "severity": "HIGH",
        "likelihood_boost": 0.2,
    },
    {
        "requires": [("SSRF",), ("INFORMATION_DISCLOSURE", "INFO_DISCLOSURE")],
        "name": "SSRF → Internal Info Disclosure",
        "description": "SSRF enables access to internal metadata endpoints (cloud provider metadata, internal APIs) exposing sensitive data.",
        "impact": "Cloud credential theft, internal service enumeration",
        "severity": "CRITICAL",
        "likelihood_boost": 0.35,
    },
    {
        "requires": [("PATH_TRAVERSAL",), ("INFORMATION_DISCLOSURE", "INFO_DISCLOSURE")],
        "name": "Path Traversal → Sensitive File Access",
        "description": "Path traversal combined with information disclosure about file structure enables targeted file reading.",
        "impact": "Reading sensitive configuration files, credentials, source code",
        "severity": "CRITICAL",
        "likelihood_boost": 0.3,
    },
    {
        "requires": [("COMMAND_INJECTION",)],
        "name": "Command Injection → Remote Code Execution",
        "description": "Command injection vulnerability provides direct remote code execution capability.",
        "impact": "Full server compromise, lateral movement",
        "severity": "CRITICAL",
        "likelihood_boost": 0.5,
        "standalone": True,
    },
    {
        "requires": [("SQL_INJECTION",)],
        "name": "SQL Injection → Data Breach",
        "description": "SQL injection enables direct database access for data extraction or modification.",
        "impact": "Complete database compromise, data exfiltration",
        "severity": "CRITICAL",
        "likelihood_boost": 0.45,
        "standalone": True,
    },
    {
        "requires": [("DEFAULT_CREDENTIALS",)],
        "name": "Default Credentials → Unauthorized Access",
        "description": "Default or weak credentials provide unauthorized access to the application.",
        "impact": "Unauthorized access to application functionality and data",
        "severity": "CRITICAL",
        "likelihood_boost": 0.5,
        "standalone": True,
    },
    {
        "requires": [("IDOR",), ("AUTHENTICATION_BYPASS",)],
        "name": "IDOR + Auth Bypass → Mass Data Access",
        "description": "Insecure Direct Object Reference combined with authentication bypass enables access to all users' data.",
        "impact": "Mass data breach affecting all users",
        "severity": "CRITICAL",
        "likelihood_boost": 0.35,
    },
    {
        "requires": [("TLS_WEAKNESS",), ("MISSING_HEADER",)],
        "name": "TLS Weakness + Missing HSTS → MitM",
        "description": "Weak TLS configuration combined with missing HSTS header enables man-in-the-middle attacks.",
        "impact": "Traffic interception, credential theft via protocol downgrade",
        "severity": "HIGH",
        "likelihood_boost": 0.15,
    },
    {
        "requires": [("XSS",), ("DEFAULT_CREDENTIALS",)],
        "name": "XSS + Default Creds → Persistent Backdoor",
        "description": "XSS can be used to inject persistent scripts while default credentials ensure continued access.",
        "impact": "Persistent compromise with multiple re-entry paths",
        "severity": "CRITICAL",
        "likelihood_boost": 0.35,
    },
]

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class CorrelationEngine:
    """Analyzes findings and identifies attack chains between related vulnerabilities."""

    def __init__(self):
        self.chains: List[AttackChain] = []
        self._chain_counter = 0

    def _normalize_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type for matching."""
        if not vuln_type:
            return ""
        t = vuln_type.upper().strip()
        aliases = {
            "CROSS_SITE_SCRIPTING": "XSS",
            "REFLECTED_XSS": "XSS",
            "STORED_XSS": "XSS",
            "DOM_XSS": "XSS",
            "SQLI": "SQL_INJECTION",
            "BLIND_SQL_INJECTION": "SQL_INJECTION",
            "SERVER_SIDE_REQUEST_FORGERY": "SSRF",
            "OPEN_REDIRECT_VULNERABILITY": "OPEN_REDIRECT",
            "REDIRECT": "OPEN_REDIRECT",
            "LFI": "PATH_TRAVERSAL",
            "LOCAL_FILE_INCLUSION": "PATH_TRAVERSAL",
            "RFI": "PATH_TRAVERSAL",
            "REMOTE_FILE_INCLUSION": "PATH_TRAVERSAL",
            "RCE": "COMMAND_INJECTION",
            "REMOTE_CODE_EXECUTION": "COMMAND_INJECTION",
            "OS_COMMAND_INJECTION": "COMMAND_INJECTION",
            "WEAK_CREDENTIALS": "DEFAULT_CREDENTIALS",
            "MISSING_SECURITY_HEADER": "MISSING_HEADER",
            "MISSING_CSP": "MISSING_HEADER",
            "MISSING_HSTS": "MISSING_HEADER",
            "MISSING_X_FRAME_OPTIONS": "MISSING_HEADER",
            "INSECURE_CORS": "CORS_MISCONFIGURATION",
            "CORS": "CORS_MISCONFIGURATION",
            "BROKEN_ACCESS_CONTROL": "IDOR",
            "INSECURE_DIRECT_OBJECT_REFERENCE": "IDOR",
            "CSRF_MISSING": "CSRF",
            "CROSS_SITE_REQUEST_FORGERY": "CSRF",
            "SENSITIVE_DATA_EXPOSURE": "INFORMATION_DISCLOSURE",
            "DATA_EXPOSURE": "INFORMATION_DISCLOSURE",
            "WEAK_SSL": "TLS_WEAKNESS",
            "WEAK_TLS": "TLS_WEAKNESS",
            "SSL_WEAKNESS": "TLS_WEAKNESS",
        }
        return aliases.get(t, t)

    @staticmethod
    def _is_confirmed(f: Dict) -> bool:
        """A finding counts as CONFIRMED via any of the three signals the
        pipeline uses (P1.5)."""
        if f.get("confirmed") is True:
            return True
        for k in ("status", "reproducibility_status"):
            if str(f.get(k) or "").upper() == "CONFIRMED":
                return True
        return False

    @staticmethod
    def _evidence_link(up: Dict, down: Dict) -> bool:
        """True only when `down` has an evidence dependency on `up` — not just a
        type/host coincidence (P1.5). Conservative, to never merge unrelated
        findings: requires either an explicit id/parent reference, or a concrete
        artifact string from `up`'s evidence reappearing in `down`'s evidence.
        """
        import re as _re
        down_text = " ".join(str(down.get(k, "")) for k in
                             ("proof", "details", "depends_on", "evidence",
                              "parent_finding", "derived_from", "prerequisite"))
        if not down_text.strip():
            return False
        up_id = str(up.get("id") or up.get("vuln_id") or "").strip()
        if up_id and up_id in down_text:
            return True
        up_text = " ".join(str(up.get(k, "")) for k in ("proof", "details", "evidence"))
        # Concrete artifacts: tokens/emails/paths/keys >= 8 chars, not pure digits.
        up_tokens = {t for t in _re.findall(r"[A-Za-z0-9_\-\.@:/]{8,}", up_text)
                     if not t.isdigit()}
        return bool(up_tokens and any(t in down_text for t in up_tokens))

    def _same_scope(self, finding_a: Dict, finding_b: Dict) -> bool:
        """Check if two findings are in the same scope (same host)."""
        def _host(f):
            for key in ("target", "location", "url"):
                val = f.get(key, "")
                if val and "://" in val:
                    return urlparse(val).hostname or ""
            return ""
        host_a = _host(finding_a)
        host_b = _host(finding_b)
        if not host_a or not host_b:
            return True  # Can't determine scope, assume same
        return host_a == host_b

    def _finding_matches_slot(self, finding: Dict, type_slot: Tuple[str, ...]) -> bool:
        """Check if a finding matches any of the types in a rule slot."""
        vuln_type = self._normalize_type(finding.get("type") or finding.get("vuln_type") or "")
        title_upper = (finding.get("title") or "").upper()

        for slot_type in type_slot:
            if vuln_type == slot_type:
                return True
            if slot_type in title_upper:
                return True
        return False

    def _compute_likelihood(self, findings: List[Dict], rule: Dict) -> float:
        """Compute likelihood score based on finding confidence and status."""
        base = 0.3
        boost = rule.get("likelihood_boost", 0.2)

        avg_confidence = 0.0
        confirmed_count = 0
        for f in findings:
            conf = f.get("confidence_score", 0.5)
            if isinstance(conf, (int, float)):
                avg_confidence += conf if conf <= 1.0 else conf / 100.0
            if (f.get("status") or "").upper() == "CONFIRMED":
                confirmed_count += 1

        avg_confidence /= max(len(findings), 1)

        score = base + boost + (avg_confidence * 0.3)
        score += confirmed_count * 0.05

        return min(score, 1.0)

    def _highest_severity(self, findings: List[Dict], rule_severity: str) -> str:
        """Return the highest severity between findings and the rule's declared severity."""
        max_sev = SEVERITY_ORDER.get(rule_severity.upper(), 0)
        for f in findings:
            sev = SEVERITY_ORDER.get((f.get("severity") or "INFO").upper(), 0)
            if sev > max_sev:
                max_sev = sev
        for name, val in SEVERITY_ORDER.items():
            if val == max_sev:
                return name
        return rule_severity

    def correlate(self, findings: List[Dict],
                  confirmed_only: bool = False,
                  require_evidence_link: bool = False) -> List[AttackChain]:
        """Analyze findings and identify attack chains.

        P1.5 strict mode (opt-in, backward compatible):
          * ``confirmed_only`` — only CONFIRMED findings may form a chain.
          * ``require_evidence_link`` — a multi-step chain is created only when
            an evidence dependency links the steps (not just type + host), so
            unrelated findings are never merged.
        Default behaviour (both False) is unchanged.
        """
        self.chains = []
        self._chain_counter = 0

        if not findings:
            return []

        if confirmed_only:
            findings = [f for f in findings if self._is_confirmed(f)]
            if not findings:
                return []

        used_finding_sets: Set[frozenset] = set()

        for rule in CHAIN_RULES:
            slots = rule["requires"]
            is_standalone = rule.get("standalone", False)

            if is_standalone and len(slots) == 1:
                # Standalone chain: each matching finding becomes its own chain
                for f in findings:
                    if self._finding_matches_slot(f, slots[0]):
                        fset = frozenset([id(f)])
                        if fset in used_finding_sets:
                            continue

                        self._chain_counter += 1
                        chain = AttackChain(
                            chain_id=f"chain_{self._chain_counter:03d}",
                            name=rule["name"],
                            description=rule["description"],
                            severity=self._highest_severity([f], rule["severity"]),
                            impact=rule["impact"],
                            findings=[f],
                            steps=[
                                f"1. Exploit: {f.get('title', 'Unknown')} at {f.get('target') or f.get('location') or 'target'}",
                                f"2. Impact: {rule['impact']}",
                            ],
                            likelihood=self._compute_likelihood([f], rule),
                            confirmed=self._is_confirmed(f),
                            evidence_link=True,  # standalone: single finding is self-evident
                        )
                        self.chains.append(chain)
                        used_finding_sets.add(fset)
                continue

            # Multi-finding chains: find combinations
            if len(slots) == 2:
                slot_a, slot_b = slots
                matches_a = [f for f in findings if self._finding_matches_slot(f, slot_a)]
                matches_b = [f for f in findings if self._finding_matches_slot(f, slot_b)]

                for fa in matches_a:
                    for fb in matches_b:
                        if fa is fb:
                            continue
                        if not self._same_scope(fa, fb):
                            continue

                        # P1.5: require an evidence dependency (either direction)
                        # before chaining, so unrelated same-host findings are
                        # never merged.
                        ev_linked = self._evidence_link(fa, fb) or self._evidence_link(fb, fa)
                        if require_evidence_link and not ev_linked:
                            continue

                        fset = frozenset([id(fa), id(fb)])
                        if fset in used_finding_sets:
                            continue

                        self._chain_counter += 1
                        chain_findings = [fa, fb]
                        chain = AttackChain(
                            chain_id=f"chain_{self._chain_counter:03d}",
                            name=rule["name"],
                            description=rule["description"],
                            severity=self._highest_severity(chain_findings, rule["severity"]),
                            impact=rule["impact"],
                            findings=chain_findings,
                            steps=[
                                f"1. {fa.get('title', 'Unknown')} at {fa.get('target') or fa.get('location') or 'target'}",
                                f"2. Chain with: {fb.get('title', 'Unknown')} at {fb.get('target') or fb.get('location') or 'target'}",
                                f"3. Achieve: {rule['impact']}",
                            ],
                            likelihood=self._compute_likelihood(chain_findings, rule),
                            confirmed=self._is_confirmed(fa) and self._is_confirmed(fb),
                            evidence_link=ev_linked,
                        )
                        self.chains.append(chain)
                        used_finding_sets.add(fset)

        # Sort by severity then likelihood
        self.chains.sort(
            key=lambda c: (SEVERITY_ORDER.get(c.severity, 0), c.likelihood),
            reverse=True,
        )

        logger.info(f"[Correlation] Found {len(self.chains)} attack chains from {len(findings)} findings")
        return self.chains

    def get_summary(self) -> Dict:
        """Get a summary of correlated attack chains."""
        if not self.chains:
            return {"total_chains": 0, "chains": []}

        return {
            "total_chains": len(self.chains),
            "critical_chains": len([c for c in self.chains if c.severity == "CRITICAL"]),
            "high_chains": len([c for c in self.chains if c.severity == "HIGH"]),
            "chains": [
                {
                    "chain_id": c.chain_id,
                    "name": c.name,
                    "severity": c.severity,
                    "impact": c.impact,
                    "likelihood": round(c.likelihood, 2),
                    "finding_count": len(c.findings),
                    "steps": c.steps,
                    "findings": [
                        {
                            "title": f.get("title", ""),
                            "type": f.get("type", ""),
                            "severity": f.get("severity", ""),
                            "target": f.get("target") or f.get("location", ""),
                        }
                        for f in c.findings
                    ],
                }
                for c in self.chains
            ],
        }

    def get_findings(self) -> List[Dict]:
        """Convert high-value chains into vulnerability findings."""
        findings = []
        for chain in self.chains:
            if chain.likelihood < 0.3:
                continue
            finding_titles = ", ".join(f.get("title", "?") for f in chain.findings)
            findings.append({
                "title": f"Attack Chain: {chain.name}",
                "type": "ATTACK_CHAIN",
                "severity": chain.severity,
                "confidence_score": chain.likelihood,
                "target": chain.findings[0].get("target") or chain.findings[0].get("location", "") if chain.findings else "",
                "location": ", ".join(f.get("target") or f.get("location", "") for f in chain.findings),
                "details": f"{chain.description}\n\nChained findings: {finding_titles}",
                "proof": "\n".join(chain.steps),
                "remediation": f"Address all findings in this chain to prevent: {chain.impact}",
                "tool": "correlation_engine",
                "status": "CONFIRMED" if chain.likelihood >= 0.6 else "UNCONFIRMED",
            })
        return findings
