"""
Relationship Database
Known vulnerability-to-vulnerability transitions with success probabilities.
Used by VulnGraph to auto-infer attack edges.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# Each entry: (source_type, target_type) → {relationship, success_rate, description}
# These represent: "if you exploit source, you can reach target with this probability"
VULN_RELATIONSHIPS = {
    # ── SQL Injection chains ──
    ("sqli", "credentials"):         {"relationship": "extracts", "success_rate": 0.85,
                                       "description": "SQLi dumps credential tables"},
    ("sqli", "auth_bypass"):         {"relationship": "enables", "success_rate": 0.80,
                                       "description": "SQLi bypasses login checks"},
    ("sqli", "data_leak"):           {"relationship": "extracts", "success_rate": 0.90,
                                       "description": "SQLi reads sensitive data"},
    ("sqli", "rce"):                 {"relationship": "escalates_to", "success_rate": 0.30,
                                       "description": "SQLi via stacked queries / INTO OUTFILE"},

    # ── Credential chains ──
    ("credentials", "admin_access"):  {"relationship": "authenticates", "success_rate": 0.90,
                                       "description": "Stolen creds grant admin access"},
    ("credentials", "auth_bypass"):   {"relationship": "enables", "success_rate": 0.85,
                                       "description": "Valid creds bypass auth"},
    ("credentials", "lateral_move"):  {"relationship": "enables", "success_rate": 0.70,
                                       "description": "Creds reused on other services"},

    # ── Admin access chains ──
    ("admin_access", "rce"):          {"relationship": "escalates_to", "success_rate": 0.95,
                                       "description": "Admin panel → file upload/exec"},
    ("admin_access", "file_upload"):  {"relationship": "enables", "success_rate": 0.90,
                                       "description": "Admin can upload arbitrary files"},
    ("admin_access", "data_leak"):    {"relationship": "enables", "success_rate": 0.95,
                                       "description": "Admin reads all data"},
    ("admin_access", "config_access"):{"relationship": "enables", "success_rate": 0.85,
                                       "description": "Admin reads server config"},

    # ── Auth bypass chains ──
    ("auth_bypass", "admin_access"):  {"relationship": "escalates_to", "success_rate": 0.60,
                                       "description": "Bypassed auth may reach admin"},
    ("auth_bypass", "data_leak"):     {"relationship": "enables", "success_rate": 0.75,
                                       "description": "Bypassed auth exposes data"},
    ("auth_bypass", "idor"):          {"relationship": "enables", "success_rate": 0.80,
                                       "description": "Auth bypass enables IDOR testing"},

    # ── File inclusion chains ──
    ("lfi", "config_access"):         {"relationship": "reads", "success_rate": 0.80,
                                       "description": "LFI reads config files"},
    ("lfi", "credentials"):           {"relationship": "extracts", "success_rate": 0.60,
                                       "description": "LFI reads credential files"},
    ("lfi", "rce"):                   {"relationship": "escalates_to", "success_rate": 0.40,
                                       "description": "LFI via log poisoning / wrappers"},

    # ── RCE chains ──
    ("rce", "privesc"):               {"relationship": "escalates_to", "success_rate": 0.70,
                                       "description": "RCE → privilege escalation"},
    ("rce", "lateral_move"):          {"relationship": "enables", "success_rate": 0.65,
                                       "description": "RCE → pivot to other hosts"},
    ("rce", "data_leak"):             {"relationship": "enables", "success_rate": 0.95,
                                       "description": "RCE reads any file on system"},
    ("rce", "persistence"):           {"relationship": "enables", "success_rate": 0.80,
                                       "description": "RCE installs backdoor"},

    # ── File upload chains ──
    ("file_upload", "rce"):           {"relationship": "escalates_to", "success_rate": 0.85,
                                       "description": "Upload webshell → RCE"},
    ("file_upload", "xss"):           {"relationship": "enables", "success_rate": 0.70,
                                       "description": "Upload HTML/SVG → stored XSS"},

    # ── XSS chains ──
    ("xss", "session_hijack"):        {"relationship": "enables", "success_rate": 0.75,
                                       "description": "XSS steals session cookies"},
    ("xss", "credentials"):           {"relationship": "extracts", "success_rate": 0.50,
                                       "description": "XSS phishes or keylog creds"},
    ("xss", "csrf"):                  {"relationship": "enables", "success_rate": 0.80,
                                       "description": "XSS triggers CSRF actions"},

    # ── SSRF chains ──
    ("ssrf", "cloud_metadata"):       {"relationship": "reads", "success_rate": 0.85,
                                       "description": "SSRF hits 169.254.169.254"},
    ("ssrf", "internal_access"):      {"relationship": "enables", "success_rate": 0.70,
                                       "description": "SSRF reaches internal services"},
    ("ssrf", "credentials"):          {"relationship": "extracts", "success_rate": 0.60,
                                       "description": "SSRF reads internal cred stores"},

    # ── IDOR chains ──
    ("idor", "data_leak"):            {"relationship": "enables", "success_rate": 0.90,
                                       "description": "IDOR reads other users' data"},
    ("idor", "admin_access"):         {"relationship": "escalates_to", "success_rate": 0.40,
                                       "description": "IDOR to admin user object"},

    # ── Config access chains ──
    ("config_access", "credentials"): {"relationship": "extracts", "success_rate": 0.75,
                                       "description": "Config contains DB/API credentials"},
    ("config_access", "sqli"):        {"relationship": "enables", "success_rate": 0.60,
                                       "description": "Config reveals DB connection string"},

    # ── Session hijack chains ──
    ("session_hijack", "admin_access"):{"relationship": "escalates_to", "success_rate": 0.50,
                                        "description": "Hijacked admin session"},
    ("session_hijack", "data_leak"):   {"relationship": "enables", "success_rate": 0.80,
                                        "description": "Session grants data access"},

    # ── Privesc chains ──
    ("privesc", "persistence"):       {"relationship": "enables", "success_rate": 0.85,
                                       "description": "Root → install rootkit"},
    ("privesc", "data_leak"):         {"relationship": "enables", "success_rate": 0.95,
                                       "description": "Root reads everything"},

    # ── CORS/CSRF chains ──
    ("cors_misconfig", "data_leak"):  {"relationship": "enables", "success_rate": 0.60,
                                       "description": "CORS allows cross-origin reads"},
    ("csrf", "admin_access"):         {"relationship": "escalates_to", "success_rate": 0.35,
                                       "description": "CSRF changes admin password"},

    # ── Cloud metadata chains ──
    ("cloud_metadata", "credentials"):{"relationship": "extracts", "success_rate": 0.90,
                                       "description": "Metadata contains IAM keys"},
    ("cloud_metadata", "rce"):        {"relationship": "escalates_to", "success_rate": 0.50,
                                       "description": "Cloud keys → instance control"},

    # ── Weak config chains ──
    ("weak_config", "auth_bypass"):   {"relationship": "enables", "success_rate": 0.55,
                                       "description": "Default creds / weak settings"},
    ("weak_config", "data_leak"):     {"relationship": "enables", "success_rate": 0.45,
                                       "description": "Misconfigured access controls"},

    # ── SSTI chains ──
    ("ssti", "rce"):                  {"relationship": "escalates_to", "success_rate": 0.80,
                                       "description": "Template injection → code exec"},
    ("ssti", "data_leak"):            {"relationship": "enables", "success_rate": 0.70,
                                       "description": "SSTI reads server variables"},

    # ── XXE chains ──
    ("xxe", "lfi"):                   {"relationship": "enables", "success_rate": 0.85,
                                       "description": "XXE reads local files"},
    ("xxe", "ssrf"):                  {"relationship": "enables", "success_rate": 0.75,
                                       "description": "XXE triggers outbound requests"},

    # ── Open redirect chains ──
    ("open_redirect", "xss"):         {"relationship": "enables", "success_rate": 0.40,
                                       "description": "Redirect to XSS payload page"},
    ("open_redirect", "credentials"): {"relationship": "extracts", "success_rate": 0.45,
                                       "description": "Redirect to phishing page"},

    # ── Deserialization chains ──
    ("deserialization", "rce"):       {"relationship": "escalates_to", "success_rate": 0.75,
                                       "description": "Unsafe deserialization → code exec"},
}

# Type aliases for normalization
TYPE_ALIASES = {
    "sql_injection": "sqli",
    "sql injection": "sqli",
    "cross_site_scripting": "xss",
    "cross-site scripting": "xss",
    "local_file_inclusion": "lfi",
    "file_inclusion": "lfi",
    "path_traversal": "lfi",
    "directory_traversal": "lfi",
    "remote_code_execution": "rce",
    "command_injection": "rce",
    "os_command_injection": "rce",
    "server_side_request_forgery": "ssrf",
    "server-side request forgery": "ssrf",
    "insecure_direct_object_reference": "idor",
    "broken_access_control": "idor",
    "authentication_bypass": "auth_bypass",
    "broken_authentication": "auth_bypass",
    "server_side_template_injection": "ssti",
    "template_injection": "ssti",
    "xml_external_entity": "xxe",
    "cross_site_request_forgery": "csrf",
    "security_misconfiguration": "weak_config",
    "misconfiguration": "weak_config",
    "default_credentials": "credentials",
    "information_disclosure": "data_leak",
    "sensitive_data_exposure": "data_leak",
}


class RelationshipDB:
    """Database of known vulnerability relationships and transition probabilities"""

    def __init__(self):
        self.relationships = dict(VULN_RELATIONSHIPS)
        self.aliases = dict(TYPE_ALIASES)

    def normalize_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type names"""
        vt = vuln_type.lower().strip().replace(" ", "_").replace("-", "_")
        return self.aliases.get(vt, vt)

    def get_relationship(self, source_type: str, target_type: str) -> Optional[Dict]:
        """Get relationship between two vuln types"""
        src = self.normalize_type(source_type)
        tgt = self.normalize_type(target_type)
        return self.relationships.get((src, tgt))

    def get_all_targets(self, source_type: str) -> List[Dict]:
        """Get all vulnerability types reachable from source"""
        src = self.normalize_type(source_type)
        results = []
        for (s, t), rel in self.relationships.items():
            if s == src:
                results.append({"target": t, **rel})
        results.sort(key=lambda x: x["success_rate"], reverse=True)
        return results

    def get_all_sources(self, target_type: str) -> List[Dict]:
        """Get all vulnerability types that can lead to target"""
        tgt = self.normalize_type(target_type)
        results = []
        for (s, t), rel in self.relationships.items():
            if t == tgt:
                results.append({"source": s, **rel})
        results.sort(key=lambda x: x["success_rate"], reverse=True)
        return results

    def get_chain_probability(self, chain: List[str]) -> float:
        """Calculate probability of a full chain succeeding"""
        if len(chain) < 2:
            return 1.0
        prob = 1.0
        for i in range(len(chain) - 1):
            rel = self.get_relationship(chain[i], chain[i+1])
            if rel:
                prob *= rel["success_rate"]
            else:
                prob *= 0.1  # Unknown relationship = low probability
        return prob

    def suggest_next_steps(self, current_type: str, max_results: int = 5) -> List[Dict]:
        """Given a vuln type, suggest what to try next"""
        targets = self.get_all_targets(current_type)
        return targets[:max_results]

    def add_relationship(self, source: str, target: str,
                         relationship: str, success_rate: float,
                         description: str = ""):
        """Add or update a relationship (for LLM-discovered chains)"""
        src = self.normalize_type(source)
        tgt = self.normalize_type(target)
        self.relationships[(src, tgt)] = {
            "relationship": relationship,
            "success_rate": success_rate,
            "description": description,
        }
        logger.info(f"[RelDB] Added: {src} --[{relationship} {success_rate:.0%}]--> {tgt}")

    def summary_for_llm(self) -> str:
        """Compact summary of known relationships for LLM"""
        lines = ["KNOWN ATTACK RELATIONSHIPS:"]
        by_source = {}
        for (s, t), rel in self.relationships.items():
            by_source.setdefault(s, []).append((t, rel["success_rate"], rel["relationship"]))

        for src in sorted(by_source.keys()):
            targets = sorted(by_source[src], key=lambda x: -x[1])[:3]
            target_str = ", ".join(f"{t}({r:.0%})" for t, p, r in targets)
            lines.append(f"  {src} → {target_str}")

        return "\n".join(lines)