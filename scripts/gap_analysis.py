#!/usr/bin/env python3
"""Coverage gap analysis: persisted scan findings vs OWASP Juice Shop's
canonical vulnerability CLASSES. Prints coverage %, found/missing classes, and
the responsible probe for each miss (the "reason for miss" starting point).

Usage:
    python scripts/gap_analysis.py [scan_id]
If scan_id omitted, uses the most recent scan in the DB.
Only reads the DB (live pipeline is the sole writer). Never mutates findings.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database.pg_store import ScanRepo, VulnRepo  # noqa: E402

# OWASP Juice Shop canonical vulnerability classes -> (title/type keywords that
# evidence a real finding of that class, responsible probe/module). Keys mirror
# the OFFICIAL OWASP Juice Shop challenge categories (Broken Access Control,
# Broken Anti Automation, Broken Authentication, Cryptographic Issues, Improper
# Input Validation, Injection [SQL/NoSQL/RCE], Insecure Deserialization,
# Security Misconfiguration, Sensitive Data Exposure, Unvalidated Redirects,
# Vulnerable Components, XSS, XXE) plus the concrete sub-classes Juice Shop ships
# under "Miscellaneous"/input-validation (SSRF, CSRF, prototype pollution).
# Patterns are deliberately BROAD (high recall): the goal is to catch ANY finding
# of a class regardless of how the probe/LLM worded its title — especially crypto.
JS_CLASSES = {
    "injection_sql":            (r"sql\s*inject|\bsqli\b|union\s+select|'\s*or\b|\bor\s+1=1|boolean-based|time-based blind|error-based sql|sqlmap|injectable (param|point)|dbms", "sqlmap / param_fuzzer / credential_spray"),
    "injection_nosql":          (r"nosql|mongo|\$where|\$ne\b|\$gt\b|\$regex|\$exists|json operator inject|operator inject", "param_fuzzer / semantic_api_fuzzer"),
    "injection_rce_cmd":        (r"\brce\b|remote code|command inject|os command|arbitrary command|code execution|shell inject|\beval\(|template inject|\bssti\b", "custom_probe / exploit_agent / ssti_probe"),
    "xss":                      (r"\bxss\b|cross.?site.?script|reflected script|stored script|persistent xss|dom.?based|script injection|html inject|javascript inject|<script", "dom_sink_monitor / dalfox / param_fuzzer"),
    "broken_access_control":    (r"idor|bola|broken access|forced.?brows|admin endpoint|admin.*accessib|unauthor|privilege escal|access control|horizontal|vertical priv|missing function.?level|insecure direct object|missing auth(entication|orization)?|api abuse|verb override|method override|unauthenticated (api|access|endpoint|read|write)|no auth (required|check)", "authz_matrix / cross_role_replay"),
    "broken_authentication":    (r"auth(entication)? bypass|\bjwt\b|weak (pass|cred)|default cred|brute.?force|oauth|login bypass|session fixation|password reset|\b2fa\b|otp bypass|token forg|credential stuff|improper auth", "credential_spray / session_probe / hash_cracker"),
    "sensitive_data_exposure":  (r"sensitive data|info(rmation)? (leak|disclos)|data (leak|exposure)|backup file|exposed (token|key|secret|credential|password)|directory listing|\bftp\b|source ?map|verbose error|stack trace|\bpii\b|confidential|debug data", "js_bundle_analyzer / dump_extractor"),
    "security_misconfiguration":(r"misconfig|missing (security )?header|\bcors\b|clickjack|\bcsp\b|\bhsts\b|x-frame|x-content-type|metrics? expos|swagger|actuator|debug (mode|endpoint)|default (config|page|creds?)|verbose banner|directory index", "cors_probe / clickjack_probe / host_header_probe"),
    "xxe":                      (r"\bxxe\b|xml external entit|<!doctype|entity expansion|external dtd|billion laughs|xml inject", "xxe_probe"),
    "ssrf":                     (r"\bssrf\b|server.?side request|internal (url|resource|network) (fetch|access)|blind ssrf|metadata (endpoint|service)|169\.254|localhost fetch", "expert_probes / custom_probe"),
    "unvalidated_redirect":     (r"open redirect|unvalidated redirect|redirect.?to=|url redirection|forward.*unvalidat|arbitrary redirect", "open_redirect_probe"),
    "csrf":                     (r"\bcsrf\b|cross.?site request forger|\bxsrf\b|state-changing.*no token|missing anti.?csrf|no csrf (token|protection)", "expert_probes"),
    "insecure_deserialization": (r"deserial|\bpickle\b|yaml (load|deserial)|node-serialize|__proto__ gadget|marshal|unsafe object|object inject", "deserial_probe"),
    "broken_anti_automation":   (r"rate.?limit|anti.?automation|no throttl|brute.?force allowed|captcha bypass|missing (rate|throttle)|excessive request|resource exhaust|\bdos\b|flood", "rate_limit_probe / race_probe"),
    "improper_input_validation":(r"input validation|improper (input|validation)|type juggl|\bhpp\b|parameter pollution|path travers|directory travers|\blfi\b|\brfi\b|file (upload|inclusion)|zip slip|arbitrary file (write|overwrite|read)|malformed|mass assign|over.?post", "param_fuzzer / file_upload_probe / hpp_probe / mass_assign_probe"),
    "vulnerable_components":    (r"vulnerable (component|librar|dependen)|known vuln|outdated (librar|package|version|dependen)|\bcve-|component with known|end.?of.?life|deprecated (librar|version)|retire\.?js|npm audit", "nuclei / version detection"),
    "cryptographic_issues":     (r"crypto|cipher|encrypt|decrypt|weak hash|\bmd5\b|\bsha-?1\b|insecure (random|hash|cipher)|predictable (token|seed|value)|hardcoded (key|secret|iv|salt)|weak (key|algorithm|cipher|secret)|\becb\b mode|static iv|jwt (weak|none|hs256|secret)|base64.?encoded (password|secret|key)|plaintext (password|secret|storage)|insufficient entropy|broken crypto|reversible (hash|encod)|\btls\b (weak|1\.0|1\.1)|ssl(v2|v3| 2| 3)|self.?signed cert|expired cert|weak (tls|ssl|dh)|nonce reuse", "crypto_chain / hash_cracker"),
    "prototype_pollution":      (r"prototype pollution|__proto__|constructor\.prototype|proto.?chain pollut", "prototype_pollution_probe"),
}


def classify(v):
    hay = " ".join(str(v.get(k, "")) for k in
                    ("title", "type", "description", "name", "category",
                     "cwe", "owasp", "vuln_type", "evidence")).lower()
    hay = hay.replace("_", " ")  # types are snake_case (FORCED_BROWSING, jwt_kid_injection)
    hit = set()
    for cls, (pat, _probe) in JS_CLASSES.items():
        if re.search(pat, hay):
            hit.add(cls)
    return hit


def main():
    scan_id = sys.argv[1] if len(sys.argv) > 1 else None
    if not scan_id:
        scans = ScanRepo.list_all(limit=50)
        if not scans:
            print(json.dumps({"error": "no scans in DB"}))
            return 2
        scan_id = scans[0].get("scan_id") or scans[0].get("id")
    vulns = VulnRepo.get_by_scan(scan_id)

    found = set()
    per_class_counts = {c: 0 for c in JS_CLASSES}
    for v in vulns:
        for cls in classify(v):
            found.add(cls)
            per_class_counts[cls] += 1

    total = len(JS_CLASSES)
    covered = len(found)
    missing = [c for c in JS_CLASSES if c not in found]
    pct = round(100.0 * covered / total, 1) if total else 0.0

    out = {
        "scan_id": scan_id,
        "persisted_findings": len(vulns),
        "classes_total": total,
        "classes_covered": covered,
        "coverage_pct": pct,
        "target_pct": 90.0,
        "goal_met": pct >= 90.0,
        "found_classes": sorted(found),
        "missing": [{"class": c, "responsible_probe": JS_CLASSES[c][1]} for c in missing],
        "per_class_counts": {c: n for c, n in per_class_counts.items() if n},
    }
    print(json.dumps(out, indent=2))
    return 0 if out["goal_met"] else 1


if __name__ == "__main__":
    sys.exit(main())
