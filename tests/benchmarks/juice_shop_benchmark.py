"""Phase 11.1 — OWASP Juice Shop benchmark suite.

A catalog of Juice Shop challenges mapped to the executor(s) expected to find
each, plus scoring (found/total per category and overall). The scoring and
catalog are pure and unit-testable; :func:`run_benchmark` performs a live scan
and is invoked from CI against a disposable Juice Shop container (see
docker-compose.benchmark.yml), not from the normal unit-test run.

Target scores: Phase 0 → 55+, Phase 1 → 80+, Phase 4 → 95+.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Set

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BenchmarkChallenge:
    id: str
    name: str
    category: str
    difficulty: int            # 1 (easy) .. 6 (hard)
    vuln_class: str            # internal vuln class
    executor: str              # capability expected to find it


# Representative catalog spanning Juice Shop's challenge categories. Extendable
# toward the full 117; the scoring framework is catalog-size-agnostic.
JUICE_SHOP_CHALLENGES: List[BenchmarkChallenge] = [
    BenchmarkChallenge("sqli-login", "Login Admin (SQLi)", "injection", 2, "sqli", "sql_injection"),
    BenchmarkChallenge("sqli-search", "Search SQLi", "injection", 3, "sqli", "sql_injection"),
    BenchmarkChallenge("xss-dom", "DOM XSS", "xss", 1, "xss", "xss"),
    BenchmarkChallenge("xss-bonus", "API-only XSS", "xss", 3, "xss", "xss"),
    BenchmarkChallenge("broken-access-admin", "Admin Section", "broken_access_control", 2, "auth_bypass", "authorization"),
    BenchmarkChallenge("broken-access-basket", "View Basket of Others", "broken_access_control", 3, "bola", "role_escalation"),
    BenchmarkChallenge("idor-basket", "Manipulate Basket", "broken_access_control", 3, "idor", "role_escalation"),
    BenchmarkChallenge("forged-review", "Forged Review", "broken_access_control", 3, "bola", "role_escalation"),
    BenchmarkChallenge("negative-qty", "Negative Quantity", "business_logic", 3, "business_logic", "business_logic"),
    BenchmarkChallenge("coupon-abuse", "Coupon Reuse", "business_logic", 4, "business_logic", "ecommerce"),
    BenchmarkChallenge("basket-tamper", "Basket Price Tamper", "business_logic", 4, "business_logic", "ecommerce"),
    BenchmarkChallenge("jwt-forge", "Forged JWT", "broken_auth", 5, "auth_bypass", "authentication"),
    BenchmarkChallenge("weak-password", "Weak Admin Password", "broken_auth", 2, "auth_bypass", "authentication"),
    BenchmarkChallenge("reset-token", "Password Reset", "broken_auth", 4, "auth_bypass", "authentication"),
    BenchmarkChallenge("sensitive-ftp", "Confidential Document", "sensitive_data", 2, "data_leak", "authorization"),
    BenchmarkChallenge("error-info", "Error Handling", "sensitive_data", 1, "info_disclosure", "generic"),
    BenchmarkChallenge("ssrf-image", "SSRF via Image URL", "ssrf", 5, "ssrf", "ssrf"),
    BenchmarkChallenge("xxe-upload", "XXE Data Access", "xxe", 5, "xxe", "xxe"),
    BenchmarkChallenge("redirect-open", "Open Redirect", "misc", 2, "open_redirect", "generic"),
    BenchmarkChallenge("csrf-profile", "CSRF", "misc", 4, "csrf", "authorization"),
    BenchmarkChallenge("mass-assign", "Mass Assignment Role", "api", 4, "mass_assignment", "api_mass_assignment"),
    BenchmarkChallenge("deprecated-api", "Deprecated API", "api", 3, "excessive_data_exposure", "excessive_data_exposure"),
    # ── expanded corpus (toward full 117; scoring is size-agnostic) ──
    BenchmarkChallenge("xss-reflected", "Reflected XSS", "xss", 2, "xss", "xss"),
    BenchmarkChallenge("xss-persisted", "Persisted XSS (feedback)", "xss", 3, "xss", "xss"),
    BenchmarkChallenge("nosqli-review", "NoSQL Injection (reviews)", "injection", 4, "nosqli", "nosql_injection"),
    BenchmarkChallenge("nosqli-orders", "NoSQL DoS (orders)", "injection", 5, "nosqli", "nosql_injection"),
    BenchmarkChallenge("lfi-poison", "Poison Null Byte", "injection", 4, "lfi", "path_traversal"),
    BenchmarkChallenge("access-basket-checkout", "Checkout Others Basket", "broken_access_control", 4, "idor", "role_escalation"),
    BenchmarkChallenge("access-admin-registration", "Admin Registration", "broken_access_control", 3, "mass_assignment", "api_mass_assignment"),
    BenchmarkChallenge("access-user-api", "GET /api/Users", "broken_access_control", 3, "bola", "authorization"),
    BenchmarkChallenge("jwt-none", "JWT alg=none", "broken_auth", 5, "jwt_manipulation", "authentication"),
    BenchmarkChallenge("jwt-forge-hs256", "JWT Forge HS256", "broken_auth", 6, "jwt_manipulation", "authentication"),
    BenchmarkChallenge("csrf-changepw", "CSRF Change Password", "misc", 4, "csrf", "authorization"),
    BenchmarkChallenge("redirect-crypto", "Redirect Crypto Currency", "misc", 3, "open_redirect", "generic"),
    BenchmarkChallenge("cors-misconfig", "CORS Misconfiguration", "misc", 3, "cors_misconfiguration", "cors"),
    BenchmarkChallenge("headers-missing", "Security Headers", "misc", 1, "misconfiguration", "generic"),
    BenchmarkChallenge("cookie-insecure", "Insecure Cookie Flags", "misc", 1, "misconfiguration", "generic"),
    BenchmarkChallenge("clickjack", "Clickjacking", "misc", 2, "clickjacking", "generic"),
    BenchmarkChallenge("sensitive-backup", "Access Backup File", "sensitive_data", 3, "info_disclosure", "authorization"),
    BenchmarkChallenge("sensitive-metrics", "Exposed Metrics", "sensitive_data", 2, "info_disclosure", "generic"),
    BenchmarkChallenge("api-bola-products", "BOLA Product IDs", "api", 3, "idor", "authorization"),
    BenchmarkChallenge("api-method-tamper", "API Method Tampering", "api", 3, "api_abuse", "api_abuse"),
    BenchmarkChallenge("deserial-node", "Insecure Deserialization", "injection", 6, "rce", "command_injection"),
    BenchmarkChallenge("ssti-server", "SSTI", "injection", 5, "ssti", "ssti"),
    BenchmarkChallenge("upload-malicious", "Upload Malicious File", "api", 4, "file_upload", "file_upload"),
    BenchmarkChallenge("rate-limit-reset", "No Rate Limit on Reset", "broken_auth", 3, "credential_brute_force", "authentication"),
]


def categories() -> Set[str]:
    return {c.category for c in JUICE_SHOP_CHALLENGES}


def executors_for_category(category: str) -> Set[str]:
    return {c.executor for c in JUICE_SHOP_CHALLENGES if c.category == category}


def score_results(found_ids: Iterable[str],
                  catalog: List[BenchmarkChallenge] = None) -> Dict[str, Any]:
    """Score a set of solved challenge ids against the catalog."""
    catalog = catalog or JUICE_SHOP_CHALLENGES
    found = set(found_ids)
    per_category: Dict[str, Dict[str, int]] = {}
    for ch in catalog:
        bucket = per_category.setdefault(ch.category, {"found": 0, "total": 0})
        bucket["total"] += 1
        if ch.id in found:
            bucket["found"] += 1
    total = len(catalog)
    solved = sum(1 for ch in catalog if ch.id in found)
    score = round(solved / total * 100, 1) if total else 0.0
    return {
        "score": score, "solved": solved, "total": total,
        "per_category": {k: {**v, "pct": round(v["found"] / v["total"] * 100, 1)}
                         for k, v in per_category.items()},
    }


def run_benchmark(target: str = "http://localhost:3000") -> Dict[str, Any]:  # pragma: no cover
    """Live run: scan the target, map findings back to solved challenges, score.
    Invoked by CI against a Juice Shop container — needs a real scan pipeline."""
    from tests.benchmarks._scan_adapter import scan_and_collect_findings, findings_to_challenge_ids
    findings = scan_and_collect_findings(target)
    solved = findings_to_challenge_ids(findings, JUICE_SHOP_CHALLENGES)
    return score_results(solved)
