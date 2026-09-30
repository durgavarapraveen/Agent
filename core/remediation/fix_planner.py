"""FixPlanner (D-1) — attach a concrete, actionable remediation plan to each
confirmed finding.

Design goals:
  * Non-destructive: produce guidance only; never touch the target, never apply
    a patch. (Auto-apply is out of scope by policy.)
  * LLM-driven where available (finding-specific fix + optional code patch when
    source is provided), with a deterministic per-class fallback so the stage
    works with no LLM configured.
  * Bounded: cap LLM calls per scan; dedupe by (type, endpoint) so identical
    classes on many endpoints don't each spend a call.
  * Fail-safe: any error leaves the finding untouched (never breaks reporting).

Output: sets ``finding["remediation_plan"]`` =
    {root_cause, fix, code_patch?, config_change?, verification, references, effort}
and mirrors a short human string into ``finding["remediation"]`` for reporters
that read that field.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Deterministic fallback plans, keyed by a normalized vuln-class substring. Each
# gives a real, class-correct fix + how to verify it. Used when no LLM is
# available or the LLM call fails. Not exhaustive — a generic default backs it.
_FALLBACK_PLANS: Dict[str, Dict[str, Any]] = {
    "SQLI": {
        "root_cause": "User input is concatenated into a SQL query, so it is parsed as SQL.",
        "fix": "Use parameterized queries / prepared statements for every query; never build SQL by string concatenation. Apply least-privilege DB accounts.",
        "verification": "Re-run the injection payloads; confirm they are treated as literal data (no DB error, no boolean/time divergence).",
        "references": ["CWE-89", "OWASP A03:2021-Injection"],
    },
    "XSS": {
        "root_cause": "Untrusted input is reflected/stored and rendered without context-correct output encoding.",
        "fix": "Context-encode output (HTML/attr/JS/URL); prefer framework auto-escaping; add a strict Content-Security-Policy; set HttpOnly on session cookies.",
        "verification": "Re-inject the canary; confirm it renders inert (encoded) and does not execute.",
        "references": ["CWE-79", "OWASP A03:2021-Injection"],
    },
    "SSTI": {
        "root_cause": "User input reaches a server-side template engine and is evaluated as a template expression.",
        "fix": "Never pass user input as a template; use a logic-less/sandboxed template and pass data as bound variables only.",
        "verification": "Re-send the template-expression payload; confirm it is echoed literally, not evaluated.",
        "references": ["CWE-1336", "OWASP A03:2021-Injection"],
    },
    "RCE": {
        "root_cause": "User input flows into a shell/eval/deserialization sink executed by the server.",
        "fix": "Remove the dynamic-execution sink; use safe APIs with argument arrays (no shell); allow-list commands; patch the vulnerable component.",
        "verification": "Re-run the command payload with an OOB canary; confirm no callback and no command output in the response.",
        "references": ["CWE-78", "CWE-94"],
    },
    "LFI": {
        "root_cause": "A file path is built from user input without canonicalization/allow-listing.",
        "fix": "Resolve to a canonical path and verify it stays within an allowed base dir; use an allow-list of file ids, not raw paths.",
        "verification": "Re-send traversal payloads; confirm no file contents are returned.",
        "references": ["CWE-22", "CWE-98"],
    },
    "SSRF": {
        "root_cause": "The server fetches a URL derived from user input without egress restriction.",
        "fix": "Allow-list destination hosts/schemes; block link-local/metadata/private ranges; resolve+validate the IP after DNS; disable redirects to internal hosts.",
        "verification": "Re-send SSRF payloads to metadata/internal targets; confirm the request is blocked (no OOB callback, no internal content).",
        "references": ["CWE-918", "OWASP A10:2021-SSRF"],
    },
    "XXE": {
        "root_cause": "The XML parser resolves external entities on untrusted input.",
        "fix": "Disable DTDs and external-entity resolution in the XML parser; prefer JSON where possible.",
        "verification": "Re-send the entity payload; confirm no file/OOB content is returned.",
        "references": ["CWE-611"],
    },
    "IDOR": {
        "root_cause": "An object is accessed by a client-supplied id with no per-object authorization check.",
        "fix": "Enforce object-level authorization on every access (ownership/ACL check server-side); use unguessable ids as defense-in-depth only.",
        "verification": "Repeat the cross-user access as each identity; confirm access to another user's object is denied (401/403).",
        "references": ["CWE-639", "OWASP A01:2021-Broken Access Control"],
    },
    "BOLA": {
        "root_cause": "API object access lacks per-object authorization (Broken Object Level Authorization).",
        "fix": "Check ownership/permission for the referenced object on every API call, server-side.",
        "verification": "Replay with a different identity; confirm cross-tenant access is refused.",
        "references": ["OWASP API1:2023-BOLA", "CWE-639"],
    },
    "CSRF": {
        "root_cause": "A state-changing request is accepted without an anti-CSRF token / SameSite protection.",
        "fix": "Require a per-session anti-CSRF token verified server-side on state-changing requests; set SameSite=Lax/Strict on session cookies; require a custom header on JSON APIs.",
        "verification": "Replay the state-changing request cross-site without the token; confirm it is rejected.",
        "references": ["CWE-352", "OWASP A01:2021"],
    },
    "JWT": {
        "root_cause": "JWT verification accepts a forged token (alg=none / stripped signature / weak secret).",
        "fix": "Pin the expected algorithm; reject alg=none and unsigned tokens; use a strong random secret or asymmetric keys; verify signature+claims server-side.",
        "verification": "Re-send alg=none / weak-secret tokens; confirm they are rejected (401).",
        "references": ["CWE-347"],
    },
    "MASS_ASSIGNMENT": {
        "root_cause": "Request bodies are bound to internal model fields without an allow-list.",
        "fix": "Bind only an explicit allow-list of fields; never auto-bind role/privilege/ownership attributes.",
        "verification": "Re-send the extra privileged field; confirm it is ignored (no privilege change).",
        "references": ["CWE-915", "OWASP API6:2023"],
    },
    "OPEN_REDIRECT": {
        "root_cause": "A redirect target is taken from user input without validation.",
        "fix": "Redirect only to an allow-list of relative paths / known hosts; reject absolute external URLs.",
        "verification": "Re-send an external redirect target; confirm the redirect is refused or rewritten.",
        "references": ["CWE-601"],
    },
    "MISSING_HEADER": {
        "root_cause": "Response is missing a hardening HTTP security header.",
        "fix": "Set the missing headers at the edge/app: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options=nosniff, X-Frame-Options=DENY (or CSP frame-ancestors).",
        "verification": "Re-request the page; confirm the headers are present with hardened values.",
        "references": ["OWASP Secure Headers Project"],
    },
    "TLS": {
        "root_cause": "The server negotiates deprecated protocols/ciphers.",
        "fix": "Disable SSLv2/SSLv3/TLS<1.2 and weak ciphers; enable HSTS; keep the TLS stack patched.",
        "verification": "Re-scan TLS; confirm only strong protocols/ciphers are offered.",
        "references": ["CWE-327"],
    },
}

_DEFAULT_PLAN = {
    "root_cause": "Untrusted input or a misconfiguration allows behavior outside the intended security policy.",
    "fix": "Validate/encode input at the trust boundary, enforce authorization server-side, apply least privilege, and patch affected components.",
    "verification": "Re-run the exact reproduction steps and confirm the payload no longer succeeds.",
    "references": ["OWASP Top 10"],
}

# Effort estimate (person-hours, rough) by class family.
_EFFORT = {
    "MISSING_HEADER": 1, "TLS": 2, "OPEN_REDIRECT": 3, "CSRF": 4, "JWT": 6,
    "IDOR": 8, "BOLA": 8, "MASS_ASSIGNMENT": 6, "XSS": 8, "SSRF": 8,
    "LFI": 8, "XXE": 6, "SSTI": 12, "SQLI": 12, "RCE": 16,
}

_SYSTEM = (
    "You are a senior application security engineer writing remediation guidance "
    "for a CONFIRMED vulnerability found during an AUTHORIZED penetration test. "
    "Produce a precise, correct, minimal fix. If source code is provided, propose "
    "an exact patch. Never invent facts about the target."
)


# Long-form / OWASP names → the compact _FALLBACK_PLANS keys, so a finding typed
# or titled "SQL Injection" / "Broken Access Control" still gets the right plan.
_CLASS_ALIASES = {
    "SQL_INJECTION": "SQLI", "SQLINJECTION": "SQLI",
    "CROSS_SITE_SCRIPTING": "XSS",
    "COMMAND_INJECTION": "RCE", "OS_COMMAND": "RCE", "REMOTE_CODE": "RCE",
    "CODE_INJECTION": "RCE",
    "PATH_TRAVERSAL": "LFI", "DIRECTORY_TRAVERSAL": "LFI", "FILE_INCLUSION": "LFI",
    "SERVER_SIDE_REQUEST_FORGERY": "SSRF", "SERVER_SIDE_REQUEST": "SSRF",
    "BROKEN_OBJECT_LEVEL": "BOLA",
    "INSECURE_DIRECT_OBJECT": "IDOR", "BROKEN_ACCESS_CONTROL": "IDOR",
    "SECURITY_HEADER": "MISSING_HEADER", "MISSING_SECURITY_HEADERS": "MISSING_HEADER",
    "TLS_WEAKNESS": "TLS", "SSL_ISSUE": "TLS",
    "BUSINESS_LOGIC": "IDOR",
}


def _norm_class(finding: Dict[str, Any]) -> str:
    t = (finding.get("type") or finding.get("attack_type") or finding.get("vuln_type")
         or finding.get("category") or finding.get("title") or "").upper()
    return t.replace(" ", "_").replace("-", "_")


def _fallback_plan(finding: Dict[str, Any]) -> Dict[str, Any]:
    cls = _norm_class(finding)
    chosen = None
    for key, plan in _FALLBACK_PLANS.items():
        if key in cls:
            chosen = plan
            break
    if chosen is None:  # try long-form aliases before dropping to the default
        for alias, canonical in _CLASS_ALIASES.items():
            if alias in cls and canonical in _FALLBACK_PLANS:
                chosen = _FALLBACK_PLANS[canonical]
                break
    plan = dict(chosen or _DEFAULT_PLAN)
    # effort by family match (direct key, then long-form alias)
    effort = None
    for key, hrs in _EFFORT.items():
        if key in cls:
            effort = hrs
            break
    if effort is None:
        for alias, canonical in _CLASS_ALIASES.items():
            if alias in cls and canonical in _EFFORT:
                effort = _EFFORT[canonical]
                break
    plan["effort_hours"] = effort if effort is not None else 4
    plan["source"] = "fallback"
    return plan


class FixPlanner:
    def __init__(self, llm=None, max_llm_calls: int = 25):
        self.llm = llm
        self.max_llm_calls = max_llm_calls

    def _worth_fixing(self, f: Dict[str, Any]) -> bool:
        if f.get("remediation_plan"):
            return False  # already planned
        sev = str(f.get("severity", "")).upper()
        status = str(f.get("status", "")).upper()
        return status == "CONFIRMED" or sev in ("CRITICAL", "HIGH", "MEDIUM")

    async def _llm_plan(self, finding: Dict[str, Any], source_snippet: str) -> Optional[Dict[str, Any]]:
        if self.llm is None or not hasattr(self.llm, "generate_json"):
            return None
        proof = finding.get("proof") or finding.get("evidence") or finding.get("details") or ""
        if isinstance(proof, (dict, list)):
            proof = json.dumps(proof, default=str)
        prompt = (
            "Return STRICT JSON with keys: root_cause, fix, code_patch (\"\" if no "
            "source given), config_change (\"\" if n/a), verification, references "
            "(array of CWE/OWASP ids), effort_hours (int). Fix the following "
            "CONFIRMED vulnerability.\n\n"
            f"type: {finding.get('type')}\n"
            f"title: {finding.get('title')}\n"
            f"location: {finding.get('location') or finding.get('target')}\n"
            f"severity: {finding.get('severity')}\n"
            f"evidence: {str(proof)[:800]}\n"
            + (f"\nRELEVANT SOURCE (propose an exact patch):\n{source_snippet[:2500]}\n" if source_snippet else "")
        )
        try:
            resp = await self.llm.generate_json(prompt, system=_SYSTEM, max_tokens=900)
        except TypeError:
            # harness variants without a `system=` kwarg
            resp = await self.llm.generate_json(prompt, max_tokens=900)
        except Exception as e:
            logger.debug("[FixPlanner] LLM plan failed: %s", e)
            return None
        if not isinstance(resp, dict) or not resp.get("fix"):
            return None
        refs = resp.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        return {
            "root_cause": str(resp.get("root_cause", ""))[:1000],
            "fix": str(resp.get("fix", ""))[:2000],
            "code_patch": str(resp.get("code_patch", ""))[:4000],
            "config_change": str(resp.get("config_change", ""))[:1500],
            "verification": str(resp.get("verification", ""))[:1000],
            "references": [str(r) for r in refs][:10],
            "effort_hours": int(resp.get("effort_hours", 0) or 0) or _fallback_plan(finding)["effort_hours"],
            "source": "llm",
        }

    async def enrich(self, findings: List[Dict[str, Any]], ctx=None,
                     source_snippet: str = "") -> int:
        """Attach a remediation_plan to each worth-fixing finding. Returns count.
        Deterministic fallback guarantees a plan even without an LLM. Bounded LLM
        spend; identical (class,endpoint) reuse one plan."""
        if not findings:
            return 0
        planned = 0
        llm_used = 0
        llm_attempts = 0  # count ATTEMPTS, not successes, so a degraded LLM can't
                          # blow past the cap by returning empty for every finding.
        cache: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            try:
                if not isinstance(f, dict) or not self._worth_fixing(f):
                    continue
                key = f"{_norm_class(f)}|{(f.get('location') or f.get('target') or '').split('?')[0]}"
                plan = cache.get(key)
                if plan is None:
                    plan = None
                    if llm_attempts < self.max_llm_calls:
                        llm_attempts += 1
                        plan = await self._llm_plan(f, source_snippet)
                        if plan is not None:
                            llm_used += 1
                    if plan is None:
                        plan = _fallback_plan(f)
                    cache[key] = plan
                f["remediation_plan"] = plan
                # mirror a short human string for reporters that read `remediation`
                if not f.get("remediation"):
                    f["remediation"] = plan.get("fix", "")
                planned += 1
            except Exception as e:
                logger.debug("[FixPlanner] enrich skipped a finding: %s", e)
                continue
        if planned:
            logger.info("[FixPlanner] attached remediation to %d finding(s) (%d via LLM, %d fallback)",
                        planned, llm_used, planned - llm_used)
        return planned


_planner: Optional[FixPlanner] = None


def get_fix_planner(llm=None) -> FixPlanner:
    global _planner
    if _planner is None or (llm is not None and _planner.llm is None):
        _planner = FixPlanner(llm=llm)
    return _planner
