from __future__ import annotations

import json
import logging
import os
from typing import List, Optional

import psycopg2.extras

from core.memory.database import DatabaseManager
from core.payloads.schema import InjectionContext, Payload
from core.payloads.seeds import SEED_PAYLOADS

logger = logging.getLogger(__name__)

# Single-file payload bundle (all PayloadsAllTheThings payloads, normalized).
# Built once via scripts/build_payload_bundle.py; loaded on first use so the
# catalog is fully populated offline without the repo or markdown re-parsing.
_BUNDLE_PATH = os.getenv("PAYLOAD_BUNDLE_PATH",
                         os.path.join("data", "payloads", "patt_bundle.jsonl"))

_FP_THRESHOLD = 0.3

# Default severity per class for ingested payloads lacking their own.
_CLASS_SEVERITY = {
    "rce": "CRITICAL", "sqli": "HIGH", "ssti": "HIGH", "ssrf": "HIGH",
    "xxe": "HIGH", "lfi": "HIGH", "idor": "HIGH", "auth_bypass": "HIGH",
    "jwt_manipulation": "HIGH", "file_upload": "HIGH", "prototype_pollution": "HIGH",
    "http_smuggling": "HIGH", "mass_assignment": "HIGH", "secret_exposure": "HIGH",
    "xss": "MEDIUM", "nosqli": "HIGH", "open_redirect": "MEDIUM",
    "cors_misconfiguration": "MEDIUM", "csrf": "MEDIUM", "race_condition": "HIGH",
    "cache_poisoning": "MEDIUM", "host_header_injection": "MEDIUM",
    "email_injection": "MEDIUM", "graphql_introspection": "LOW",
    "websocket_hijacking": "MEDIUM", "api_abuse": "LOW",
    "dependency_vulnerability": "MEDIUM",
    # §7 distinct categories
    "ldap_injection": "HIGH", "xpath_injection": "HIGH", "xslt_injection": "HIGH",
    "ssi_injection": "HIGH", "latex_injection": "MEDIUM", "css_injection": "LOW",
    "dom_clobbering": "MEDIUM", "crlf_injection": "MEDIUM", "type_juggling": "HIGH",
    "orm_leak": "MEDIUM", "client_side_path_traversal": "MEDIUM", "zip_slip": "HIGH",
    "prompt_injection": "HIGH", "dns_rebinding": "HIGH", "saml_injection": "HIGH",
    "xs_leak": "LOW", "csv_injection": "LOW", "insecure_randomness": "MEDIUM",
    "insecure_management_interface": "HIGH", "google_web_toolkit": "LOW",
    "virtual_hosts": "MEDIUM", "reverse_proxy_misconfig": "MEDIUM", "redos": "MEDIUM",
    "denial_of_service": "MEDIUM", "account_takeover": "CRITICAL",
    "oauth_misconfiguration": "HIGH", "web_cache_deception": "MEDIUM",
    "request_smuggling": "HIGH", "dependency_confusion": "HIGH",
    "tabnabbing": "LOW", "http_parameter_pollution": "MEDIUM",
}


class PayloadCatalog:
    """Postgres-backed payload store with context-aware selection + feedback.

    Payloads live in the ``payloads`` table (see pg_store._init_schema). A small
    built-in seed set is upserted on first use so selection works before any
    external source (nuclei / PayloadsAllTheThings) has been ingested.
    """

    def __init__(self, auto_seed: bool = True):
        self._seeded = False
        if auto_seed:
            try:
                self.ensure_seeded()
            except Exception as e:
                logger.warning("Payload seed skipped (DB unavailable?): %s", e)

    # ── Ingestion ──────────────────────────────────────────────────────
    def upsert(self, payloads: List[Payload]) -> int:
        rows = []
        for p in payloads:
            d = p.to_dict()
            rows.append((
                d["payload_id"], d["vuln_class"], d["subclass"], d["context"],
                d["payload_text"], d["encoding"], d["evasion_tags"], d["source"],
                d["effectiveness_score"], d["false_positive_rate"], d["waf_bypass_for"],
                d["confirm_patterns"], d["severity"], d["times_used"], d["times_confirmed"],
            ))
        if not rows:
            return 0
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                psycopg2.extras.execute_values(
                    cur,
                    """
                    INSERT INTO payloads
                        (payload_id, vuln_class, subclass, context, payload_text,
                         encoding, evasion_tags, source, effectiveness_score,
                         false_positive_rate, waf_bypass_for, confirm_patterns,
                         severity, times_used, times_confirmed)
                    VALUES %s
                    ON CONFLICT (payload_id) DO UPDATE SET
                        effectiveness_score = EXCLUDED.effectiveness_score,
                        false_positive_rate = EXCLUDED.false_positive_rate,
                        waf_bypass_for = EXCLUDED.waf_bypass_for,
                        confirm_patterns = EXCLUDED.confirm_patterns,
                        last_updated = NOW()
                    """,
                    rows,
                    template="(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                )
            conn.commit()
        return len(rows)

    def ensure_seeded(self) -> None:
        if self._seeded:
            return
        # Prefer the full PATT bundle if present; fall back to the tiny seed set.
        if os.path.exists(_BUNDLE_PATH):
            try:
                n = self.load_bundle(_BUNDLE_PATH)
                logger.info("Payload catalog loaded %d payloads from bundle %s", n, _BUNDLE_PATH)
                self._seeded = True
                return
            except Exception as e:
                logger.warning("Bundle load failed (%s); falling back to seed set", e)
        self.upsert(SEED_PAYLOADS)
        self._seeded = True

    def load_bundle(self, path: str) -> int:
        """Load a normalized JSONL payload bundle (one Payload dict per line)."""
        payloads: List[Payload] = []
        loaded = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    payloads.append(Payload.from_dict(json.loads(line)))
                except Exception:
                    continue
                if len(payloads) >= 2000:  # batch upserts
                    loaded += self.upsert(payloads)
                    payloads = []
        if payloads:
            loaded += self.upsert(payloads)
        return loaded

    def export_bundle(self, path: str) -> int:
        """Dump the current DB payloads to a single JSONL bundle file."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        n = 0
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM payloads")
                rows = cur.fetchall()
        with open(path, "w", encoding="utf-8") as f:
            for r in rows:
                d = dict(r)
                d.pop("last_updated", None)
                f.write(json.dumps(Payload.from_dict(d).to_dict(), ensure_ascii=False) + "\n")
                n += 1
        return n

    def ingest_custom_yaml(self, yaml_path: str) -> int:
        """Load custom payloads from a YAML file. Schema:
        vuln_class / subclass / context / severity + payloads: [{text, ...}]."""
        try:
            import yaml
        except ImportError:
            logger.warning("PyYAML not installed; cannot ingest %s", yaml_path)
            return 0
        with open(yaml_path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        vc = doc.get("vuln_class", "")
        subclass = doc.get("subclass", "")
        context = doc.get("context", "url")
        sev = doc.get("severity", "MEDIUM")
        payloads = []
        for entry in doc.get("payloads", []):
            if isinstance(entry, str):
                text, cp, es = entry, [], sev
            else:
                text = entry.get("text", "")
                cp = entry.get("confirm_patterns", [])
                es = entry.get("severity", sev)
            if not text:
                continue
            payloads.append(Payload(vuln_class=vc, payload_text=text, subclass=subclass,
                                    context=entry.get("context", context) if isinstance(entry, dict) else context,
                                    confirm_patterns=cp, severity=es, source="custom"))
        return self.upsert(payloads)

    def ingest_nuclei_templates(self, templates_dir: str) -> int:
        """Parse nuclei YAML templates -> Payload objects. Best-effort:
        extracts info.severity + matchers.words as confirm_patterns + any
        payloads/fuzzing entries. Returns count upserted."""
        import os
        try:
            import yaml
        except ImportError:
            logger.warning("PyYAML not installed; cannot ingest nuclei templates")
            return 0
        found: List[Payload] = []
        for root, _, files in os.walk(templates_dir):
            for fn in files:
                if not fn.endswith((".yaml", ".yml")):
                    continue
                try:
                    with open(os.path.join(root, fn), "r", encoding="utf-8") as f:
                        tpl = yaml.safe_load(f) or {}
                except Exception:
                    continue
                info = tpl.get("info", {})
                sev = str(info.get("severity", "medium")).upper()
                tags = info.get("tags", "")
                vc = self._infer_class(str(tags) + " " + fn)
                confirm = []
                for block in _iter_matchers(tpl):
                    confirm += block.get("words", []) or block.get("regex", []) or []
                for pl in _iter_payloads(tpl):
                    found.append(Payload(vuln_class=vc, payload_text=str(pl),
                                         source="nuclei", severity=sev,
                                         confirm_patterns=[str(c) for c in confirm[:5]]))
        return self.upsert(found)

    # Full PayloadsAllTheThings top-level dir -> our vuln_class taxonomy.
    # Every payload-bearing directory is mapped to a class the OracleEngine can
    # confirm, so ingested payloads are both stored AND testable. Non-payload
    # dirs (Methodology, _template_vuln, Headless Browser, .git ...) are omitted.
    # Each PATT category maps to a DISTINCT vuln_class the OracleEngine can
    # confirm (§7 "every category is a capability"). Classes with no ingested
    # payloads of their own fall back to a related base class at select() time
    # (see _CLASS_FALLBACK) so a category is testable immediately and cleanly
    # once the bundle is rebuilt with distinct classes.
    _PATT_DIR_MAP = {
        # ── injection ──
        "sql injection": "sqli", "nosql injection": "nosqli",
        "ldap injection": "ldap_injection", "xpath injection": "xpath_injection",
        "xss injection": "xss", "css injection": "css_injection", "dom clobbering": "dom_clobbering",
        "server side template injection": "ssti", "server side include injection": "ssi_injection",
        "latex injection": "latex_injection", "xslt injection": "xslt_injection",
        "command injection": "rce", "insecure deserialization": "rce", "java rmi": "rce",
        "prompt injection": "prompt_injection",
        "server side request forgery": "ssrf", "dns rebinding": "dns_rebinding",
        "xxe injection": "xxe",
        # ── traversal / inclusion ──
        "file inclusion": "lfi", "directory traversal": "lfi",
        "client side path traversal": "client_side_path_traversal", "zip slip": "zip_slip",
        # ── redirect / client ──
        "open redirect": "open_redirect", "tabnabbing": "tabnabbing",
        "oauth misconfiguration": "oauth_misconfiguration",
        # ── headers / smuggling / cache ──
        "cors misconfiguration": "cors_misconfiguration",
        "crlf injection": "crlf_injection",
        "request smuggling": "request_smuggling",
        "web cache deception": "web_cache_deception",
        "http parameter pollution": "http_parameter_pollution",
        "virtual hosts": "virtual_hosts", "reverse proxy misconfigurations": "reverse_proxy_misconfig",
        # ── auth / identity ──
        "insecure direct object references": "idor",
        "json web token": "jwt_manipulation", "saml injection": "saml_injection",
        "cross-site request forgery": "csrf", "csrf injection": "csrf",
        "account takeover": "account_takeover",
        "brute force rate limit": "credential_brute_force",
        # ── data / logic ──
        "mass assignment": "mass_assignment", "external variable modification": "mass_assignment",
        "prototype pollution": "prototype_pollution",
        "race condition": "race_condition",
        "business logic errors": "business_logic_bypass",
        "type juggling": "type_juggling", "orm leak": "orm_leak",
        "graphql injection": "graphql_introspection",
        # ── files / api ──
        "upload insecure files": "file_upload",
        "web sockets": "websocket_hijacking",
        "denial of service": "denial_of_service", "regular expression": "redos",
        "hidden parameters": "api_abuse",
        "dependency confusion": "dependency_confusion", "cve exploits": "dependency_vulnerability",
        # ── disclosure / misconfig / crypto ──
        "api key leaks": "secret_exposure",
        "insecure source code management": "information_disclosure",
        "xs-leak": "xs_leak", "csv injection": "csv_injection",
        "insecure randomness": "insecure_randomness",
        "insecure management interface": "insecure_management_interface",
        "google web toolkit": "google_web_toolkit", "clickjacking": "clickjacking",
    }

    # Distinct §7 class → base class whose ingested payloads to reuse when the
    # distinct class has none yet. Keeps payloads = DATA (still from catalog).
    _CLASS_FALLBACK = {
        "ldap_injection": "sqli", "xpath_injection": "sqli", "type_juggling": "sqli",
        "orm_leak": "sqli", "xslt_injection": "ssti", "latex_injection": "ssti",
        "ssi_injection": "ssti", "css_injection": "xss", "dom_clobbering": "xss",
        "crlf_injection": "email_injection", "client_side_path_traversal": "lfi",
        "zip_slip": "lfi", "prompt_injection": "rce", "dns_rebinding": "ssrf",
        "saml_injection": "jwt_manipulation", "xs_leak": "information_disclosure",
        "csv_injection": "information_disclosure", "insecure_randomness": "weak_crypto",
        "insecure_management_interface": "misconfiguration",
        "google_web_toolkit": "misconfiguration", "virtual_hosts": "host_header_injection",
        "reverse_proxy_misconfig": "host_header_injection", "redos": "api_abuse",
        "denial_of_service": "api_abuse", "account_takeover": "auth_bypass",
        "oauth_misconfiguration": "open_redirect", "web_cache_deception": "cache_poisoning",
        "request_smuggling": "http_smuggling", "dependency_confusion": "dependency_vulnerability",
        "tabnabbing": "open_redirect", "http_parameter_pollution": "xss",
    }

    def ingest_payloads_all_the_things(self, repo_dir: str) -> int:
        """Ingest ALL payloads from a PayloadsAllTheThings checkout.

        Maps every top-level directory to a vuln_class, then extracts payloads
        from each markdown file in three formats: fenced ``` code blocks
        (multi-line joined per fence, or per-line for list-style fences),
        inline `code` spans, and pipe-table cells. Deduped by payload_id.
        """
        import os
        import re
        found: List[Payload] = []
        seen_texts = set()

        def emit(vc: str, sev: str, text: str):
            text = text.strip()
            if not (3 <= len(text) <= 400):
                return
            if text in seen_texts:
                return
            if not _looks_like_payload(text):
                return
            seen_texts.add(text)
            found.append(Payload(vuln_class=vc, payload_text=text,
                                 source="payloadsallthethings", severity=sev))

        for root, _, files in os.walk(repo_dir):
            rel = os.path.relpath(root, repo_dir).split(os.sep)[0].lower()
            vc = self._PATT_DIR_MAP.get(rel)
            if not vc:
                continue
            sev = _CLASS_SEVERITY.get(vc, "MEDIUM")
            for fn in files:
                if not fn.lower().endswith(".md"):
                    continue
                try:
                    with open(os.path.join(root, fn), "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                # 1. fenced code blocks
                for block in re.findall(r"```[a-zA-Z0-9]*\n(.*?)```", content, re.DOTALL):
                    lines = [l for l in block.splitlines() if l.strip()]
                    structured = any(mk in block for mk in
                                     ("<?xml", "<!DOCTYPE", "<!ENTITY", "{%", "SOAP", "<soap"))
                    if structured:  # multi-line payload (XXE/SSTI/SOAP blob) -> one
                        emit(vc, sev, block.strip())
                    elif len(lines) > 1 and all(len(l) <= 200 for l in lines):
                        for l in lines:  # list-style fence -> one payload per line
                            emit(vc, sev, l)
                    else:
                        emit(vc, sev, block.strip())
                # 2. inline code spans
                for m in re.findall(r"`([^`\n]{3,200})`", content):
                    emit(vc, sev, m)
                # 3. table cells wrapped in backticks already caught; plain cells:
                for row in re.findall(r"^\|(.+)\|$", content, re.MULTILINE):
                    for cell in row.split("|"):
                        cell = cell.strip().strip("`")
                        if any(c in cell for c in "<>{}$';\"()") and " " not in cell[:1]:
                            emit(vc, sev, cell)
        return self.upsert(found)

    @staticmethod
    def _infer_class(text: str) -> str:
        t = text.lower()
        for key, vc in (("sqli", "sqli"), ("sql", "sqli"), ("xss", "xss"),
                        ("ssrf", "ssrf"), ("ssti", "ssti"), ("xxe", "xxe"),
                        ("lfi", "lfi"), ("rce", "rce"), ("redirect", "open_redirect"),
                        ("cors", "cors_misconfiguration")):
            if key in t:
                return vc
        return "misconfiguration"

    # ── Selection ──────────────────────────────────────────────────────
    def select(self, vuln_class: str, context: Optional[InjectionContext] = None,
               waf: Optional[str] = None, tech_stack: List[str] = None,
               budget: int = 20) -> List[Payload]:
        ctx_name = context.context if context else None
        tech_stack = [t.lower() for t in (tech_stack or [])]
        with DatabaseManager.get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                sql = ["SELECT * FROM payloads WHERE vuln_class = %s",
                       "AND false_positive_rate <= %s"]
                params: list = [vuln_class.lower(), _FP_THRESHOLD]
                if ctx_name:
                    sql.append("AND (context = %s OR context = 'url')")
                    params.append(ctx_name)
                if waf and waf.lower() != "none":
                    # exclude payloads known to be blocked by this WAF
                    sql.append("AND NOT (%s = ANY(waf_bypass_for) IS NOT TRUE AND %s = ANY(evasion_tags))")
                    params += [waf.lower(), f"blocked:{waf.lower()}"]
                sql.append("ORDER BY effectiveness_score DESC, times_confirmed DESC")
                unlimited = budget is None or budget <= 0
                if not unlimited:
                    sql.append("LIMIT %s")
                    params.append(max(budget * 3, budget))
                cur.execute(" ".join(sql), params)
                rows = [Payload.from_dict(dict(r)) for r in cur.fetchall()]
        # §7: distinct category with no own payloads yet → reuse a base class's
        # payloads (payloads stay DATA from the catalog; only the routing falls back).
        if not rows:
            fb = self._CLASS_FALLBACK.get(vuln_class.lower())
            if fb and fb != vuln_class.lower():
                return self.select(fb, context, waf=waf, tech_stack=tech_stack, budget=budget)
        # tech-stack boost (in-memory rerank), then trim to budget (unlimited -> all)
        if tech_stack:
            def boost(p: Payload) -> float:
                tags = " ".join(p.evasion_tags + [p.subclass]).lower()
                return p.effectiveness_score + (0.2 if any(t in tags for t in tech_stack) else 0)
            rows.sort(key=boost, reverse=True)
        return rows if (budget is None or budget <= 0) else rows[:budget]

    def texts_for(self, vuln_class: str, context: str = "url", budget: int = 30,
                  waf: Optional[str] = None, tech_stack: List[str] = None) -> List[str]:
        """Convenience for migrated probes: ranked raw payload strings for a class.
        Empty list if DB/bundle unavailable (caller decides how to handle)."""
        try:
            ic = InjectionContext(endpoint="", parameter="", context=context)
            return [p.payload_text for p in self.select(vuln_class, ic, waf=waf,
                                                         tech_stack=tech_stack, budget=budget)]
        except Exception as e:
            logger.debug("texts_for(%s) failed: %s", vuln_class, e)
            return []

    # ── Feedback ───────────────────────────────────────────────────────
    def record_outcome(self, payload_id: str, confirmed: bool,
                       waf_blocked: bool = False) -> None:
        """Bayesian-ish effectiveness update from a scan result.
        confirmed -> score up; unconfirmed+not-blocked -> score down;
        unconfirmed+waf_blocked -> score unchanged (WAF, not the payload)."""
        with DatabaseManager.get_connection() as conn:
            with conn.cursor() as cur:
                if confirmed:
                    cur.execute(
                        """UPDATE payloads SET
                             times_used = times_used + 1,
                             times_confirmed = times_confirmed + 1,
                             effectiveness_score = LEAST(1.0, effectiveness_score + 0.05),
                             last_updated = NOW()
                           WHERE payload_id = %s""", (payload_id,))
                elif waf_blocked:
                    cur.execute(
                        """UPDATE payloads SET times_used = times_used + 1,
                             last_updated = NOW() WHERE payload_id = %s""", (payload_id,))
                else:
                    cur.execute(
                        """UPDATE payloads SET
                             times_used = times_used + 1,
                             effectiveness_score = GREATEST(0.0, effectiveness_score - 0.02),
                             false_positive_rate = LEAST(1.0, false_positive_rate + 0.01),
                             last_updated = NOW()
                           WHERE payload_id = %s""", (payload_id,))
            conn.commit()


import re as _re

# Chars/patterns that signal an actual attack payload (vs prose/example output).
_PAYLOAD_SIGNAL = _re.compile(
    r"""[<>{}$'";|`\\]|\.\./|%[0-9a-fA-F]{2}|&#|"""
    r"""\b(SELECT|UNION|OR|AND|SLEEP|BENCHMARK|script|alert|onerror|onload|"""
    r"""ENTITY|DOCTYPE|proto|__proto__|etc/passwd|win\.ini|file:|http:|https:|"""
    r"""169\.254|127\.0\.0\.1|localhost|\$\{|\{\{|#\{)\b""", _re.IGNORECASE)

# Lines that are clearly prose / example code / docs, not payloads.
_NOISE_PREFIX = ("//", "/*", "* ", "> ", "- ", "Note", "Example", "Payload", "Description",
                 "Values:", "Request", "Response", "Output", "e.g", "var ", "let ", "const ",
                 "function ", "import ", "from ", "package ", "public ", "private ", "class ",
                 "def ", "return ", "print(", "console.", "echo ", "curl ", "http GET", "GET /endpoint",
                 "$ ", "# ", "```")
_PROSE_RE = _re.compile(r"^[A-Za-z][A-Za-z ,.:'\-]{15,}$")  # long all-words sentence


def _looks_like_payload(text: str) -> bool:
    t = text.strip()
    if t.startswith(_NOISE_PREFIX):
        return False
    if t.lower().startswith(("http://example", "https://example.com/foo", "//example")):
        return False
    if _PROSE_RE.match(t):  # pure prose sentence, no code chars
        return False
    # Must carry at least one attack signal, OR be a short structured token.
    if _PAYLOAD_SIGNAL.search(t):
        return True
    if len(t) <= 60 and _re.search(r"[=/\-_.:]", t) and " " not in t:
        return True  # short structured token e.g. filenames, params
    return False


def _iter_matchers(tpl: dict):
    for req in (tpl.get("requests") or tpl.get("http") or []):
        for m in (req.get("matchers") or []):
            yield m


def _iter_payloads(tpl: dict):
    for req in (tpl.get("requests") or tpl.get("http") or []):
        pls = req.get("payloads") or {}
        if isinstance(pls, dict):
            for v in pls.values():
                if isinstance(v, list):
                    for item in v:
                        yield item
    # fuzzing entries
    for fz in (tpl.get("fuzzing") or []):
        for v in (fz.get("values") or []):
            yield v


_catalog_instance: Optional[PayloadCatalog] = None


def get_payload_catalog() -> PayloadCatalog:
    global _catalog_instance
    if _catalog_instance is None:
        _catalog_instance = PayloadCatalog()
    return _catalog_instance
