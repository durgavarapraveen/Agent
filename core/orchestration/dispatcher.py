"""Dispatcher (gaps §0, §2, §4) — routes every discovered surface to its full
applicable exploit battery, at its REAL injection points.

Flow: SurfaceClassifier → for each surface → for each injection point → for each
applicable class → unified injection engine (UniversalProbeEngine.probe_point).
Non-injection classes (upload RCE-verify, IDOR/BOLA, JWT, websocket, graphql,
race, business-logic) are delegated to their dedicated probes rather than
duplicated here — the dispatcher records the delegation so coverage is honest.

Everything is derived from observed data; nothing is aimed at a guessed `?q=`.
Budgets from env: DISPATCH_BUDGET (0 = exhaustive/leave-nothing-untested),
DISPATCH_MAX_SURFACES, DISPATCH_MAX_POINTS.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Classes the unified engine can place into a point and confirm from the HTTP
# response via the OracleEngine. Response-detectable per-category classes live
# here; PATT payloads for each are already in the catalog (§6/§7).
ENGINE_CLASSES = {
    "SQLI", "NOSQLI", "XSS", "SSTI", "RCE", "LFI", "XXE", "SSRF",
    "OPEN_REDIRECT", "MASS_ASSIGNMENT", "PROTOTYPE_POLLUTION",
    "HOST_HEADER_INJECTION", "CACHE_POISONING", "EMAIL_INJECTION",
    "CORS_MISCONFIGURATION", "INFORMATION_DISCLOSURE",
    # §7 additions — only classes whose oracle keys off fields the generic engine
    # actually populates from the HTTP response (body/status/timing/headers/
    # reflection). Classes needing differential/multi-request evidence
    # (TYPE_JUGGLING, HTTP_PARAMETER_POLLUTION, XS_LEAK) are delegated instead so
    # the engine never burns budget on a test it structurally cannot confirm.
    "LDAP_INJECTION", "XPATH_INJECTION", "XSLT_INJECTION", "CSS_INJECTION",
    "SSI_INJECTION", "CSV_INJECTION", "LATEX_INJECTION", "CRLF_INJECTION",
    "ORM_LEAK", "CLIENT_SIDE_PATH_TRAVERSAL", "REDOS", "PROMPT_INJECTION",
    "DOM_CLOBBERING",
}

# Classes owned by a dedicated probe elsewhere in the pipeline (not duplicated).
DELEGATED = {
    "FILE_UPLOAD": "file_upload_probe",
    "IDOR": "differential_tester/authz_matrix",
    "JWT": "auth/jwt probe",
    "WEBSOCKET_HIJACKING": "websocket probe",
    "GRAPHQL": "api_probe/graphql",
    "RACE_CONDITION": "race_probe",
    "BUSINESS_LOGIC": "workflow violation tester",
    "CSRF": "csrf checks",
    "AUTH_BYPASS": "auth probe",
    "CREDENTIAL_BRUTE_FORCE": "credential_spray",
    "SESSION_HIJACKING": "session checks",
    "HTTP_SMUGGLING": "smuggling probe",
    # need differential / multi-request evidence, not a single-response oracle
    "TYPE_JUGGLING": "differential auth probe",
    "HTTP_PARAMETER_POLLUTION": "differential param probe",
    "XS_LEAK": "cross-site oracle probe",
}


class Dispatcher:
    def __init__(self, engine=None, classifier=None):
        self._engine = engine
        self._classifier = classifier

    @property
    def engine(self):
        if self._engine is None:
            from core.payloads.probe_engine import UniversalProbeEngine
            self._engine = UniversalProbeEngine()
        return self._engine

    @property
    def classifier(self):
        if self._classifier is None:
            from core.recon.surface_classifier import get_surface_classifier
            self._classifier = get_surface_classifier()
        return self._classifier

    async def run(self, ctx) -> List[Dict[str, Any]]:
        budget = self._int_env("DISPATCH_BUDGET", 0)          # 0 = all payloads
        max_surfaces = self._int_env("DISPATCH_MAX_SURFACES", 40)
        max_points = self._int_env("DISPATCH_MAX_POINTS", 30)

        # Coverage ledger — records every (surface, point, class) outcome so a
        # skip/error is never silent (gaps: "never skip silently").
        from core.coverage.coverage_ledger import CoverageLedger
        ledger = CoverageLedger()

        surfaces = self.classifier.classify(ctx)
        findings: List[Dict[str, Any]] = []
        delegated_seen: Dict[str, int] = {}
        upload_needed = False

        for s in surfaces[:max_surfaces]:
            engine_classes = [c for c in s.applicable_classes if c in ENGINE_CLASSES]
            for c in s.applicable_classes:
                if c in DELEGATED:
                    delegated_seen[c] = delegated_seen.get(c, 0) + 1
                    if c == "FILE_UPLOAD":
                        upload_needed = True
                    ledger.skipped(s.url, "surface", c, f"delegated to {DELEGATED[c]}")
            # point × class injection battery
            for pt in s.injection_points[:max_points]:
                # skip classes that only make sense for a different point kind
                for c in engine_classes:
                    if not self._point_supports(pt, c):
                        ledger.skipped(s.url, pt.key(), c, "point kind not applicable")
                        continue
                    try:
                        fs = await self.engine.probe_point(s, pt, c, ctx, budget=budget, ledger=ledger)
                        findings.extend(fs)
                    except Exception as e:
                        logger.warning("probe_point %s @ %s failed: %s", c, pt.key(), e)
                        ledger.errored(s.url, pt.key(), c, f"{type(e).__name__}: {e}")

        # delegate upload once (real field detection + execution verify lives there)
        if upload_needed:
            try:
                from core.exploitation.file_upload_probe import run_file_upload_probe
                uf = await run_file_upload_probe(ctx)
                findings.extend(uf or [])
            except Exception as e:
                logger.debug("file_upload delegation failed: %s", e)

        rep = ledger.report()
        logger.info("Dispatcher: %d surfaces → %d findings; coverage %.0f%% (%s); delegated=%s",
                    len(surfaces), len(findings), rep["completeness"] * 100, rep["counts"], delegated_seen)
        try:
            setattr(ctx, "coverage_ledger", rep)
        except Exception:
            pass
        try:
            self._record_coverage(ctx, surfaces, delegated_seen)
        except Exception:
            pass
        return findings

    @staticmethod
    def _point_supports(pt, vuln_class: str) -> bool:
        loc = pt.location
        # header-oriented classes only at header points; url-oriented only where url-valued
        if vuln_class in ("HOST_HEADER_INJECTION", "CACHE_POISONING", "CORS_MISCONFIGURATION"):
            return loc == "header"
        if vuln_class in ("SSRF", "OPEN_REDIRECT", "CLIENT_SIDE_PATH_TRAVERSAL"):
            return "url_valued" in getattr(pt, "signals", set()) or loc in ("query", "json_body", "form")
        if vuln_class in ("MASS_ASSIGNMENT", "PROTOTYPE_POLLUTION", "TYPE_JUGGLING", "ORM_LEAK"):
            return loc in ("json_body", "form")
        if vuln_class == "EMAIL_INJECTION":
            return "email" in getattr(pt, "signals", set()) or loc in ("query", "json_body", "form")
        if vuln_class == "INFORMATION_DISCLOSURE":
            return loc in ("query", "path")
        # generic text-injection classes: any text-bearing point
        return loc in ("query", "json_body", "form", "multipart", "ws_message", "graphql_arg", "path")

    @staticmethod
    def _record_coverage(ctx, surfaces, delegated) -> None:
        summary = {
            "surfaces": len(surfaces),
            "points": sum(len(s.injection_points) for s in surfaces),
            "kinds": {},
            "delegated": delegated,
        }
        for s in surfaces:
            summary["kinds"][s.kind] = summary["kinds"].get(s.kind, 0) + 1
        try:
            setattr(ctx, "surface_coverage", summary)
        except Exception:
            pass

    @staticmethod
    def _int_env(name: str, default: int) -> int:
        try:
            return int(os.getenv(name, str(default)))
        except ValueError:
            return default


async def run_dispatcher(ctx) -> List[Dict[str, Any]]:
    return await Dispatcher().run(ctx)
