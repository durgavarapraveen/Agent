"""Single confirmation/ingestion gate shared by every finding path.

Historically the oracle re-verify, observation, reproduction/confirmation and
takeover gates lived only inside ``FindingIngestionMixin._stamp_and_add_vuln``.
Specialist probes and the Dispatcher/UPE call ``ctx.add_vulnerability`` directly,
so a probe that self-set ``status=CONFIRMED`` reached the DB unverified (P0-1).

This module hoists those gates into one pure function that BOTH paths call:
``_stamp_and_add_vuln`` (tool/executor path) and ``SharedContext.add_vulnerability``
(the universal sink every probe hits). It mutates ``vuln`` in place (downgrading
an unearned ``CONFIRMED``) and returns ``True`` only when the finding must be
dropped (out of scope). It never UPGRADES status — confirmation is earned
elsewhere — and it is idempotent: once run on a dict it stamps ``_gated`` and
returns immediately if called again, so the two paths never double-gate.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# Classes whose confirmation signature lives in the HTTP response the gate can
# see (error string / canary / file marker / timing / OOB). For these, an oracle
# refutation given the finding's own forwarded evidence reliably means the
# self-reported CONFIRMED was a false positive, so a downgrade is safe.
# Field-keyed classes (mass_assignment/csrf/jwt/cors/idor/auth_bypass/
# business_logic/open_redirect/xss-DOM) are NEVER downgraded here: absent
# evidence keys mean "the probe didn't populate them", not "not vulnerable"
# (P1-4). They keep whatever status their own probe/verifier assigned.
_RESPONSE_DERIVABLE_ORACLES = {"SQLI", "NOSQLI", "SSTI", "RCE", "LFI", "XXE", "SSRF"}

# External tools that CONFIRM via their own verification (timing/boolean/OOB) whose
# proof does not live in the HTTP response body the oracle reads. Never re-judge
# their findings — a clean body would otherwise wrongly downgrade e.g. a
# sqlmap-confirmed blind SQLi.
_TRUSTED_CONFIRMERS = {"sqlmap", "nuclei", "dalfox", "commix", "tplmap", "nosqlmap", "ffuf"}


def oracle_reverify(v: dict) -> None:
    """Re-verify a self-reported CONFIRMED finding against the canonical
    OracleEngine, downgrading to UNCONFIRMED only for response-derivable classes
    the forwarded evidence can actually adjudicate. Single source of truth used by
    both the shared gate and _stamp_and_add_vuln. Never upgrades."""
    try:
        if str(v.get("status") or "").upper() != "CONFIRMED":
            return
        # A finding an external confirming tool already validated (sqlmap blind
        # SQLi, nuclei template match, ...) carries its proof outside the response
        # body — do not re-judge it against a body-reading oracle.
        if (v.get("tool") or v.get("source") or "").lower() in _TRUSTED_CONFIRMERS:
            return
        from core.evidence.oracle import get_oracle_engine
        eng = get_oracle_engine()
        cls = (v.get("type") or v.get("attack_type") or "").upper().replace(" ", "_").replace("-", "_")
        if not cls or cls not in getattr(eng, "_oracles", {}):
            return
        det = v.get("details")
        det_dict = det if isinstance(det, dict) else {}
        # A REAL response body only — never fall back to `proof`/`evidence`, which
        # for UniversalProbeEngine findings is a human summary string (e.g.
        # "payload=... -> HTTP 500; Database error in response"). Re-evaluating an
        # oracle against that summary always refutes and would silently downgrade a
        # genuinely-confirmed finding. Absent a real body => inconclusive => no
        # downgrade (these UPE findings were already oracle-confirmed at build).
        resp = (v.get("response_body") or v.get("response_snippet") or v.get("response")
                or det_dict.get("response_body") or det_dict.get("response_snippet") or "")
        if isinstance(resp, (dict, list)):
            resp = str(resp)
        if not resp:
            return
        # Merge WITHOUT clobbering: details-supplied evidence keys win; top-level /
        # mapped fields only fill gaps. (Previously a blanket ev.update overwrote
        # details["expected_result"]/["response_time_ms"] etc. with empty top-level
        # values, causing false downgrades.)
        ev = dict(det_dict)

        def _fill(k, val):
            if not ev.get(k):
                ev[k] = val

        _fill("response_body", resp)
        _fill("response_headers", v.get("response_headers") or v.get("headers") or {})
        _fill("status_code", v.get("status_code") or v.get("response_code"))
        # oracle key names differ from some probe field names — map both.
        _fill("response_time_ms", v.get("response_time_ms") or v.get("elapsed_ms") or v.get("timing_ms") or 0)
        _fill("payload", v.get("payload") or "")
        _fill("expected_result", v.get("expected_result") or v.get("canary") or v.get("marker") or "")
        _fill("canary", v.get("canary") or v.get("marker") or v.get("payload") or "")
        _fill("dom_events", v.get("dom_events") or [])
        _fill("oob_interactions", v.get("oob_interactions")
              or ([v["oob_interaction"]] if v.get("oob_interaction") else []))
        _fill("evidence_id", v.get("evidence_id") or v.get("finding_id") or v.get("id"))
        res = eng.evaluate(cls, ev)
        reason = getattr(res, "reasoning", "") or ""
        if (not getattr(res, "is_vulnerable", False)
                and not reason.startswith("Oracle error")
                and not reason.startswith("No oracle")
                and cls in _RESPONSE_DERIVABLE_ORACLES):
            v["status"] = "UNCONFIRMED"
            v.setdefault("_downgraded_by", "oracle_gate")
            v.setdefault("_oracle_reason", reason)
    except Exception:
        pass


# Weak single-signal, field-keyed classes: their probes confirm on one composite
# boolean flag. We don't DOWNGRADE (P1-4 — absent evidence != not vulnerable), but
# we require a SECOND corroboration before CONFIRMED ships; without one the finding
# is routed to NEEDS_REVIEW (kept, flagged) rather than trusted outright.
_CORROBORATION_REQUIRED = {"CORS", "CSRF", "JWT", "AUTH_BYPASS"}


def corroboration_gate(v: dict) -> None:
    """For weak field-keyed classes, demand a 2nd signal before CONFIRMED.
    Corroboration = attached proof, a reproduction/corroboration count, a DOM or
    OOB signal, or a trusted external confirmer. Missing → NEEDS_REVIEW (never
    dropped, never silently trusted). Never upgrades."""
    try:
        if str(v.get("status") or "").upper() != "CONFIRMED":
            return
        cls = (v.get("type") or v.get("attack_type") or "").upper().replace(" ", "_").replace("-", "_")
        if cls not in _CORROBORATION_REQUIRED:
            return
        if (v.get("tool") or v.get("source") or "").lower() in _TRUSTED_CONFIRMERS:
            return
        corroborated = bool(
            v.get("proof")
            or int(v.get("corroborations", 0) or 0) >= 1
            or int(v.get("reproduction_count", 0) or 0) >= 2
            or v.get("dom_events")
            or v.get("oob_interactions") or v.get("oob_interaction")
        )
        if not corroborated:
            v["status"] = "NEEDS_REVIEW"
            v.setdefault("_downgraded_by", "corroboration_gate")
            v.setdefault("_corroboration_reason",
                         f"{cls} confirmed on a single signal; second corroboration required")
    except Exception:
        pass


def apply_ingestion_gates(vuln: dict, target: str = "", source: str = "", parser: str = "regex") -> bool:
    """Run every purely-vuln-scoped ingestion gate. Returns True to DROP.

    Idempotent via the ``_gated`` marker: a dict already gated on one path is
    not re-judged when it reaches the shared sink.
    """
    if not isinstance(vuln, dict):
        return False
    if vuln.get("_gated"):
        return False
    v = vuln
    _base = target or ""

    # --- URL hygiene: un-stack "GET:get://https://…" corruption on every field.
    try:
        from core.common.url_hygiene import canonical_http_url as _canon
        for _k in ("location", "target", "url", "affected_endpoint"):
            _val = v.get(_k)
            if isinstance(_val, str) and _val and (
                "get://" in _val
                or _val[:8].upper().startswith(("GET:", "POST:", "PUT:", "HEAD:"))
            ):
                _c = _canon(_val, _base)
                if _c.startswith(("http://", "https://")):
                    v[_k] = _c
        for _k in ("title", "description"):
            _s = v.get(_k)
            if isinstance(_s, str) and _s and (
                "get://" in _s
                or re.search(r'\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS):(?:get://)?https?://', _s)
            ):
                _s = _s.replace("get://", "")
                _s = re.sub(r'\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS):(https?://)', r'\1 \2', _s)
                v[_k] = _s
    except Exception:
        pass

    # --- Scope guard: drop a finding whose endpoint host is a DIFFERENT
    # registrable domain than the scan target (third-party CDN scraped from a
    # source-map, etc.). Relative/host-less locations and same-domain subdomains
    # are kept. Returns True to signal the caller to drop it.
    try:
        def _reg(h: str) -> str:
            parts = (h or "").lower().strip(".").split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else (h or "").lower()

        _tgt_host = urlparse(_base if "://" in _base else "http://" + _base).hostname or ""
        _fhost = ""
        # Only judge the VULNERABLE endpoint's host (location/affected_endpoint).
        # `target`/`url` are used by some probes for the payload DESTINATION
        # (open-redirect target, SSRF callback host) — judging those would drop a
        # legit finding whose vulnerable endpoint is in scope.
        for _k in ("location", "affected_endpoint"):
            _u = v.get(_k)
            if isinstance(_u, str) and _u.startswith(("http://", "https://")):
                _fhost = urlparse(_u).hostname or ""
                if _fhost:
                    break
        if _tgt_host and _fhost and _reg(_fhost) != _reg(_tgt_host):
            logger.info("[ingest] dropped out-of-scope finding host=%s (target=%s) title=%r",
                        _fhost, _tgt_host, str(v.get("title"))[:80])
            v["_gated"] = True
            return True
    except Exception:
        pass

    # --- Evidence-based confidence SCORE (only when not already set).
    # NOTE: deliberately does NOT set `confidence_label`. SharedContext.
    # add_vulnerability sets the authoritative label via
    # core.analysis.finding_confidence.classify, whose vocabulary
    # (CONFIRMED/INCONCLUSIVE/...) drives the exploit-mirror guard. Setting the
    # confidence_model vocabulary ("very_low"/...) here would shadow it.
    try:
        from core.evidence.confidence_model import compute, ConfidenceInputs
        already = float(v.get("confidence_score") or 0.0)
        if already <= 0:
            inp = ConfidenceInputs(
                source=source or v.get("tool", "") or v.get("source", ""),
                parser=parser,
                validated=(str(v.get("status") or "").upper() == "CONFIRMED"),
                corroborations=int(v.get("corroborations", 0) or 0),
                age_seconds=0.0,
            )
            v["confidence_score"] = round(compute(inp), 3)
    except Exception:
        pass

    # --- Observation gate: raw observations must not enter CONFIRMED unless the
    # source is signed/validated.
    try:
        from core.findings.observation import is_confirmable_without_validation
        src = (v.get("tool") or source or "").lower()
        kind = (v.get("type") or "").lower()
        if str(v.get("status") or "").upper() == "CONFIRMED" and not v.get("proof"):
            if not is_confirmable_without_validation(f"{src}_confirmed") \
                    and not is_confirmable_without_validation(kind):
                v["status"] = "UNCONFIRMED"
                v.setdefault("_downgraded_by", "observation_gate")
    except Exception:
        pass

    # --- Oracle re-verify gate (single source of truth: oracle_reverify). A
    # self-reported CONFIRMED response-derivable finding can't reach the DB unless
    # a real oracle agrees; field-keyed classes are never downgraded here.
    oracle_reverify(v)

    # --- Corroboration gate: weak field-keyed classes (CORS/CSRF/JWT/auth) need
    # a 2nd signal to stay CONFIRMED, else → NEEDS_REVIEW (kept, not trusted).
    corroboration_gate(v)

    # --- Reproduction + confirmation gates (ReproductionGate P0.8 +
    # FindingConfirmationGate P0.6). A CONFIRMED finding that fails is DOWNGRADED
    # to NEEDS_REVIEW, never dropped, never silently kept.
    try:
        if str(v.get("status") or "").upper() == "CONFIRMED":
            _fid = str(v.get("finding_id") or v.get("id") or "")
            _cat = (v.get("type") or v.get("category") or v.get("attack_type") or "GENERIC")
            _gate_reason = ""
            _repro = v.get("reproduction_responses")
            if _repro:
                try:
                    from core.verification.reproduction_gate import ReproductionGate
                    _rg = ReproductionGate()
                    _rg.check_reproducible(_fid, v, responses=_repro)
                    _ok, _rr = _rg.is_confirmation_allowed(_fid)
                    if not _ok:
                        _gate_reason = f"reproduction_gate:{_rr}"
                except ImportError:
                    pass
            if not _gate_reason:
                try:
                    from core.verification.finding_confirmation_gate import FindingConfirmationGate
                    _cg = FindingConfirmationGate()
                    _cg.register(_fid, _cat)
                    _pv = v.get("proof") or v.get("evidence") or v.get("details") or ""
                    _eval_v = v if v.get("proof") else {**v, "proof": _pv if isinstance(_pv, str) else str(_pv)}
                    _stage, _reason = _cg.evaluate(_fid, _eval_v)
                    if getattr(_stage, "value", str(_stage)) == "rejected":
                        _gate_reason = f"confirmation_gate:{_reason}"
                except ImportError:
                    pass
            if _gate_reason:
                v["status"] = "NEEDS_REVIEW"
                v.setdefault("_downgraded_by", "confirmation_gate")
                v.setdefault("_gate_reason", _gate_reason)
    except Exception:
        pass

    # --- Takeover gate: takeover indicators must pass DNS validation before
    # CONFIRMED.
    try:
        if (v.get("type") or "").upper() in ("SUBDOMAIN_TAKEOVER", "TAKEOVER"):
            from core.intelligence.takeover_workflow import detect_indicator, validate, TakeoverStage
            cand = detect_indicator(
                v.get("target") or v.get("location") or "",
                int(v.get("status_code") or 0),
                str(v.get("proof") or v.get("details") or ""),
            )
            if cand is None:
                v["status"] = "UNCONFIRMED"
                v.setdefault("_downgraded_by", "takeover_gate:no_indicator")
            else:
                validated = validate(cand)
                if validated.stage != TakeoverStage.CONFIRMED:
                    v["status"] = "UNCONFIRMED"
                    v.setdefault("_downgraded_by",
                                 f"takeover_gate:{validated.stage.value}:{validated.reason}")
    except Exception:
        pass

    v["_gated"] = True
    return False
