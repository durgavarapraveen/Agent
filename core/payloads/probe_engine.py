from __future__ import annotations

import logging
import os
import time
import urllib.parse
from typing import Any, Dict, List, Optional

from core.payloads.catalog import PayloadCatalog, get_payload_catalog
from core.payloads.mutation import MutationEngine
from core.payloads.schema import InjectionContext, Payload

logger = logging.getLogger(__name__)

_WAF_BLOCK_STATUS = {403, 406, 429, 501}
_WAF_BODY_SIGNS = ("access denied", "request blocked", "cloudflare", "captcha",
                   "web application firewall", "mod_security", "forbidden")


class UniversalProbeEngine:
    """Catalog-driven probe engine (P1).

    Replaces per-class hardcoded payload lists: pulls ranked payloads from the
    PayloadCatalog, optionally mutates for WAF evasion, injects them, validates
    responses through the shared OracleEngine, and feeds outcomes back to the
    catalog (effectiveness learning). Emits finding dicts via
    ``ctx.add_vulnerability`` to match the existing probe pipeline.
    """

    def __init__(self, catalog: PayloadCatalog = None, oracle=None):
        self.catalog = catalog or get_payload_catalog()
        self.mutation = MutationEngine()
        if oracle is None:
            from core.evidence.oracle import get_oracle_engine
            oracle = get_oracle_engine()
        self.oracle = oracle

    async def _jev_corroborate(self, finding: Dict[str, Any], vuln_class: str,
                               evidence: Dict[str, Any]) -> None:
        """Opt-in Jev triage: attach a fast second-opinion confirmation probability
        to a finding the oracle already confirmed. ANNOTATION ONLY — it never drops
        or downgrades a finding (a general scanner must not skip a real bug on a
        classifier's word); downstream ranking/reporting can use jev_probability."""
        try:
            from core.llm.jev_config import jev_triage_enabled
            if not jev_triage_enabled():
                return
            from agents.providers.jev_classifier import get_jev
            jev = get_jev(scan_id=finding.get("scan_id", "") if isinstance(finding, dict) else "")
            if jev is None:
                return
            state = {
                "vuln_class": vuln_class,
                "payload": evidence.get("payload", ""),
                "status_code": evidence.get("status_code"),
                "response_time_ms": evidence.get("response_time_ms"),
                "response_body": str(evidence.get("response_body", ""))[:4000],
                "expected_result": evidence.get("expected_result", ""),
            }
            confirmed, prob = await jev.noul(
                state,
                f"Does this HTTP response genuinely CONFIRM a real {vuln_class} "
                f"vulnerability (not a false positive, error page, or WAF block)?",
                site="triage")
            finding["jev_confirmed"] = bool(confirmed)
            finding["jev_probability"] = round(float(prob), 4)
        except Exception as e:  # annotation must never break probing
            logger.debug("[Jev] corroboration skipped: %s", e)

    async def probe(self, endpoint: str, vuln_class: str, ctx,
                    parameter: str = "q", budget: int = 15) -> List[Dict[str, Any]]:
        """Run one (endpoint, vuln_class) test plan; return finding dicts."""
        from core.orchestration import scan_mode
        budget = scan_mode.effective_budget(budget)
        waf = self._waf_mode(ctx)
        tech = self._tech_for(ctx, endpoint)
        inj = InjectionContext(endpoint=endpoint, parameter=parameter,
                               context=self._context_for(endpoint), detected_tech=tech,
                               detected_waf=waf)
        try:
            payloads = self.catalog.select(vuln_class, inj, waf=waf, tech_stack=tech, budget=budget)
        except Exception as e:
            logger.warning("payload select failed for %s: %s", vuln_class, e)
            return []
        if waf and waf != "none":
            payloads = self._expand_with_mutations(payloads, waf, budget)

        findings: List[Dict[str, Any]] = []
        for p in payloads:
            resp = await self._inject(endpoint, parameter, p, inj)
            if resp is None:
                continue
            body, status, elapsed_ms = resp
            waf_blocked = status in _WAF_BLOCK_STATUS or any(s in body.lower() for s in _WAF_BODY_SIGNS)
            evidence = {
                "response_body": body,
                "status_code": status,
                "response_time_ms": elapsed_ms,
                "payload": p.payload_text,
                "expected_result": (p.confirm_patterns[0] if p.confirm_patterns else ""),
                "evidence_id": p.payload_id,
            }
            result = self.oracle.evaluate(vuln_class, evidence)
            try:
                self.catalog.record_outcome(p.payload_id, confirmed=result.is_vulnerable,
                                            waf_blocked=waf_blocked)
            except Exception:
                pass
            if result.is_vulnerable:
                findings.append(self._build_finding(endpoint, parameter, p, vuln_class, result, status))
                await self._jev_corroborate(findings[-1], vuln_class, evidence)
                ctx.add_vulnerability(findings[-1])
                if scan_mode.stop_after_first():
                    break  # FAST: one confirmation per (endpoint, class) is enough
                # COVERAGE/BENCHMARK: keep testing to catch distinct bugs/challenges
        return findings

    # Classes whose confirmation needs an out-of-band callback (blind bugs).
    _OOB_CLASSES = {"SSRF", "RCE", "XXE", "DNS_REBINDING"}

    def _oob_payloads(self, vuln_class: str, token) -> List[str]:
        """Technique templates (LOGIC) that embed our unique OOB URL/host so a
        callback proves a blind hit. Not catalog data — they must carry the token."""
        u, host = token.http_url, token.domain
        vc = vuln_class.upper()
        if vc in ("SSRF", "DNS_REBINDING"):
            return [u, token.https_url, f"http://{host}", f"//{host}", f"http://{host}@{host}"]
        if vc == "RCE":
            return [f";curl {u}", f"|curl {u}", f"`curl {u}`", f"$(curl {u})",
                    f";nslookup {host}", f"& nslookup {host}", f"|nslookup {host}"]
        if vc == "XXE":
            return [f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "{u}">]><r>&x;</r>']
        return []

    async def _run_oob(self, surface, point, vuln_class: str, ctx) -> List[Dict[str, Any]]:
        try:
            from core.oob.collaborator import get_collaborator
            collab = get_collaborator()
        except Exception:
            return []
        if not collab.is_active():
            return []
        token = collab.new_token(tag=vuln_class.lower())
        findings: List[Dict[str, Any]] = []
        for text in self._oob_payloads(vuln_class, token):
            p = Payload(vuln_class=vuln_class.lower(), payload_text=text,
                        context=self._context_for_location(point.location), severity="HIGH")
            resp = await self._inject_at_point(surface, point, p)
            if resp is None:
                continue
            hits = collab.had_interaction(token.token, wait_s=float(
                __import__("os").getenv("OOB_WAIT_SECONDS", "3")))
            if hits:
                ev = self._evidence_from_response(resp, p, surface, point)
                ev["oob_interactions"] = [h.to_evidence() for h in hits]
                result = self.oracle.evaluate(vuln_class, ev)
                if result.is_vulnerable:
                    f = self._build_finding(surface.url, f"{point.location}:{point.name}",
                                            p, vuln_class, result, ev["status_code"])
                    f["proof"] = f"OOB callback ({hits[0].protocol}) confirmed blind {vuln_class}"
                    f["confirmed"] = True
                    f["status"] = "CONFIRMED"
                    findings.append(f)
                    ctx.add_vulnerability(f)
                    break
        return findings

    # ── unified injection at a REAL point (gaps §0) ────────────────────
    async def probe_point(self, surface, point, vuln_class: str, ctx,
                          budget: int = 0, ledger=None) -> List[Dict[str, Any]]:
        """Inject the full technique set for ``vuln_class`` into ONE real
        injection point of a discovered request (query/json/form/header/
        cookie/path/multipart), oracle-validate, and learn.

        ``surface`` / ``point`` come from SurfaceClassifier. Budget<=0 = send
        every catalog payload of the class (exhaustive; §7 "leave nothing
        untested"). Returns confirmed finding dicts (also added to ctx)."""
        from core.orchestration import scan_mode
        budget = scan_mode.effective_budget(budget)
        pkey = f"{point.location}:{point.name}"
        waf = self._waf_mode(ctx)
        tech = self._tech_for(ctx, surface.url)
        loc_ctx = self._context_for_location(point.location)
        inj = InjectionContext(endpoint=surface.url, parameter=point.name,
                               context=loc_ctx, detected_tech=tech, detected_waf=waf)
        try:
            payloads = self.catalog.select(vuln_class.lower(), inj, waf=waf,
                                           tech_stack=tech, budget=budget)
        except Exception as e:
            logger.debug("select %s failed: %s", vuln_class, e)
            if ledger is not None:
                ledger.errored(surface.url, pkey, vuln_class, f"payload select failed: {e}")
            return []
        if not payloads and vuln_class.upper() not in self._OOB_CLASSES:
            if ledger is not None:
                ledger.skipped(surface.url, pkey, vuln_class, "no payloads in catalog")
            return []
        if waf and waf != "none":
            payloads = self._expand_with_mutations(payloads, waf, budget or len(payloads))

        # Adaptive brain (gaps §5): when Bedrock is reachable, ask the LLM for
        # context-specific novel variants and prepend them. No-op otherwise.
        llm_ids = set()
        try:
            from core.llm.enhancer import get_enhancer
            enh = get_enhancer()
            if enh.is_available():
                novel = enh.novel_payloads(vuln_class, {
                    "endpoint": surface.url, "point": pkey, "context": loc_ctx,
                    "tech": tech, "waf": waf}, max_n=int(os.getenv("LLM_NOVEL_PER_POINT", "5")))
                for text in novel:
                    np = Payload(vuln_class=vuln_class.lower(), payload_text=text,
                                 context=loc_ctx, source="llm_generated", severity="MEDIUM")
                    llm_ids.add(np.payload_id)
                    payloads.insert(0, np)
        except Exception as e:
            logger.debug("llm novel payloads skipped: %s", e)

        findings: List[Dict[str, Any]] = []
        any_blocked = False
        try:
            # 1. baseline (for differential / boolean-blind detection)
            baseline = await self._baseline(surface, point)
            # 2. in-band payloads
            for p in payloads:
                resp = await self._inject_at_point(surface, point, p)
                if resp is None:
                    continue
                ev = self._evidence_from_response(resp, p, surface, point)
                if baseline is not None:
                    ev["baseline_status"] = baseline["status"]
                    ev["baseline_length"] = len(baseline["body"])
                    ev["response_length"] = len(ev["response_body"])
                waf_blocked = ev["status_code"] in _WAF_BLOCK_STATUS or any(
                    s in ev["response_body"].lower() for s in _WAF_BODY_SIGNS)
                any_blocked = any_blocked or waf_blocked
                result = self.oracle.evaluate(vuln_class, ev)
                try:
                    self.catalog.record_outcome(p.payload_id, confirmed=result.is_vulnerable,
                                                waf_blocked=waf_blocked)
                except Exception:
                    pass
                if result.is_vulnerable:
                    f = self._build_finding(surface.url, pkey, p, vuln_class, result, ev["status_code"])
                    findings.append(f)
                    ctx.add_vulnerability(f)
                    # A novel LLM payload that actually confirmed is worth keeping:
                    # persist it to the catalog so it's reused (learn-as-you-go §5).
                    if p.payload_id in llm_ids:
                        try:
                            p.effectiveness_score = 0.85
                            p.confirm_patterns = p.confirm_patterns or [ev.get("expected_result", "")]
                            self.catalog.upsert([p])
                        except Exception:
                            pass
                    if scan_mode.stop_after_first():
                        break  # FAST: one confirmation per (point, class)
                    # COVERAGE/BENCHMARK: keep going for distinct bugs/challenges
            # 3. boolean-blind SQLi (differential TRUE/FALSE pair) when error/
            #    time-based in-band probes found nothing.
            if not findings and vuln_class.upper() == "SQLI":
                bf = await self._boolean_blind_sqli(surface, point, ctx, baseline)
                if bf:
                    findings.append(bf)
            # 4. out-of-band confirmation for blind classes (no in-band signal)
            if not findings and vuln_class.upper() in self._OOB_CLASSES:
                findings.extend(await self._run_oob(surface, point, vuln_class, ctx))
        except Exception as e:
            logger.debug("probe_point %s @ %s errored: %s", vuln_class, pkey, e)
            if ledger is not None:
                ledger.errored(surface.url, pkey, vuln_class, f"{type(e).__name__}: {e}")
            return findings

        if ledger is not None:
            if findings:
                ledger.tested(surface.url, pkey, vuln_class, confirmed=True)
            elif any_blocked:
                ledger.blocked(surface.url, pkey, vuln_class, "WAF/policy blocked payloads")
            else:
                ledger.tested(surface.url, pkey, vuln_class, confirmed=False)
        return findings

    async def _boolean_blind_sqli(self, surface, point, ctx, baseline) -> Optional[Dict[str, Any]]:
        """Differential boolean-blind: a TRUE condition should mirror the normal
        response; a FALSE condition should diverge. Confirms only when TRUE≈base
        and FALSE clearly differs — low false-positive by construction."""
        pairs = [("' AND '1'='1", "' AND '1'='2"),
                 (" AND 1=1", " AND 1=2"),
                 ("') AND ('1'='1", "') AND ('1'='2")]
        base_val = point.sample_value or "1"
        for true_suffix, false_suffix in pairs:
            rt = await self._inject_at_point(surface, point,
                    Payload(vuln_class="sqli", payload_text=base_val + true_suffix,
                            context=self._context_for_location(point.location)))
            rf = await self._inject_at_point(surface, point,
                    Payload(vuln_class="sqli", payload_text=base_val + false_suffix,
                            context=self._context_for_location(point.location)))
            if not rt or not rf:
                continue
            lt, lf = len(rt["body"]), len(rf["body"])
            st, sf = rt["status"], rf["status"]
            # TRUE close to FALSE => not injectable; require a clear divergence.
            if st == sf and lt and lf:
                delta = abs(lt - lf) / max(lt, lf)
                true_like_base = baseline is None or abs(lt - len(baseline["body"])) <= max(20, 0.05 * lt)
                if delta >= 0.30 and true_like_base:
                    p = Payload(vuln_class="sqli", payload_text=base_val + true_suffix, severity="HIGH")
                    from core.evidence.oracle import OracleResult
                    res = OracleResult(True, 0.85, [p.payload_id],
                                       f"Boolean-blind SQLi: TRUE/FALSE responses diverge {delta:.0%}.")
                    f = self._build_finding(surface.url, f"{point.location}:{point.name}",
                                            p, "SQLI", res, st)
                    f["confirmed"] = True
                    f["status"] = "CONFIRMED"
                    ctx.add_vulnerability(f)
                    return f
            elif st != sf:  # status flip between TRUE/FALSE is a strong signal
                p = Payload(vuln_class="sqli", payload_text=base_val + true_suffix, severity="HIGH")
                from core.evidence.oracle import OracleResult
                res = OracleResult(True, 0.8, [p.payload_id],
                                   f"Boolean-blind SQLi: status flips {st}/{sf} on TRUE/FALSE.")
                f = self._build_finding(surface.url, f"{point.location}:{point.name}",
                                        p, "SQLI", res, st)
                f["confirmed"] = True
                f["status"] = "CONFIRMED"
                ctx.add_vulnerability(f)
                return f
        return None

    async def _baseline(self, surface, point) -> Optional[dict]:
        """A benign request so oracles can diff payload responses against normal."""
        try:
            benign = Payload(vuln_class="baseline", payload_text="probe_baseline_1",
                             context=self._context_for_location(point.location))
            return await self._inject_at_point(surface, point, benign)
        except Exception:
            return None

    async def _inject_at_point(self, surface, point, payload: Payload) -> Optional[dict]:
        try:
            from core.network.network_broker import NetworkBroker
            broker = NetworkBroker.get()
        except Exception as e:
            logger.debug("broker unavailable: %s", e)
            return None
        method = surface.method or "GET"
        url = surface.url
        raw = surface.raw if isinstance(surface.raw, dict) else {}
        headers = {str(k): v for k, v in (raw.get("headers") or {}).items()}
        kwargs: Dict[str, Any] = {}
        val = payload.payload_text
        loc = point.location

        if loc == "query":
            url = self._url_with_param(url, point.name, val)
        elif loc == "path":
            url = self._url_with_path_seg(url, int(point.name) if point.name.isdigit() else 0, val)
        elif loc == "json_body":
            method = method if method != "GET" else "POST"
            kwargs["content"] = self._merge_json(raw.get("body"), point.name, val)
            headers["Content-Type"] = "application/json"
        elif loc == "form":
            method = method if method != "GET" else "POST"
            kwargs["content"] = self._merge_form(raw.get("body"), point.name, val)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif loc == "header":
            headers[point.name] = val
        elif loc == "cookie":
            headers["Cookie"] = self._merge_cookie(headers.get("Cookie", ""), point.name, val)
        elif loc == "multipart":
            method = method if method != "GET" else "POST"
            # real multipart/form-data body with the target field replaced
            # (upload probe owns file-content RCE verify; this covers text
            # injection into multipart field values with correct encoding).
            boundary = "----probeboundary7MA4YWxkTrZu0gW"
            body_mp, ctype_mp = self._merge_multipart(point.name, val, boundary)
            kwargs["content"] = body_mp
            headers["Content-Type"] = ctype_mp
        else:
            url = self._url_with_param(url, point.name or "q", val)
        if headers:
            kwargs["headers"] = headers

        start = time.perf_counter()
        try:
            resp = await broker.request(method, url, **kwargs)
        except Exception as e:
            logger.debug("inject request failed: %s", e)
            return None
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        rheaders = {}
        try:
            rheaders = {str(k).lower(): v for k, v in dict(getattr(resp, "headers", {}) or {}).items()}
        except Exception:
            pass
        return {
            "body": getattr(resp, "text", "") or "",
            "status": getattr(resp, "status_code", 0) or 0,
            "elapsed_ms": elapsed_ms,
            "headers": rheaders,
        }

    def _evidence_from_response(self, resp: dict, p: Payload, surface, point) -> Dict[str, Any]:
        h = resp.get("headers", {})
        ev = {
            "response_body": resp["body"],
            "status_code": resp["status"],
            "response_time_ms": resp["elapsed_ms"],
            "payload": p.payload_text,
            "expected_result": (p.confirm_patterns[0] if p.confirm_patterns else ""),
            "evidence_id": p.payload_id,
            "headers": h,
            "redirect_location": h.get("location", ""),
            "acao": h.get("access-control-allow-origin", ""),
            "acac": h.get("access-control-allow-credentials", ""),
            "x_frame_options": h.get("x-frame-options", ""),
            "csp": h.get("content-security-policy", ""),
        }
        # class-specific hints derivable from the injected point/value
        if point.location == "header" and point.name.lower() in ("host", "x-forwarded-host"):
            ev["injected_host"] = p.payload_text
        if "url_valued" in getattr(point, "signals", set()):
            ev["expected_redirect_domain"] = self._payload_host(p.payload_text)
        return ev

    @staticmethod
    def _payload_host(text: str) -> str:
        try:
            return urllib.parse.urlparse(text).netloc or ""
        except Exception:
            return ""

    @staticmethod
    def _context_for_location(location: str) -> str:
        return {"json_body": "json_body", "header": "header", "cookie": "header",
                "multipart": "html_body", "form": "url"}.get(location, "url")

    @staticmethod
    def _url_with_path_seg(url: str, idx: int, value: str) -> str:
        parts = urllib.parse.urlparse(url)
        segs = parts.path.split("/")
        real = [i for i, s in enumerate(segs) if s]
        if idx < len(real):
            segs[real[idx]] = urllib.parse.quote(value, safe="")
        return urllib.parse.urlunparse(parts._replace(path="/".join(segs)))

    @staticmethod
    def _merge_json(body, name: str, value: str) -> str:
        import json
        try:
            obj = json.loads(body) if isinstance(body, str) else (body or {})
        except Exception:
            obj = {}
        if not isinstance(obj, dict):
            obj = {}
        top = name.split(".")[0].split("[")[0]
        obj[top] = value
        return json.dumps(obj)

    @staticmethod
    def _merge_form(body, name: str, value: str) -> str:
        pairs = dict(urllib.parse.parse_qsl(str(body or "")))
        pairs[name] = value
        return urllib.parse.urlencode(pairs)

    @staticmethod
    def _merge_multipart(name: str, value: str, boundary: str) -> tuple:
        crlf = "\r\n"
        body = (f"--{boundary}{crlf}"
                f'Content-Disposition: form-data; name="{name}"{crlf}{crlf}'
                f"{value}{crlf}"
                f"--{boundary}--{crlf}")
        return body, f"multipart/form-data; boundary={boundary}"

    @staticmethod
    def _merge_cookie(cookie: str, name: str, value: str) -> str:
        parts = [c for c in (cookie or "").split(";") if c.strip() and not c.strip().startswith(name + "=")]
        parts.append(f"{name}={value}")
        return "; ".join(p.strip() for p in parts)

    # ── internals ─────────────────────────────────────────────────────
    def _expand_with_mutations(self, payloads: List[Payload], waf: str, budget: int) -> List[Payload]:
        out = list(payloads)
        for p in payloads[: max(1, budget // 3)]:
            out.extend(self.mutation.waf_adapt(p, waf))
        return out[:budget]

    async def _inject(self, endpoint: str, parameter: str, payload: Payload,
                      inj: InjectionContext) -> Optional[tuple]:
        try:
            from core.network.network_broker import NetworkBroker
            broker = NetworkBroker.get()
        except Exception as e:
            logger.debug("broker unavailable: %s", e)
            return None

        method = "GET"
        url = endpoint
        kwargs: Dict[str, Any] = {}
        ctx_name = payload.context or inj.context
        if ctx_name in ("json_body",):
            method = "POST"
            kwargs["content"] = payload.payload_text
            kwargs["headers"] = {"Content-Type": "application/json"}
        elif ctx_name == "header":
            name, _, val = payload.payload_text.partition(":")
            kwargs["headers"] = {name.strip() or "X-Probe": (val.strip() or payload.payload_text)}
        else:  # url / query / html_* -> query parameter injection
            url = self._url_with_param(endpoint, parameter, payload.payload_text)

        start = time.perf_counter()
        try:
            resp = await broker.request(method, url, **kwargs)
        except Exception as e:
            logger.debug("inject request failed: %s", e)
            return None
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        body = getattr(resp, "text", "") or ""
        status = getattr(resp, "status_code", 0) or 0
        return body, status, elapsed_ms

    @staticmethod
    def _url_with_param(endpoint: str, parameter: str, value: str) -> str:
        parts = urllib.parse.urlparse(endpoint)
        q = dict(urllib.parse.parse_qsl(parts.query))
        q[parameter] = value
        return urllib.parse.urlunparse(parts._replace(query=urllib.parse.urlencode(q)))

    def _build_finding(self, endpoint, parameter, payload: Payload, vuln_class,
                       result, status) -> Dict[str, Any]:
        import hashlib
        fid = "UPE_" + hashlib.sha256(
            f"{vuln_class}|{endpoint}|{parameter}|{payload.payload_id}".encode()).hexdigest()[:16]
        return {
            "id": fid,
            "type": vuln_class.upper(),
            "title": f"{vuln_class.upper()} via {parameter} on {endpoint}",
            "severity": payload.severity,
            "target": endpoint,
            "location": endpoint,
            "parameter": parameter,
            "proof": f"payload={payload.payload_text!r} -> HTTP {status}; {result.reasoning}",
            "details": result.reasoning,
            "tool": "universal_probe_engine",
            "confidence": result.confidence,
            "confirmed": result.is_vulnerable and not result.requires_manual_confirmation,
            "status": "CONFIRMED" if not result.requires_manual_confirmation else "NEEDS_REVIEW",
            "payload_id": payload.payload_id,
        }

    @staticmethod
    def _waf_mode(ctx) -> Optional[str]:
        try:
            from core.adaptation.waf_state import get_waf_state
            mode = get_waf_state().mode_for(getattr(ctx, "target", ""))
            return getattr(mode, "value", str(mode)).lower()
        except Exception:
            return None

    @staticmethod
    def _tech_for(ctx, endpoint: str) -> List[str]:
        try:
            techs = getattr(ctx, "technologies", {}) or {}
            flat: List[str] = []
            for v in techs.values():
                flat.extend(v if isinstance(v, list) else [v])
            return [str(t).lower() for t in flat]
        except Exception:
            return []

    @staticmethod
    def _context_for(endpoint: str) -> str:
        return "url"
