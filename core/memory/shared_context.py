import json
import re as _re
import threading
from typing import Dict, List, Optional, Any
from datetime import datetime as _dt
import logging
from core.domain.endpoint import Endpoint
from core.domain.identity import Identity
from core.domain.session import Session
from core.coverage.coverage_state import CoverageStateV2
from core.attack_surface.attack_surface_state import AttackSurfaceState

logger = logging.getLogger(__name__)

# E1/E4: repair endpoint URLs corrupted upstream before they are stored/probed:
#   - a leading HTTP-method prefix   "GET:https://…"      → "https://…"
#   - a method-shaped double scheme   "get://https://…"    → "https://…"
#   - a client-side SPA hash route    "https://h/#/admin"  → "https://h/"
# Iterative so stacked prefixes ("GET:get://https://…") unwind fully. Generic —
# no target specifics. Returns "" for un-rendered template junk ("${x}", "{{y}}").
def _sanitize_endpoint_url(raw: str) -> str:
    # Un-stack METHOD:/pseudo-scheme prefixes via the shared url_hygiene primitive
    # (single source of truth for that unwind), then keep this function's own
    # contract: pass relative paths through unchanged, drop SPA hash fragments,
    # reject un-rendered template junk.
    if not raw or "://" not in raw:
        return raw or ""
    from core.common.url_hygiene import _strip_stacked_prefixes
    u = _strip_stacked_prefixes(raw.strip()).strip()
    # Drop SPA client-route hash fragment — it is not a server request target.
    if "#" in u:
        u = u.split("#", 1)[0]
    if "${" in u or "{{" in u or "`" in u:
        return ""
    return u


def _dedup_endpoint_location(loc: str) -> str:
    """Canonical finding-location key (E3): scheme://host/path + sorted parameter
    NAMES, query values dropped. So /x?id=1 and /x?id=2 dedup, while /x?id and
    /x?token stay distinct. Falls back to the raw lowercased string on error."""
    loc = _sanitize_endpoint_url(loc or "")
    try:
        from urllib.parse import urlsplit, parse_qsl
        s = urlsplit(loc)
        if not s.scheme:
            return (loc or "").lower()
        names = sorted({k for k, _ in parse_qsl(s.query, keep_blank_values=True)})
        base = f"{s.scheme}://{s.netloc}{s.path}".lower().rstrip("/")
        return base + ("?" + ",".join(names) if names else "")
    except Exception:
        return (loc or "").lower()


class SharedContextV2:
    def __init__(self, target: str = None, scope: Dict = None):
        self._state_lock = threading.RLock()
        self._dynamic_keys: set = set()
        self.target = target
        self.scope = scope or {}

        # --- Canonical V2 state (active fields only) ---
        self.endpoints: Dict[str, Endpoint] = {}
        self.identities: Dict[str, Identity] = {}
        self.sessions: Dict[str, Session] = {}
        self.tool_results: Dict[str, Dict] = {}
        self.exploit_results: List[Dict] = []
        self.coverage_state: Optional[CoverageStateV2] = None
        self.attack_surface: Optional[AttackSurfaceState] = AttackSurfaceState(target or "") if target else None
        self.auth_credentials: List[Dict] = []

        # --- V1 backward compatibility ---
        self.subdomains: List[str] = []
        self.ports: List[Dict] = []
        self.agents_spawned: List[str] = []
        self.vulnerabilities: List[Dict] = []
        self.ips: List[str] = []
        self.technologies: Dict[str, Any] = {}
        self.directories: List[str] = []
        self.headers: Dict[str, Any] = {}
        self.ssl_info: Dict[str, Any] = {}
        self.secrets: List[Dict] = []
        self.crawled_pages: List[str] = []
        self.captured_requests: List[Dict] = []
        self.tool_executions: List[Dict] = []
        self.brain_log: List[str] = []
        self.attack_chains: List[Dict] = []
        self.privesc_findings: List[Dict] = []
        self.harvested_creds: List[Dict] = []
        self.lateral_plan: Dict[str, Any] = {}
        self.persistence_plan: Dict[str, Any] = {}
        self.mitre_mappings: List[Dict] = []
        self.has_shell_access: bool = False
        self.shell_access: List[Dict] = []
        # P0-5: endpoints on hosts outside the authorised scope are kept here for
        # context (so the operator can see what the app depends on) but never
        # enter endpoints/hypotheses/test queues.
        self.external_dependencies: List[Dict] = []
        # P1.12: scanner-generated probe artifacts (SPA-detect paths, 404
        # baseline probes, deliberately-nonexistent URLs) are kept here for
        # audit but never enter the real attack surface / hypotheses / coverage.
        self.synthetic_endpoints: List[Dict] = []
        # P1.9: browser/Chromium capability. A capture failure due to a missing
        # browser is UNAVAILABLE, NOT "no client-side requests" — downstream must
        # not read it as negative security evidence.
        self.browser_status: str = "UNKNOWN"
        self.browser_status_reason: str = ""
        # P1.15: observed serving layer per host (EDGE/ORIGIN/APPLICATION),
        # learned from response headers, so findings can be attributed correctly.
        self.host_layers: Dict[str, str] = {}

        # P1.2: canonical registry of discovered assets (JS/etc). Analyzers must
        # resolve relative refs against a registered origin, never re-prefix the
        # global target — otherwise an asset served from the real origin gets
        # rebuilt to an unreachable address (curl rc=7) and silently dropped.
        try:
            from core.domain.asset_registry import AssetRegistry
            self.asset_registry = AssetRegistry()
        except Exception:
            self.asset_registry = None
        # P1.3: canonical registry of discovered artifacts (OpenAPI/Swagger/
        # GraphQL/robots/sitemap/auth-metadata) so the API importer consumes
        # what recon already found instead of re-probing in isolation.
        try:
            from core.domain.artifact_registry import ArtifactRegistry
            self.artifact_registry = ArtifactRegistry()
        except Exception:
            self.artifact_registry = None

        self.target_summary = {
            "tech_stack": [],
            "auth_types": []
        }
        self.execution_mode = "safe"
        
    def get_full_summary(self, max_chars: int = 0) -> Dict[str, Any]:
        summary = {
            "target": self.target,
            "endpoints_count": len(self.endpoints),
            "subdomains_count": len(self.subdomains),
            "vulnerabilities_count": len(self.vulnerabilities),
            "target_summary": self.target_summary
        }
        if max_chars > 0:
            text = json.dumps(summary)
            if len(text) > max_chars:
                summary.pop("target_summary", None)
        return summary
        
    def log_agent(self, agent_id: str, objective: str = None, status: str = None, result_summary: str = None):
        if agent_id not in self.agents_spawned:
            self.agents_spawned.append(agent_id)
        if objective or status:
            self.brain_log.append(f"[agent] {agent_id}: {objective or ''} -> {status or ''}")

    def log_brain(self, msg: str, event_type: str = "brain"):
        self.brain_log.append(f"[{event_type}] {msg}")

    # P1-10/P1-11: finding classes that describe a HOST-level control, not a
    # per-URL defect. These are deduped by (type, host) so one policy finding
    # covers the whole host instead of one row per path (root-cause clustering).
    _HOST_LEVEL_TYPES = {
        "MISSING_HEADER", "MISSING_HEADERS", "MISSING_SECURITY_HEADERS",
        "SECURITY_HEADER", "SECURITY_HEADERS",
        "TLS_WEAKNESS", "SSL_ISSUE", "HSTS", "CSP", "CLICKJACKING",
    }

    @staticmethod
    def _vuln_host(vuln: Dict) -> str:
        loc = vuln.get("location") or vuln.get("target") or ""
        try:
            from urllib.parse import urlparse
            return (urlparse(loc).netloc or loc).lower()
        except Exception:
            return str(loc).lower()

    def add_vulnerability(self, vuln: Dict):
        # E2: never store a blank type — derive one from the finding's own fields
        # so it can't land as an untyped row. Generic; no fixed vocabulary.
        if not (vuln.get("type") or "").strip():
            derived = (vuln.get("category") or vuln.get("attack_type")
                       or vuln.get("vuln_type") or vuln.get("sub_type") or "").strip()
            vuln["type"] = derived or "UNCATEGORIZED"
        title = (vuln.get("title") or "").lower()
        vtype = (vuln.get("type") or "UNCATEGORIZED").upper()
        location = (vuln.get("location") or vuln.get("target") or "").lower()
        # E3: dedup on the endpoint route + parameter NAMES, dropping query values,
        # so the same bug reported on /x?id=1 and /x?id=2 collapses to one finding
        # (without merging genuinely different parameters).
        _norm_loc = _dedup_endpoint_location(location)
        host = self._vuln_host(vuln)
        host_level = vtype in self._HOST_LEVEL_TYPES or (
            "header" in title and "missing" in title)

        with self._state_lock:
            for existing in self.vulnerabilities:
                e_title = (existing.get("title") or "").lower()
                e_type = (existing.get("type") or "").upper()
                e_loc = (existing.get("location") or existing.get("target") or "").lower()
                if e_title == title and e_type == vtype and \
                        _dedup_endpoint_location(e_loc) == _norm_loc:
                    return
                # P1-11 / P1.14: same host-level control on the same host → one
                # root finding. Preserve the per-endpoint evidence by recording
                # the affected endpoint on the existing root finding instead of
                # silently dropping the duplicate.
                if host_level and e_type == vtype and self._vuln_host(existing) == host:
                    loc_new = vuln.get("location") or vuln.get("target") or ""
                    if loc_new:
                        aff = existing.setdefault("affected_endpoints", [])
                        if loc_new not in aff:
                            aff.append(loc_new)
                    return

            # Conflict resolution: don't add "Missing X header" if we already know the header is present
            if vtype == "MISSING_HEADER" and "missing" in title:
                header_name = title.replace("missing ", "").replace(" header", "").strip().lower()
                for existing in self.vulnerabilities:
                    e_title = (existing.get("title") or "").lower()
                    if header_name in e_title and "present" in e_title:
                        return

            # P1.13: stamp an evidence-based confidence label. A finding whose
            # only evidence is a noisy status (HTTP 500/406) is INCONCLUSIVE, not
            # proof — this label is authoritative for the mirror guard below.
            try:
                from core.analysis.finding_confidence import classify
                label = classify(vuln)
                vuln.setdefault("confidence_label", label)
            except Exception:
                label = None

            # P1.15: attribute the finding to the serving layer of its host
            # (edge/origin/application) when we have observed it.
            try:
                if "infra_layer" not in vuln:
                    layer = self.host_layers.get(host)
                    if layer:
                        vuln["infra_layer"] = layer
            except Exception:
                pass

            self.vulnerabilities.append(vuln)
            # P0-1: a deterministically CONFIRMED vulnerability is also an
            # exploitation result. Mirror it into exploit_results so it persists
            # as an exploit row (and increments the EXPLOITS counter) instead of
            # living only in logs. Dedup by proof/location so re-detections don't
            # inflate the count. P1.13: never mirror a finding that only a noisy
            # status backs (classified INCONCLUSIVE) — a 500 is not an exploit.
            try:
                confirmed = bool(vuln.get("confirmed")) or \
                    str(vuln.get("status", "")).upper() == "CONFIRMED"
                if confirmed and label != "INCONCLUSIVE":
                    self._mirror_confirmed_exploit(vuln)
            except Exception:
                pass

        # Shared blackboard (delta 1): broadcast EVERY newly-added finding here,
        # at the universal sink, so findings reach the live board no matter which
        # ingestion path produced them (dedup collapses re-posts by ref). Fired
        # outside the state lock; dedup returns above never reach this point.
        try:
            from core.orchestration import blackboard as _bb
            _sid = getattr(self, "scan_id", "") or ""
            if _sid:
                _ref = str(vuln.get("finding_id") or vuln.get("id")
                           or f"{vuln.get('type','')}|{vuln.get('location') or vuln.get('target','')}")
                _bb.post(_sid, vuln.get("tool") or "agent", "finding",
                         vuln.get("title") or vuln.get("type") or "Finding",
                         {"type": vuln.get("type", ""), "severity": vuln.get("severity", ""),
                          "status": vuln.get("status", ""),
                          "location": vuln.get("location") or vuln.get("target") or "",
                          "confidence": vuln.get("confidence_score") or vuln.get("confidence"),
                          "tool": vuln.get("tool", "")},
                         ref=_ref[:200])
        except Exception:
            pass

    def _mirror_confirmed_exploit(self, vuln: Dict):
        proof = vuln.get("proof") or ""
        loc = vuln.get("location") or vuln.get("target") or ""
        dedup_key = (proof or loc).lower()
        for ex in self.exploit_results:
            if (ex.get("proof") or ex.get("location") or "").lower() == dedup_key:
                return
        self.exploit_results.append({
            "vuln_id": vuln.get("id", ""),
            "exploit_id": vuln.get("cwe", "") or vuln.get("type", ""),
            "vuln_type": vuln.get("type", ""),
            "title": vuln.get("title", ""),
            "payload": vuln.get("payload", "") or vuln.get("proof", ""),
            "success": True,
            "proof": proof or f"{loc}",
            "location": loc,
            "severity": (vuln.get("severity") or "MEDIUM").upper(),
            "tool": vuln.get("tool", ""),
            "strategy": vuln.get("type", "unknown"),
            "test_type": vuln.get("type", "unknown"),
            "timestamp": _dt.now().isoformat(),
        })

    def add_subdomains(self, subs: List[str], source: str = None):
        with self._state_lock:
            for s in subs:
                if s not in self.subdomains:
                    self.subdomains.append(s)

    def get_subdomains(self) -> List[str]:
        with self._state_lock:
            return list(self.subdomains)

    @staticmethod
    def _endpoint_url(ep) -> str:
        if isinstance(ep, str):
            return _sanitize_endpoint_url(ep)
        if isinstance(ep, dict):
            return _sanitize_endpoint_url(ep.get("url") or ep.get("name") or "")
        return _sanitize_endpoint_url(getattr(ep, "url", "") or "")

    @staticmethod
    def canonical_endpoint_id(method: str, url: str) -> str:
        from core.domain.endpoint import canonical_endpoint_key
        return canonical_endpoint_key(method, _sanitize_endpoint_url(url))

    # P1.12: probe artifacts the scanner itself generates — must never become
    # normal attack-surface discoveries.
    _SYNTHETIC_MARKERS = (
        "__spa_detect", "spa_detect", "does-not-exist", "doesnotexist",
        "does_not_exist", "should-not-exist", "nonexistent", "non-existent",
        "__baseline", "randomnonexistent", "__antigravity_probe",
    )

    @classmethod
    def _is_synthetic_url(cls, url: str) -> bool:
        u = (url or "").lower()
        if any(m in u for m in cls._SYNTHETIC_MARKERS):
            return True
        # A path segment that is a long random hex/alnum token (baseline 404
        # probes) — e.g. /this-path-…-98765 or /a1b2c3d4e5f6a7b8.
        import re as _re
        for seg in u.split("?")[0].split("/"):
            if len(seg) >= 16 and _re.fullmatch(r"[a-z0-9]+", seg) and _re.search(r"\d", seg) and _re.search(r"[a-f]", seg):
                return True
        return False

    @classmethod
    def _endpoint_origin(cls, url: str, source: str) -> str:
        s = (source or "").lower()
        if cls._is_synthetic_url(url) or any(k in s for k in ("synthetic", "spa_probe", "baseline", "404probe")):
            return "SYNTHETIC"
        if any(k in s for k in ("capture", "browser", "playwright", "observed", "crawl")):
            return "OBSERVED"
        if any(k in s for k in ("nuclei", "ffuf", "gobuster", "feroxbuster", "dirsearch", "tool", "katana", "sqlmap")):
            return "TOOL_DERIVED"
        if any(k in s for k in ("llm", "guess", "generated", "candidate", "inferred")):
            return "GENERATED"
        return "DISCOVERED"

    def _endpoint_in_scope(self, ep) -> bool:
        url = self._endpoint_url(ep)
        if not url:
            return True  # relative/path-only endpoints belong to the target
        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname
            if not host:
                return True  # no host → relative path on the target
            from core.security.authorization import TargetScopeValidator
            return TargetScopeValidator.get().is_authorized(host)
        except Exception as e:
            logger.warning(f"[Scope] endpoint scope check crashed for {url!r}: {e} — rejecting (fail-closed)")
            return False

    @staticmethod
    def _looks_like_endpoint(u: str) -> bool:
        """Reject non-endpoint strings that discovery (esp. JS bundle analysis)
        scrapes as if they were routes — unresolved template literals
        (``${...}``/``{{...}}``), i18n keys / enum constants
        (``FEEDBACK_FIVE_STAR_THANK_YOU``), and bare identifiers (``caption``,
        ``language``). Spec §13: do not treat every string as an endpoint."""
        if not u or not isinstance(u, str):
            return False
        s = u.strip()
        if not s:
            return False
        if "${" in s or "{{" in s or "}}" in s:
            return False  # unresolved template literal
        if "://" in s or s.startswith("/") or "/" in s:
            return True   # absolute URL, rooted path, or any path with a separator
        import re as _re
        if _re.search(r"\.[A-Za-z]{2,5}($|\?|#)", s):
            return True   # dotted resource (foo.json, bar.php)
        return False      # bare token / constant / i18n key → not an endpoint

    def add_endpoints(self, eps: List, source: str = None):
        _newly_added: List[str] = []
        with self._state_lock:
            for ep in eps:
                # Discovery hygiene: drop scraped strings that aren't endpoints
                # before they reach scope-validation/probing (cuts wasted probes
                # + AUTHORIZATION_DENIED log noise from JS-extracted junk).
                if not self._looks_like_endpoint(self._endpoint_url(ep)):
                    continue
                if not self._endpoint_in_scope(ep):
                    url = self._endpoint_url(ep)
                    if not any(d.get("url") == url for d in self.external_dependencies):
                        try:
                            from urllib.parse import urlparse
                            self.external_dependencies.append({
                                "url": url,
                                "host": urlparse(url).hostname or "",
                                "source": source or "",
                            })
                        except Exception:
                            pass
                    continue
                # P1.12: divert scanner-generated probe artifacts out of the real
                # attack surface (they otherwise pollute coverage & hypotheses),
                # and stamp the origin on everything else.
                _url = self._endpoint_url(ep)
                _origin = self._endpoint_origin(_url, source or "")
                if _origin == "SYNTHETIC":
                    if not any(d.get("url") == _url for d in self.synthetic_endpoints):
                        self.synthetic_endpoints.append({"url": _url, "source": source or ""})
                    continue
                if isinstance(ep, dict):
                    ep.setdefault("origin", _origin)
                if isinstance(ep, str):
                    eid = self.canonical_endpoint_id("GET", ep) if "://" in ep else ep
                elif isinstance(ep, dict):
                    eid = self.canonical_endpoint_id(ep.get("method", "GET"), ep.get("url", ""))
                else:
                    eid = getattr(ep, "endpoint_id", None) or self.canonical_endpoint_id(
                        getattr(ep, "method", "GET"), getattr(ep, "url", str(ep)))
                # Store the sanitized URL too, not just a clean id, so the surface
                # classifier and probes don't re-derive corrupted targets (E1/E4).
                if isinstance(ep, dict) and ep.get("url"):
                    ep["url"] = _sanitize_endpoint_url(ep["url"])
                elif isinstance(ep, str):
                    ep = _sanitize_endpoint_url(ep)
                if eid not in self.endpoints:
                    self.endpoints[eid] = ep
                    _newly_added.append(str(eid))
        # Broadcast newly-discovered attack surface to the shared blackboard so
        # other agents can pick it up (kind="tool"). One concise post per batch,
        # not per endpoint; skip trivial single adds to keep the board readable.
        if len(_newly_added) >= 3:
            try:
                from core.orchestration import blackboard as _bb
                _sid = getattr(self, "scan_id", "") or getattr(self, "_scan_id", "")
                _preview = ", ".join(e.split("://")[-1][:80] for e in _newly_added[:10])
                _bb.post(_sid, source or "recon", "tool",
                         f"Discovered {len(_newly_added)} new endpoints",
                         data={"count": len(_newly_added), "source": source or "",
                               "sample": _newly_added[:20]},
                         ref=f"surface:{source or 'recon'}:{len(self.endpoints)}")
            except Exception:
                pass

    def get_endpoints(self) -> List:
        with self._state_lock:
            return list(self.endpoints.values())

    # P3: the endpoint store is a canonical-id -> record dict. Pruning/reset must
    # go through these so the dict contract is never replaced by a bare list
    # (which silently breaks dedup, iteration-by-value, and DB persistence).
    def clear_endpoints(self) -> None:
        with self._state_lock:
            self.endpoints.clear()

    def drop_endpoints_by_url(self, urls) -> int:
        dead = {str(u) for u in (urls or []) if u}
        if not dead:
            return 0
        with self._state_lock:
            keep, removed = {}, 0
            for eid, ep in self.endpoints.items():
                if self._endpoint_url(ep) in dead:
                    removed += 1
                else:
                    keep[eid] = ep
            self.endpoints = keep
            return removed

    def add_ports(self, host_or_ports, ports: List[Dict] = None, source: str = None):
        if ports is None:
            actual_ports = host_or_ports
        else:
            actual_ports = ports
        with self._state_lock:
            for p in actual_ports:
                if isinstance(p, dict) and "port" in p and isinstance(p.get("port"), int):
                    if p not in self.ports:
                        self.ports.append(p)

    def add_technologies(self, host: str, techs: List[str]):
        with self._state_lock:
            if host not in self.technologies:
                self.technologies[host] = []
            for t in techs:
                if t not in self.technologies[host]:
                    self.technologies[host].append(t)
            # Auto-register host as subdomain if it belongs to target apex
            if host and hasattr(self, 'target') and self.target:
                apex = self.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
                apex = apex[4:] if apex.startswith("www.") else apex
                h = host.lower()
                if (h == apex or h.endswith("." + apex)) and h not in self.subdomains:
                    self.subdomains.append(h)

    def get_technologies(self) -> Dict[str, Any]:
        return self.technologies

    def add_exploit_result(self, result: Dict):
        self.exploit_results.append(result)

    # ── P2-6: response baseline store ──────────────────────────────────────
    def record_baseline(self, method: str, url: str, status: int,
                        length: int, content_type: str = "") -> None:
        try:
            key = self.canonical_endpoint_id(method, url)
            store = getattr(self, "response_baselines", None)
            if store is None:
                store = {}
                setattr(self, "response_baselines", store)
            if key not in store:
                store[key] = {"status": int(status or 0), "length": int(length or 0),
                              "content_type": content_type}
        except Exception:
            pass

    def baseline_for(self, method: str, url: str) -> Optional[Dict]:
        try:
            store = getattr(self, "response_baselines", None) or {}
            return store.get(self.canonical_endpoint_id(method, url))
        except Exception:
            return None

    def add_tool_result(self, tool_id: str = None, result: Dict = None):
        if tool_id and result:
            self.tool_results[tool_id] = result
        elif isinstance(result, dict) and "tool" in result:
            self.tool_results[result["tool"]] = result

    def add_directory(self, directory: str, source: str = None):
        if directory not in self.directories:
            self.directories.append(directory)

    def add_secret(self, secret: Dict):
        for existing in self.secrets:
            if existing.get("value") == secret.get("value") and existing.get("location") == secret.get("location"):
                return
        self.secrets.append(secret)

    def add_captured_request(self, req: Dict):
        self.captured_requests.append(req)

    def add_captured_requests(self, reqs: list, **kwargs):
        for r in reqs:
            if isinstance(r, dict):
                self.captured_requests.append(r)
            elif hasattr(r, "to_dict"):
                self.captured_requests.append(r.to_dict())
            elif hasattr(r, "__dict__"):
                self.captured_requests.append(dict(r.__dict__))

    def add_tool_execution(self, exec_record: Dict):
        self.tool_executions.append(exec_record)

    def add_ssl_info(self, host: str, info: Dict):
        self.ssl_info[host] = info

    def add_headers(self, host: str, hdrs: Dict):
        self.headers[host] = hdrs

    def add_event(self, event: str, data: Any = None):
        self.brain_log.append(f"[event] {event}: {data}")

    def get(self, key: str, default=None):
        return getattr(self, key, default)

    def save(self, path: str):
        data = {
            "target": self.target,
            "scope": self.scope,
            "subdomains": self.subdomains,
            "ports": self.ports,
            "ips": self.ips,
            "vulnerabilities": self.vulnerabilities,
            "technologies": self.technologies,
            "endpoints": [str(e) for e in self.endpoints.keys()],
            "directories": self.directories,
            "headers": self.headers,
            "ssl_info": self.ssl_info,
            "secrets": self.secrets,
            "crawled_pages": self.crawled_pages,
            "captured_requests": self.captured_requests,
            "tool_executions": self.tool_executions,
            "exploit_results": self.exploit_results,
            "attack_chains": self.attack_chains,
            "agents_spawned": self.agents_spawned,
            "tool_results_count": len(self.tool_results),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def update(self, key: str, value: Any):
        # Store EVERY key so recon/OSINT data (employees, GitHub info, leaked creds,
        # cloud buckets, threat correlations, …) is never silently dropped — any agent
        # can then read it via ctx.get(key). Previously novel keys were discarded.
        if key == "target_profile" and isinstance(value, dict) and hasattr(self, "target_summary"):
            self.target_summary.update(value)
        existed = hasattr(self, key)
        setattr(self, key, value)
        if not existed and not key.startswith("_"):
            try:
                self._dynamic_keys.add(key)
            except AttributeError:
                self._dynamic_keys = {key}

    def dynamic_data(self) -> Dict[str, Any]:
        keys = getattr(self, "_dynamic_keys", set())
        out = {}
        for k in keys:
            try:
                out[k] = getattr(self, k)
            except Exception:
                pass
        return out
        
    def get_endpoint(self, endpoint_id: str) -> Optional[Endpoint]:
        return self.endpoints.get(endpoint_id)
        
    def get_identity(self, identity_id: str) -> Optional[Identity]:
        return self.identities.get(identity_id)
        
    def get_session(self, session_id: str) -> Optional[Session]:
        return self.sessions.get(session_id)
        
    def get_coverage(self) -> Optional[CoverageStateV2]:
        return self.coverage_state
        
    def get_pending_tests(self) -> List[str]:
        if not self.coverage_state:
            return []
        pending = []
        for test_id, run_state in self.coverage_state.coverage_map.items():
            if run_state.status.value in ["NOT_TESTED", "READY", "INCONCLUSIVE"]:
                pending.append(test_id)
        return pending

    # Per-key caps for the LLM-facing agent context. This is REFERENCE TEXT only —
    # agents read real/full data from ctx methods — so we project each item to its
    # essential fields, cap counts, and put objective-relevant items first. Without
    # this, serializing all endpoints+captured_requests+vulns+exploit_results (with
    # nested bodies/headers/proofs) into every step ballooned requests to ~140K
    # tokens each. Env-tunable.
    _CTX_CAPS = {
        "endpoints": 40, "captured_requests": 25, "vulnerabilities": 40,
        "exploit_results": 25, "parameters": 60, "directories": 60,
        "subdomains": 50, "js_files": 40, "headers": 40, "secrets": 30,
        "technologies": 40, "ips": 40, "ports": 40,
    }

    @staticmethod
    def _ctx_cap(key: str, default: int) -> int:
        import os as _os
        try:
            return max(1, int(_os.getenv(f"AGENT_CTX_MAX_{key.upper()}", str(default))))
        except Exception:
            return default

    @staticmethod
    def _get(item, *names, default=""):
        for n in names:
            if isinstance(item, dict):
                if item.get(n) not in (None, ""):
                    return item.get(n)
            else:
                v = getattr(item, n, None)
                if v not in (None, ""):
                    return v
        return default

    def _project_item(self, key: str, item):
        """Project one list item to its essential, LLM-useful fields (drops verbose
        bodies/headers/proof blobs). Falls back to a truncated string."""
        try:
            if key == "endpoints":
                params = self._get(item, "parameters", "params", default=[]) or []
                pnames = [str(self._get(p, "name", default=p))[:40] for p in params][:12] if isinstance(params, list) else []
                return {"path": str(self._get(item, "path", "url", "location"))[:160],
                        "methods": self._get(item, "method_set", "methods", "method", default="GET"),
                        "params": pnames}
            if key == "captured_requests":
                return {"method": self._get(item, "method", default="GET"),
                        "url": str(self._get(item, "url", "location", "target"))[:200],
                        "params": list((self._get(item, "fields", default={}) or {}).keys())[:12]
                                  if isinstance(self._get(item, "fields", default={}), dict) else [],
                        "ct": str(self._get(item, "content_type", default=""))[:60]}
            if key == "vulnerabilities":
                return {"type": self._get(item, "type", "vuln_type", "sub_type", default="?"),
                        "location": str(self._get(item, "location", "target", "url"))[:160],
                        "severity": self._get(item, "severity", default=""),
                        "status": self._get(item, "status", default=("confirmed" if self._get(item, "confirmed") else ""))}
            if key == "exploit_results":
                return {"type": self._get(item, "type", "vuln_type", default="?"),
                        "location": str(self._get(item, "location", "target", "url"))[:160],
                        "status": self._get(item, "status", default="")}
        except Exception:
            pass
        if isinstance(item, (str, int, float, bool)):
            return item
        return str(item)[:200]

    def _relevance_key(self, objective: str):
        """Extract a path/host token from the objective so matching items sort first."""
        import re as _re
        m = _re.search(r"https?://[^\s]+|/[\w./-]{2,}", str(objective or ""))
        tok = (m.group(0) if m else "").lower()
        # reduce a full URL to its path for loose contains-matching
        tok = _re.sub(r"^https?://[^/]+", "", tok)
        return tok.strip()

    def get_context_for_agent(self, objective: str, context_keys: list = None) -> Dict[str, Any]:
        context = {"target": self.target, "objective": objective}
        keys = context_keys or []
        rel = self._relevance_key(objective)
        for key in keys:
            val = getattr(self, key, None)
            if val is None:
                continue
            if isinstance(val, list):
                cap = self._ctx_cap(key, self._CTX_CAPS.get(key, 50))
                items = val
                if rel and key in ("endpoints", "captured_requests", "vulnerabilities", "exploit_results"):
                    # objective-relevant items first, so the cap keeps what matters
                    def _match(it):
                        blob = str(self._get(it, "location", "url", "target", "path", default="")).lower()
                        return rel in blob
                    items = sorted(val, key=lambda it: 0 if _match(it) else 1)
                projected = [self._project_item(key, it) for it in items[:cap]]
                if len(val) > cap:
                    projected.append(f"...(+{len(val) - cap} more {key} omitted; query ctx for full data)")
                context[key] = projected
            elif isinstance(val, dict):
                context[key] = dict(val)
            else:
                context[key] = val
        return context

    def build_llm_context(self, task: str, params: Dict[str, Any], memory_retriever=None, tool_learning=None) -> Dict[str, Any]:
        context = {
            "task": task,
            "target_summary": self.target_summary,
            "execution_mode": self.execution_mode
        }
        
        # Attack surface slice
        if "endpoint_id" in params:
            ep = self.get_endpoint(params["endpoint_id"])
            if ep:
                context["attack_surface_slice"] = {
                    "path": ep.path,
                    "methods": ep.method_set,
                    "parameters": [p.name for p in ep.parameters],
                    "auth_required": ep.auth_required
                }
                
        # Identities context
        context["current_identities"] = [
            {"id": ident.identity_id, "role": ident.role.value, "auth_state": ident.authentication_state.value}
            for ident in self.identities.values()
        ]
        
        # Coverage status
        if self.coverage_state:
            stats = {}
            for t_id, run_state in self.coverage_state.coverage_map.items():
                stats[t_id] = run_state.status.value
            context["coverage_state"] = stats
            
        # Relevant memory and Tools (if engines provided)
        if memory_retriever and "test_id" in params:
            # We will fetch up to 3 relevant experiences to keep context small
            experiences = memory_retriever.retrieve_relevant_experiences(params.get("endpoint_id"), params["test_id"])
            context["relevant_memory"] = [{"strategy": e["strategy_id"], "outcome": e["outcome"]} for e in experiences[:3]]
            
        if tool_learning:
            # Simplified tool capabilities
            context["available_tools"] = [
                {"tool": name, "score": score} for name, score in tool_learning.get_top_tools(params.get("test_id", "all")).items()
            ]
            
        # Log to simulate ContextBuilder size tracking
        context_str = json.dumps(context)
        token_estimate = len(context_str) // 4
        logger.info(f"LLM_CONTEXT_BUILT endpoints={len(self.endpoints)} identities={len(self.identities)} token_estimate={token_estimate}")
        print(f"LLM_CONTEXT_BUILT endpoints={len(self.endpoints)} identities={len(self.identities)} token_estimate={token_estimate}")
        
        return context
