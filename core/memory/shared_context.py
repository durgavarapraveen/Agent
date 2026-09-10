import json
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
        title = (vuln.get("title") or "").lower()
        vtype = (vuln.get("type") or "").upper()
        location = (vuln.get("location") or vuln.get("target") or "").lower()
        host = self._vuln_host(vuln)
        host_level = vtype in self._HOST_LEVEL_TYPES or (
            "header" in title and "missing" in title)

        with self._state_lock:
            for existing in self.vulnerabilities:
                e_title = (existing.get("title") or "").lower()
                e_type = (existing.get("type") or "").upper()
                e_loc = (existing.get("location") or existing.get("target") or "").lower()
                if e_title == title and e_type == vtype and e_loc == location:
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
                from core.analysis.finding_confidence import classify, FindingConfidence
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
            return ep
        if isinstance(ep, dict):
            return ep.get("url") or ep.get("name") or ""
        return getattr(ep, "url", "") or ""

    @staticmethod
    def canonical_endpoint_id(method: str, url: str) -> str:
        from core.domain.endpoint import canonical_endpoint_key
        return canonical_endpoint_key(method, url)

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
        except Exception:
            return True  # fail open: never drop a real endpoint on a scope error

    def add_endpoints(self, eps: List, source: str = None):
        with self._state_lock:
            for ep in eps:
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
                if eid not in self.endpoints:
                    self.endpoints[eid] = ep

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

    def get_context_for_agent(self, objective: str, context_keys: list = None) -> Dict[str, Any]:
        context = {"target": self.target, "objective": objective}
        keys = context_keys or []
        for key in keys:
            val = getattr(self, key, None)
            if val is not None:
                if isinstance(val, dict):
                    context[key] = dict(val)
                elif isinstance(val, list):
                    context[key] = list(val)
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
