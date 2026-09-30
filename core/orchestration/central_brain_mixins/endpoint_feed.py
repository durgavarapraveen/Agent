from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class EndpointFeedMixin:
    """Feed discovered endpoints/recon/catalog into the V2 inventory and the
    AttackSurfaceState / injection matrix. Extracted from CentralBrain; domain
    classes are imported method-locally, the rest are shared self attrs.
    """

    def _feed_endpoints_to_v2(self):
        count = 0

        def _params_of(ep):
            out = []
            for p in getattr(ep, "parameters", []) or []:
                pt = getattr(p, "parameter_type", None)
                loc = pt.value if hasattr(pt, "value") else (pt or "query")
                out.append({"name": getattr(p, "name", ""), "location": loc})
            return out

        def _feed_obj(ep):
            self.endpoint_inventory.add_endpoint({
                "endpoint_id": getattr(ep, "endpoint_id", "")
                or (ep.canonical_id() if hasattr(ep, "canonical_id") else ""),
                "url": getattr(ep, "url", "") or getattr(ep, "path", ""),
                "method": (ep.method_set[0] if getattr(ep, "method_set", None) else "GET"),
                "parameters": _params_of(ep),
                "auth_required": getattr(ep, "auth_required", False),
                "content_type": getattr(ep, "content_type", "") or "text/html",
            })

        eps = getattr(self.ctx, "endpoints", None) or {}
        ep_iter = eps.values() if isinstance(eps, dict) else eps
        for ep in ep_iter:
            try:
                if isinstance(ep, str):
                    self.endpoint_inventory.add_endpoint({"url": ep, "method": "GET"})
                elif isinstance(ep, dict):
                    self.endpoint_inventory.add_endpoint(ep)
                else:
                    _feed_obj(ep)
                count += 1
            except Exception as e:
                logger.debug(f"[V2Sync] ctx endpoint feed skipped: {e}")

        # Pull the deduped AttackSurfaceState endpoints (store #2, authoritative).
        surface = getattr(self.ctx, "attack_surface", None)
        surf_eps = getattr(surface, "endpoints", None)
        if isinstance(surf_eps, dict):
            for ep in surf_eps.values():
                try:
                    _feed_obj(ep)
                    count += 1
                except Exception as e:
                    logger.debug(f"[V2Sync] surface endpoint feed skipped: {e}")

        if count > 0:
            uniq = len(self.endpoint_inventory.list_endpoints())
            logger.info(f"[V2Sync] Fed {count} endpoint records into EndpointInventoryV2 "
                        f"({uniq} unique)")
            self.security_context_v2.endpoints = {
                str(ep.get("endpoint_id") or ep.get("url") or ""): ep
                for ep in self.endpoint_inventory.list_endpoints()
            }

    def _feed_recon_to_attack_surface_state(self):
        surface = getattr(self.ctx, 'attack_surface', None)
        if not surface:
            logger.debug("[ReconV2Wire] No AttackSurfaceState on ctx, skipping")
            return

        fed = {"assets": 0, "endpoints": 0, "technologies": 0, "parameters": 0}

        # Subdomains → assets
        for sub in getattr(self.ctx, 'subdomains', []) or []:
            if isinstance(sub, str) and sub.strip():
                surface.add_asset(sub.strip(), "subdomain", {"hostname": sub.strip()},
                                  source="recon_pipeline")
                fed["assets"] += 1

        # IPs → assets
        for ip in getattr(self.ctx, 'ips', []) or []:
            if isinstance(ip, str) and ip.strip():
                surface.add_asset(ip.strip(), "ip", {"address": ip.strip()},
                                  source="recon_pipeline")
                fed["assets"] += 1

        # Technologies → technologies
        for host, techs in (getattr(self.ctx, 'technologies', {}) or {}).items():
            if isinstance(techs, bool) or techs is None:
                continue
            for tech in (techs if isinstance(techs, list) else [techs]):
                try:
                    if isinstance(tech, dict):
                        from core.domain.asset import Technology as TechObj
                        t = TechObj(name=tech.get("name", ""), version=tech.get("version", ""),
                                    source="recon_pipeline")
                        surface.add_technology(host, t)
                    elif isinstance(tech, str):
                        from core.domain.asset import Technology as TechObj
                        surface.add_technology(host, TechObj(name=tech, source="recon_pipeline"))
                    else:
                        continue
                    fed["technologies"] += 1
                except Exception:
                    pass

        # Endpoints → endpoints
        from core.domain.endpoint import Endpoint as EPObj
        from core.domain.parameter import Parameter as ParamObj
        from urllib.parse import urlparse
        ep_errors = 0
        for ep_data in getattr(self.ctx, 'endpoints', []) or []:
            try:
                if isinstance(ep_data, dict):
                    url = ep_data.get("url", ep_data.get("path", ""))
                    method = ep_data.get("method", "GET").upper()
                elif isinstance(ep_data, str):
                    url = ep_data
                    method = "GET"
                else:
                    continue
                if not url:
                    continue

                parsed = urlparse(url if "://" in url else f"https://{url}")
                path = parsed.path or "/"
                host = parsed.hostname or self.ctx.target if hasattr(self.ctx, 'target') else ""
                scheme = parsed.scheme or "https"
                port = parsed.port or (443 if scheme == "https" else 80)

                ep = EPObj(
                    endpoint_id="",
                    url=url,
                    path=path,
                    method_set=[method],
                    host=host,
                    scheme=scheme,
                    port=port,
                    source="recon_pipeline",
                )
                # P0.1: one canonical, content-addressed identity across every
                # store — a random uuid made the same URL "new" here but a
                # "duplicate" elsewhere, which drove transferred_to_v2 to 1-3.
                try:
                    ep.endpoint_id = ep.canonical_id()
                except Exception:
                    ep.endpoint_id = ep.normalized_key()
                if surface.add_endpoint(ep, source="recon_pipeline"):
                    fed["endpoints"] += 1

                    # Parameters for this endpoint
                    params = ep_data.get("params", []) if isinstance(ep_data, dict) else []
                    for p in params:
                        try:
                            if isinstance(p, dict):
                                param = ParamObj(name=p.get("name", ""), parameter_type=p.get("type", "query"))
                            elif isinstance(p, str):
                                param = ParamObj(name=p, parameter_type="query")
                            else:
                                continue
                            surface.add_parameter(ep.endpoint_id, param, source="recon_pipeline")
                            fed["parameters"] += 1
                        except Exception as pe:
                            logger.debug(f"[ReconV2Wire] Parameter add failed: {pe}")
            except Exception as ep_err:
                ep_errors += 1
                if ep_errors <= 3:
                    logger.warning(f"[ReconV2Wire] Endpoint construction failed: {ep_err}")
        if ep_errors > 3:
            logger.warning(f"[ReconV2Wire] {ep_errors} total endpoint construction failures")

        # Phase 5: Wire redirects from subdomain_status into AttackSurfaceState
        subdomain_status = getattr(self.ctx, 'subdomain_status', {}) or {}
        for host, info in subdomain_status.items():
            if isinstance(info, dict):
                redirect_url = info.get("url", "")
                if redirect_url and host and redirect_url != f"https://{host}" and redirect_url != f"http://{host}":
                    from urllib.parse import urlparse as _up
                    redirect_host = _up(redirect_url).netloc
                    if redirect_host and redirect_host != host:
                        surface.add_redirect(host, redirect_host)

        # Phase 5: Wire related applications (e.g., API subdomains as related apps)
        target = self.ctx.target if hasattr(self.ctx, 'target') else ""
        api_subs = [s for s in getattr(self.ctx, 'subdomains', []) or []
                    if isinstance(s, str) and any(kw in s.lower() for kw in ("api.", "admin.", "staging.", "dev.", "app."))]
        for sub in api_subs:
            surface.add_related_application(target, sub)

        # Mark transferred counts for Phase 4 tracking
        if fed["endpoints"] > 0 or fed["parameters"] > 0:
            surface.mark_transferred_to_v2(fed["endpoints"], fed["parameters"])

        surface.log_transfer_counts()
        logger.info(f"[ReconV2Wire] Fed to AttackSurfaceState: "
                    f"assets={fed['assets']} endpoints={fed['endpoints']} "
                    f"technologies={fed['technologies']} parameters={fed['parameters']}")

    def _feed_catalog_to_attack_surface(self):
        from urllib.parse import urlparse, parse_qs
        from core.domain.endpoint import Endpoint
        from core.domain.parameter import Parameter, ParameterType

        catalog = getattr(self.ctx, "endpoint_catalog", []) or []
        added = 0
        for entry in catalog:
            url = entry.get("url", "")
            method = entry.get("method", "GET")
            path = entry.get("path", "/")
            if not url:
                continue
            pu = urlparse(url)
            eid = f"{method}:{pu.netloc}{pu.path}"
            # skip if already in the graph
            if eid in self.attack_surface.endpoints:
                continue
            # extract parameters from query string
            params = []
            qs = parse_qs(pu.query, keep_blank_values=True)
            for pname in qs:
                params.append(Parameter(
                    name=pname,
                    parameter_type=ParameterType.QUERY,
                    inferred_data_type="string",
                    is_required=False,
                ))
            # for POST/PUT/PATCH, add a generic body param so injection matrix tests it
            if method in ("POST", "PUT", "PATCH") and not any(
                    p.parameter_type == ParameterType.BODY for p in params):
                params.append(Parameter(
                    name="body",
                    parameter_type=ParameterType.BODY,
                    inferred_data_type="string",
                    is_required=False,
                ))
            try:
                ep = Endpoint(
                    endpoint_id=eid,
                    url=url,
                    path=pu.path or "/",
                    method_set=[method],
                    parameters=params,
                    auth_required=entry.get("kind") == "sensitive",
                )
                self.attack_surface.add_endpoint(ep)
                # Also register each parameter into the graph's parameter inventory
                # so the InjectionMatrix / param-fuzz path can actually enumerate
                # them (without this, parameters=0 despite thousands of endpoints).
                try:
                    for _p in params:
                        self.attack_surface.add_parameter(eid, _p)
                except Exception:
                    pass
                added += 1
            except Exception:
                continue
        if added:
            try:
                self.attack_surface.build_graph()
            except Exception:
                pass
            logger.info(f"[Preflight→AttackSurface] Fed {added} catalog endpoints "
                        f"(with params) into attack surface graph")
