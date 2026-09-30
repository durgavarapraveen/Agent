from __future__ import annotations

import logging

from agents.authorization import AuthorizationManager
from agents.llm_client import TaskTier

logger = logging.getLogger(__name__)


class AuthzMixin:
    """Authorization concerns: parse the engagement authorization document into
    scope, run the cross-role replay authz check, and propose admin/privileged
    URL paths. Extracted from CentralBrain.
    """

    async def _parse_authorization(self, auth_doc: str):
        logger.info("Parsing authorization document...")
        self.ctx.log_brain("Parsing authorization document", "parse_auth")

        result = await self.llm.generate_json(
            f"Parse this authorization document and extract:\n"
            f"- domains: list of authorized domains\n"
            f"- max_tier: POC, SHALLOW, or DEEP\n"
            f"- restrictions: any restrictions mentioned\n"
            f"- valid_until: expiration date if mentioned\n\n"
            f"Document:\n{auth_doc[:3000]}\n\n"
            f"Return JSON: {{\"domains\": [...], \"max_tier\": \"...\", "
            f"\"restrictions\": [...], \"valid_until\": \"...\"}}",
            tier=TaskTier.SMALL,
        )

        if result and result.get("domains"):
            self.ctx.scope = result
            self.auth.scope = AuthorizationManager.create_scope(
                domains=result["domains"],
                max_tier=result.get("max_tier", "POC"),
            )
            logger.info(f"Scope: {result['domains']}, tier: {result.get('max_tier')}")

    async def _run_authz_phase(self) -> None:
        try:
            from core.exploitation.cross_role_replay import run_cross_role_replay
        except Exception as e:
            logger.debug(f"[AUTHZ] cross_role_replay import failed: {e}")
            return
        captured = getattr(self.ctx, "captured_requests", []) or []
        identities = []
        try:
            identities = list(getattr(self.identity_manager, "identities", []) or [])
        except Exception:
            pass
        if not captured:
            if getattr(self.ctx, "browser_status", "") == "UNAVAILABLE":
                logger.info("[AUTHZ] captured_requests UNAVAILABLE (browser missing) — "
                            "not a negative result; skipping cross-role replay")
            else:
                logger.info("[AUTHZ] no captured_requests on ctx — skipping cross-role replay")
            return
        if len(identities) < 2:
            logger.info(f"[AUTHZ] only {len(identities)} identity/identities discovered — "
                        f"cross-role replay needs at least 2 to compare")
            return
        logger.info(f"[AUTHZ] cross-role replay: {len(captured)} requests × "
                    f"{len(identities)} identities")
        findings = await run_cross_role_replay(self.ctx)
        for f in findings or []:
            if isinstance(f, dict):
                f.setdefault("phase", "authz")
                f.setdefault("tool", "cross_role_replay")
                if hasattr(self.ctx, "add_vulnerability"):
                    self.ctx.add_vulnerability(f)
        logger.info(f"[AUTHZ] cross-role replay produced {len(findings or [])} finding(s)")

    async def _llm_admin_path_candidates(self, limit: int = 8) -> list:
        """LLM-proposed admin/privileged URL paths for THIS target, inferred
        from discovered endpoints + detected technologies. Modern apps route
        admin under varied paths, so this augments discovery. Returns [] on any
        failure."""
        try:
            eps = []
            for e in (getattr(self.ctx, "endpoints", []) or [])[:60]:
                u = e if isinstance(e, str) else (e.get("url", "") if isinstance(e, dict) else "")
                if u:
                    eps.append(u)
            _t = getattr(self.ctx, "technologies", None)
            techs = (list(_t)[:15] if isinstance(_t, dict) else (list(_t or [])[:15]))
            if not eps and not techs:
                return []
            prompt = (
                "You are mapping a web app's admin/privileged surface. From the "
                "discovered endpoints and detected technologies, propose up to "
                f"{limit} likely ADMIN or privileged URL PATHS (leading slash, no "
                "host) a regular user should NOT reach. Prefer paths consistent "
                "with the app's own routing style. Return JSON "
                "{\"paths\": [\"/...\"]}.\n"
                f"Endpoints: {eps}\nTechnologies: {techs}"
            )
            data = await self.llm.generate_json(prompt, tier=TaskTier.SMALL,
                                                max_tokens=300)
            out = []
            for p in ((data.get("paths") if isinstance(data, dict) else []) or []):
                if isinstance(p, str) and p.startswith("/") and len(p) < 120:
                    out.append(p.split("?")[0])
            return out[:limit]
        except Exception:
            return []
