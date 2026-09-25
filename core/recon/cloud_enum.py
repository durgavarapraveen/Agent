"""Cloud asset enumeration — derive candidate S3 / GCS / Azure Blob bucket
names from the target's brand tokens and check for public exposure. Requests go
through the scoped NetworkBroker; cloud hosts that aren't in scope are recorded
as UNVERIFIED candidates rather than probed (no egress-control bypass)."""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_SUFFIXES = ["", "-dev", "-prod", "-staging", "-backup", "-assets", "-static",
             "-media", "-uploads", "-data", "-public", "-private", "-files"]

_PROVIDERS = {
    "s3": "https://{name}.s3.amazonaws.com/",
    "gcs": "https://storage.googleapis.com/{name}/",
    "azure": "https://{name}.blob.core.windows.net/?comp=list",
}
# Response markers that indicate a listable / existing bucket.
_OPEN_MARKERS = ("<ListBucketResult", "<Contents>", "<EnumerationResults",
                 "<Blobs>", '"items"')
_EXISTS_MARKERS = ("<Error><Code>AccessDenied", "BucketAlreadyExists",
                   "<Code>AuthenticationRequired")


class CloudEnum:
    def __init__(self, ctx=None, max_candidates: int = 40):
        self.ctx = ctx
        self.max_candidates = max_candidates

    def _brand_tokens(self) -> List[str]:
        t = getattr(self.ctx, "target", "") or ""
        host = urlparse(t if "://" in t else f"//{t}").hostname or t
        parts = re.split(r"[.\-]", host)
        # drop TLD + common infra labels (incl. modern eTLDs)
        drop = {"com", "net", "org", "io", "co", "www", "app", "api", "dev",
                "ai", "xyz", "cloud", "tech", "sh", "gg", "online", "site"}
        return [p for p in parts if p and p.lower() not in drop][:3]

    def _candidates(self) -> List[str]:
        names = set()
        for tok in self._brand_tokens():
            for suf in _SUFFIXES:
                names.add(f"{tok}{suf}")
        return list(names)[:self.max_candidates]

    async def _check(self, name: str) -> List[Dict[str, Any]]:
        findings = []
        for provider, tpl in _PROVIDERS.items():
            url = tpl.format(name=name)
            host = urlparse(url).hostname
            try:
                from core.security.authorization import TargetScopeValidator
                in_scope = TargetScopeValidator.get().is_authorized(host)
            except Exception:
                in_scope = False
            if not in_scope:
                # Do not probe out-of-scope cloud hosts; record as candidate.
                continue
            try:
                from core.network.network_broker import NetworkBroker
                resp = await NetworkBroker.get().request("GET", url)
                body = (getattr(resp, "text", "") or "")[:600]
                status = getattr(resp, "status_code", 0) or 0
            except Exception:
                continue
            if any(m in body for m in _OPEN_MARKERS) or status == 200:
                findings.append(self._f(provider, name, url, "public_listable", "HIGH", body[:120]))
            elif any(m in body for m in _EXISTS_MARKERS):
                findings.append(self._f(provider, name, url, "exists_private", "LOW", body[:120]))
        return findings

    def _f(self, provider, name, url, sub, sev, proof) -> Dict[str, Any]:
        import hashlib
        fid = "CLOUD_" + hashlib.sha256(f"{provider}|{name}|{sub}".encode()).hexdigest()[:16]
        return {
            "id": fid, "type": "SECRET_EXPOSURE", "sub_type": f"{provider}_{sub}",
            "title": f"{provider.upper()} bucket '{name}' {sub}",
            "severity": sev, "target": url, "location": url,
            "tool": "cloud_enum", "proof": f"{url} -> {proof}",
            "details": f"Cloud storage candidate {name} on {provider} appears {sub}.",
            "confirmed": sub == "public_listable", "status": "CONFIRMED" if sub == "public_listable" else "NEEDS_REVIEW",
            "cwe": "CWE-200",
        }

    async def scan(self) -> List[Dict[str, Any]]:
        cands = self._candidates()
        if not cands:
            return []
        logger.info("[CloudEnum] %d candidate bucket names", len(cands))
        results = await asyncio.gather(*[self._check(n) for n in cands], return_exceptions=True)
        findings = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        # stash all candidates as recon info regardless of probe result
        try:
            self.ctx.update("cloud_bucket_candidates", cands)
        except Exception:
            pass
        logger.info("[CloudEnum] %d exposed cloud assets", len(findings))
        return findings


async def run_cloud_enum(ctx) -> List[Dict[str, Any]]:
    import os
    if os.getenv("CLOUD_ENUM_ENABLED", "false").lower() not in ("true", "1", "yes", "on"):
        return []
    if not getattr(ctx, "target", ""):
        return []
    return await CloudEnum(ctx).scan()
