"""Cloud agent API (spec §17) — read-only provider attack-path analysis.

POST /api/cloud/analyze analyzes a supplied cloud *snapshot* (a dict of
``{identities|networks|compute|storage|databases|kubernetes: [...]}``) for a
given provider. Engagement scope-gated when ``engagement_id`` is supplied: the
account must be an authorized resource or the agent returns an empty inventory.
Live SDK-backed discovery is available via the provider Source classes (boto3
for AWS); those run on the API host and are wired by operators, not exposed
here, to keep credentials off the request path.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/cloud", tags=["cloud"])


def _load_engagement(engagement_id: Optional[str]):
    if not engagement_id:
        return None
    try:
        from core.database.pg_store import EngagementRepo
        row = EngagementRepo.get(engagement_id)
    except Exception as e:
        raise HTTPException(503, f"engagement store unavailable: {e}")
    if not row:
        raise HTTPException(404, "engagement not found")
    spec = row.get("spec") or {}
    if isinstance(spec, str):
        import json
        try:
            spec = json.loads(spec)
        except Exception:
            spec = {}
    from core.domain.engagement import Engagement
    try:
        return Engagement.from_dict(spec)
    except Exception as e:
        raise HTTPException(500, f"engagement spec corrupt: {e}")


class AnalyzeBody(BaseModel):
    provider: str = Field(..., max_length=16)
    account_id: str = Field(default="account", max_length=256)
    engagement_id: Optional[str] = Field(default=None, max_length=64)
    snapshot: Dict[str, Any] = Field(default_factory=dict)


@router.get("/providers")
def list_providers():
    from core.cloud.providers import PROVIDERS
    return {"providers": sorted(PROVIDERS)}


@router.post("/analyze")
def analyze(body: AnalyzeBody):
    from core.cloud import CloudAgent
    eng = _load_engagement(body.engagement_id)
    try:
        agent = CloudAgent.from_snapshot(
            body.provider, body.snapshot,
            account_id=body.account_id, engagement=eng)
    except ValueError as ve:
        raise HTTPException(400, str(ve))
    return agent.run()
