"""SCA agent API (spec §5/§20/§21) — static dependency + container analysis.

POST /api/sca/analyze takes a ``{path: content}`` file map (manifests,
lockfiles, Dockerfiles), an optional advisory set, and an optional target /
engagement_id for scope-gating. When ``use_osv`` is true and no advisories are
supplied, the live OSV.dev source is used (best-effort; empty offline).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/sca", tags=["sca"])


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
    target: str = Field(default="artifact", max_length=512)
    engagement_id: Optional[str] = Field(default=None, max_length=64)
    files: Dict[str, str] = Field(default_factory=dict)
    advisories: List[Dict[str, Any]] = Field(default_factory=list)
    use_osv: bool = Field(default=False)


@router.post("/analyze")
def analyze(body: AnalyzeBody):
    from core.sca import ScaAgent
    from core.sca.advisories import StaticAdvisorySource, OsvSource

    eng = _load_engagement(body.engagement_id)
    if body.advisories:
        source = StaticAdvisorySource(body.advisories)
    elif body.use_osv:
        source = OsvSource()
    else:
        source = StaticAdvisorySource([])

    agent = ScaAgent(body.files, advisory_source=source,
                     target=body.target, engagement=eng)
    return agent.run()
