"""Kubernetes agent API (spec §19) — read-only cluster attack-path analysis.

Two entry points:

* POST /api/kubernetes/analyze  — analyze a supplied cluster *snapshot* (a dict
  of ``{resource: [raw objects]}``, e.g. exported via ``kubectl get ... -o json``).
  No live cluster or extra dependency required.
* POST /api/kubernetes/analyze-live — analyze a live cluster via the local
  ``kubectl`` (read-only). Requires kubectl + kubeconfig on the API host.

Both are Engagement scope-gated when ``engagement_id`` is supplied: the cluster
must be an authorized resource or the agent returns an empty inventory.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/kubernetes", tags=["kubernetes"])


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


class SnapshotBody(BaseModel):
    cluster_id: str = Field(default="cluster", max_length=256)
    engagement_id: Optional[str] = Field(default=None, max_length=64)
    snapshot: Dict[str, Any] = Field(default_factory=dict)


@router.post("/analyze")
def analyze_snapshot(body: SnapshotBody):
    from core.kubernetes import KubernetesAgent
    eng = _load_engagement(body.engagement_id)
    agent = KubernetesAgent.from_snapshot(
        body.snapshot, cluster_id=body.cluster_id, engagement=eng)
    return agent.run()


class LiveBody(BaseModel):
    cluster_id: str = Field(default="cluster", max_length=256)
    engagement_id: Optional[str] = Field(default=None, max_length=64)
    kubeconfig: Optional[str] = Field(default=None, max_length=1024)
    context: Optional[str] = Field(default=None, max_length=256)


@router.post("/analyze-live")
def analyze_live(body: LiveBody):
    from core.kubernetes import KubernetesAgent
    eng = _load_engagement(body.engagement_id)
    agent = KubernetesAgent.from_kubeconfig(
        kubeconfig=body.kubeconfig, context=body.context,
        cluster_id=body.cluster_id, engagement=eng)
    return agent.run()
