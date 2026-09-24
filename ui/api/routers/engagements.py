"""Engagement API (spec §1, §40) — the authorization boundary, control-plane.

Create an engagement, activate it, list/read it, run the fail-closed gate, and
launch runs under it. The global X-API-Key auth middleware in server.py applies
to these routes. Persistence is via ``EngagementRepo`` / ``EngagementRunRepo``;
a persistence failure is surfaced (503) rather than silently dropped, because
an un-persisted authorization boundary must never look like success.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.domain.engagement import Engagement, EngagementStatus, Run, RunStatus

router = APIRouter(prefix="/api/engagements", tags=["engagements"])


# ── Request bodies ───────────────────────────────────────────────────────
class EngagementCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="")
    environment_type: str = Field(default="unknown")
    authorized_targets: List[str] = Field(default_factory=list)
    excluded_targets: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    allowed_ips: List[str] = Field(default_factory=list)
    allowed_urls: List[str] = Field(default_factory=list)
    allowed_operations: List[str] = Field(default_factory=list)
    forbidden_operations: List[str] = Field(default_factory=list)
    execution_mode: str = Field(default="PASSIVE")
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    rate_limit_rps: float = Field(default=5.0, ge=0.0)
    max_concurrent: int = Field(default=3, ge=1)
    data_handling_policy: str = Field(default="minimal")


class AuthorizeBody(BaseModel):
    target: str = Field(..., max_length=2048)
    operation: str = Field(default="", max_length=128)


class RunCreate(BaseModel):
    target: str = Field(..., max_length=2048)
    tier: str = Field(default="POC", max_length=32)
    operation: str = Field(default="scan", max_length=128)


# ── Helpers ──────────────────────────────────────────────────────────────
def _load(engagement_id: str) -> Engagement:
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
    try:
        return Engagement.from_dict(spec)
    except Exception as e:
        raise HTTPException(500, f"engagement spec corrupt: {e}")


def _persist(eng: Engagement) -> None:
    try:
        from core.database.pg_store import EngagementRepo
        EngagementRepo.create(eng.id, eng.name, eng.status.value, eng.to_dict())
    except Exception as e:
        raise HTTPException(503, f"engagement persist failed: {e}")


# ── Routes ───────────────────────────────────────────────────────────────
@router.post("")
def create_engagement(body: EngagementCreate):
    try:
        eng = Engagement(
            name=body.name, description=body.description,
            environment_type=body.environment_type,
            authorized_targets=body.authorized_targets,
            excluded_targets=body.excluded_targets,
            allowed_domains=body.allowed_domains,
            allowed_ips=body.allowed_ips,
            allowed_urls=body.allowed_urls,
            allowed_operations=body.allowed_operations,
            forbidden_operations=body.forbidden_operations,
            execution_mode=body.execution_mode,
            start_time=body.start_time, end_time=body.end_time,
            rate_limit_rps=body.rate_limit_rps,
            max_concurrent=body.max_concurrent,
            data_handling_policy=body.data_handling_policy,
            status=EngagementStatus.DRAFT,
        )
    except Exception as e:
        raise HTTPException(400, f"invalid engagement: {e}")
    _persist(eng)
    return eng.summary()


@router.get("")
def list_engagements(limit: int = 200, offset: int = 0):
    try:
        from core.database.pg_store import EngagementRepo
        rows = EngagementRepo.list_all(limit=limit, offset=offset)
    except Exception as e:
        raise HTTPException(503, f"engagement store unavailable: {e}")
    return {"engagements": [
        {"engagement_id": r.get("engagement_id"), "name": r.get("name"),
         "status": r.get("status")} for r in rows]}


@router.get("/{engagement_id}")
def get_engagement(engagement_id: str):
    return _load(engagement_id).summary()


@router.post("/{engagement_id}/activate")
def activate_engagement(engagement_id: str):
    eng = _load(engagement_id)
    eng.status = EngagementStatus.ACTIVE
    _persist(eng)
    return {"engagement_id": eng.id, "status": eng.status.value}


@router.post("/{engagement_id}/pause")
def pause_engagement(engagement_id: str):
    eng = _load(engagement_id)
    eng.status = EngagementStatus.PAUSED
    _persist(eng)
    return {"engagement_id": eng.id, "status": eng.status.value}


@router.post("/{engagement_id}/authorize")
def authorize(engagement_id: str, body: AuthorizeBody):
    """Run the deterministic fail-closed gate for a (target, operation)."""
    eng = _load(engagement_id)
    allowed, reason = eng.authorize(body.target, body.operation)
    return {"allowed": allowed, "reason": reason,
            "target": body.target, "operation": body.operation}


@router.post("/{engagement_id}/runs")
def create_run(engagement_id: str, body: RunCreate):
    """Launch a run — refused unless the engagement gate authorizes it."""
    eng = _load(engagement_id)
    allowed, reason = eng.authorize(body.target, body.operation)
    if not allowed:
        # Fail closed: no run row is created for an unauthorized request.
        raise HTTPException(403, f"run refused: {reason}")
    run = Run(engagement_id=eng.id, target=body.target,
              tier=body.tier, status=RunStatus.PENDING, reason="authorized")
    try:
        from core.database.pg_store import EngagementRunRepo
        EngagementRunRepo.create(run.id, eng.id, target=run.target,
                                 tier=run.tier, status=run.status.value,
                                 reason=run.reason)
    except Exception as e:
        raise HTTPException(503, f"run persist failed: {e}")
    return {"run_id": run.id, "engagement_id": eng.id,
            "target": run.target, "status": run.status.value}


@router.get("/{engagement_id}/runs")
def list_runs(engagement_id: str):
    try:
        from core.database.pg_store import EngagementRunRepo
        rows = EngagementRunRepo.list_by_engagement(engagement_id)
    except Exception as e:
        raise HTTPException(503, f"engagement store unavailable: {e}")
    return {"runs": rows}
