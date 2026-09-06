"""Placeholder for the planned split of `ui/api/server.py` (#159).

`server.py` is currently ~2.6k lines. The intended split is:

    ui/api/routers/scans.py      - /api/scans/*  + WS /ws/scan/{job_id}
    ui/api/routers/targets.py    - /api/targets/*
    ui/api/routers/review.py     - /api/review-queue/*, /api/audit-trail
    ui/api/routers/rag.py        - /api/rag/*
    ui/api/routers/canonical.py  - /api/canonical/*
    ui/api/routers/health.py     - /api/health, /api/metrics
    ui/api/routers/analytics.py  - /api/decision-log, /api/experiences, ...

Each file uses `APIRouter()` locally and gets attached via
`app.include_router(...)` in `server.py`. The split is staged one file at a
time so nothing breaks — `server.py` keeps the routes it hasn't extracted
yet, plus middleware / lifecycle / model definitions common to all routers.

This module intentionally has no imports so it can be a marker package until
the migration begins.
"""
