"""Ambient current-scan id via a ContextVar.

Low-level tool execution (tool_gateway) runs far from the brain and doesn't get
the scan_id passed down. The brain sets it here at scan start so any layer can
tag its output (e.g. persisting raw tool stdout to `tool_outputs` for the UI).
Reusable + dependency-free.
"""
from __future__ import annotations

from contextvars import ContextVar
from typing import Optional

_current_scan_id: ContextVar[str] = ContextVar("current_scan_id", default="")


def set_scan_id(scan_id: str) -> None:
    try:
        _current_scan_id.set(scan_id or "")
    except Exception:
        pass


def get_scan_id() -> str:
    try:
        return _current_scan_id.get() or ""
    except Exception:
        return ""
