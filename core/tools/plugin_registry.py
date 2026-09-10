"""Phase 15.1 — Typed plugin/tool registry.

Versioned registry for recon, web, browser, source, protocol, fuzzing, and
verification capabilities. Every tool declares input schema, risk class,
prerequisites, output schema, sandbox requirements, and supported evidence types.
Unknown tools cannot execute. Plugin upgrades are compatibility-tested.
"""
from __future__ import annotations

import hashlib
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class RiskClass(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DESTRUCTIVE = "destructive"


class ToolCategory(str, Enum):
    RECON = "recon"
    WEB = "web"
    BROWSER = "browser"
    SOURCE = "source"
    PROTOCOL = "protocol"
    FUZZING = "fuzzing"
    VERIFICATION = "verification"
    CLOUD = "cloud"
    INFRA = "infra"


@dataclass(frozen=True)
class ToolSchema:
    tool_name: str
    version: str
    category: ToolCategory
    risk_class: RiskClass
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    prerequisites: FrozenSet[str] = frozenset()
    sandbox_required: bool = False
    supported_evidence_types: FrozenSet[str] = frozenset()
    description: str = ""
    max_timeout_ms: int = 60_000
    requires_auth: bool = False


@dataclass
class ToolRegistration:
    schema: ToolSchema
    handler: Optional[Callable] = None
    registered_at: float = field(default_factory=time.time)
    pinned_for_scan: str = ""
    compatible_versions: List[str] = field(default_factory=list)


class TypedPluginRegistry:
    """Versioned tool registry with schema validation and risk enforcement."""

    def __init__(self, allowed_risk: Optional[Set[RiskClass]] = None):
        self._lock = threading.RLock()
        self._tools: Dict[str, ToolRegistration] = {}
        self._scan_pins: Dict[str, Dict[str, str]] = {}
        self._allowed_risk = allowed_risk or {RiskClass.SAFE, RiskClass.LOW, RiskClass.MEDIUM}

    def register(self, schema: ToolSchema, handler: Optional[Callable] = None) -> bool:
        key = f"{schema.tool_name}:{schema.version}"
        with self._lock:
            if key in self._tools:
                return False
            self._tools[key] = ToolRegistration(schema=schema, handler=handler)
        logger.info(f"[PluginRegistry] Registered {key} ({schema.category.value})")
        return True

    def unregister(self, tool_name: str, version: str) -> bool:
        key = f"{tool_name}:{version}"
        with self._lock:
            return self._tools.pop(key, None) is not None

    def get(self, tool_name: str, version: Optional[str] = None) -> Optional[ToolRegistration]:
        with self._lock:
            if version:
                return self._tools.get(f"{tool_name}:{version}")
            candidates = [(k, v) for k, v in self._tools.items()
                          if k.startswith(f"{tool_name}:")]
            if candidates:
                return max(candidates, key=lambda x: x[1].registered_at)[1]
        return None

    def resolve_for_scan(self, tool_name: str, scan_id: str) -> Optional[ToolRegistration]:
        with self._lock:
            pinned_version = self._scan_pins.get(scan_id, {}).get(tool_name)
        if pinned_version:
            return self.get(tool_name, pinned_version)
        return self.get(tool_name)

    def pin_for_scan(self, scan_id: str, tool_name: str, version: str) -> bool:
        reg = self.get(tool_name, version)
        if not reg:
            return False
        with self._lock:
            self._scan_pins.setdefault(scan_id, {})[tool_name] = version
        return True

    def can_execute(self, tool_name: str, version: Optional[str] = None) -> Tuple[bool, str]:
        reg = self.get(tool_name, version)
        if not reg:
            return False, f"unknown tool: {tool_name}"
        if reg.schema.risk_class not in self._allowed_risk:
            return False, f"risk class {reg.schema.risk_class.value} not allowed"
        return True, "ok"

    def check_compatibility(self, tool_name: str, old_version: str,
                             new_version: str) -> Dict[str, Any]:
        old = self.get(tool_name, old_version)
        new = self.get(tool_name, new_version)
        if not old or not new:
            return {"compatible": False, "reason": "version not found"}
        input_compat = set(old.schema.input_schema.keys()) <= set(new.schema.input_schema.keys())
        output_compat = set(old.schema.output_schema.keys()) <= set(new.schema.output_schema.keys())
        return {
            "compatible": input_compat and output_compat,
            "input_compatible": input_compat,
            "output_compatible": output_compat,
            "risk_changed": old.schema.risk_class != new.schema.risk_class,
        }

    def list_tools(self, category: Optional[ToolCategory] = None,
                    risk_class: Optional[RiskClass] = None) -> List[Dict[str, Any]]:
        with self._lock:
            tools = list(self._tools.values())
        if category:
            tools = [t for t in tools if t.schema.category == category]
        if risk_class:
            tools = [t for t in tools if t.schema.risk_class == risk_class]
        return [{
            "name": t.schema.tool_name, "version": t.schema.version,
            "category": t.schema.category.value, "risk": t.schema.risk_class.value,
            "sandbox": t.schema.sandbox_required,
        } for t in tools]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            by_cat: Dict[str, int] = {}
            for t in self._tools.values():
                c = t.schema.category.value
                by_cat[c] = by_cat.get(c, 0) + 1
        return {"total": len(self._tools), "by_category": by_cat,
                "pinned_scans": len(self._scan_pins)}

